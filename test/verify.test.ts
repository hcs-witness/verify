import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { keysetSha256, verifyProof, type UnsignedProof } from "../src/index.js";
import { makeTestSigners, signTestProof } from "./helpers/signer.js";

// Fingerprint of the committed reference vector — regeneration is forbidden.
// Regenerated exactly once in the phase-5 commit that added the signed
// display_sha256 field (ADR 0007); v1 was not yet consumed by any client.
const EXPECTED_SHA256 =
  "c99201f9ec594e5eae2bb1d2f6691572f82ab734250244285b11cd6a9cb48409";

const rawProof = readFileSync("test/vectors/proof-v1-valid.json", "utf8");
const rawKeys = readFileSync("test/vectors/keys-test.json", "utf8");
const proof = JSON.parse(rawProof) as Record<string, unknown>;
const keyset = JSON.parse(rawKeys) as Record<string, unknown>;

function mutate(field: string): Record<string, unknown> {
  const p = JSON.parse(rawProof) as Record<string, unknown>;
  const cur = Object.entries(p)
    .find(([k]) => k === field)
    ?.at(1);
  const next =
    typeof cur === "string"
      ? `${cur.slice(0, -1)}${cur.endsWith("X") ? "Y" : "X"}`
      : cur;
  return { ...p, [field]: next };
}

describe("verifyProof — reference vector", () => {
  it("is pinned by SHA-256 fingerprint (no silent regeneration)", () => {
    const digest = createHash("sha256").update(rawProof).digest("hex");
    expect(digest).toBe(EXPECTED_SHA256);
  });

  it("verifies the committed valid proof", () => {
    const r = verifyProof(proof, keyset);
    expect(r).toMatchObject({ valid: true, errors: [] });
  });

  it.each([
    "proof_id",
    "tenant_id",
    "approval_id",
    "action",
    "subject_ref",
    "context_sha256",
    "display_sha256",
    "decision",
    "issued_at",
    "expires_at",
  ])("rejects a single-char mutation of %s", (field) => {
    const r = verifyProof(mutate(field), keyset);
    expect(r.valid).toBe(false);
  });

  it("rejects swapped signatures", () => {
    const p = JSON.parse(rawProof) as {
      sig: { es256: { value: string }; mldsa65: { value: string } };
    };
    [p.sig.es256.value, p.sig.mldsa65.value] = [
      p.sig.mldsa65.value,
      p.sig.es256.value,
    ];
    expect(verifyProof(p, keyset).valid).toBe(false);
  });

  it("rejects a high-S ES256 signature", () => {
    const p = JSON.parse(rawProof) as {
      sig: { es256: { value: string } };
    };
    const sig = Uint8Array.from(
      Buffer.from(
        p.sig.es256.value.replaceAll("-", "+").replaceAll("_", "/"),
        "base64",
      ),
    );
    const n = BigInt(
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    const s = BigInt(`0x${Buffer.from(sig.subarray(32)).toString("hex")}`);
    const s2 = n - s;
    const r = Buffer.from(sig.subarray(0, 32));
    const out = Buffer.concat([
      r,
      Buffer.from(s2.toString(16).padStart(64, "0"), "hex"),
    ]);
    p.sig.es256.value = out
      .toString("base64")
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    expect(verifyProof(p, keyset).errors).toContain("ES256_HIGH_S");
  });

  it("rejects an unknown es256 kid", () => {
    const p = JSON.parse(rawProof) as {
      sig: { es256: { kid: string } };
    };
    p.sig.es256.kid = "unknown-kid";
    expect(verifyProof(p, keyset).errors).toContain("ES256_KID_UNKNOWN");
  });

  it("rejects an unknown mldsa kid", () => {
    const p = JSON.parse(rawProof) as {
      sig: { mldsa65: { kid: string } };
    };
    p.sig.mldsa65.kid = "unknown-kid";
    expect(verifyProof(p, keyset).errors).toContain("MLDSA_KID_UNKNOWN");
  });

  it("rejects a key used outside its validity window", () => {
    const ks = JSON.parse(rawKeys) as {
      keys: { status: string; not_before: string; not_after?: string }[];
    };
    for (const k of ks.keys) {
      k.status = "retired";
      k.not_before = "2020-01-01T00:00:00Z";
      k.not_after = "2020-06-01T00:00:00Z";
    }
    expect(verifyProof(proof, ks).errors).toContain(
      "KEY_NOT_VALID_AT_ISSUANCE",
    );
  });

  it("rejects a removed signature", () => {
    const p = JSON.parse(rawProof) as { sig?: unknown };
    delete p.sig;
    expect(verifyProof(p, keyset).errors).toContain("SCHEMA_INVALID");
  });

  it("rejects an extra field (additionalProperties false)", () => {
    const p = { ...proof, extra: 1 };
    expect(verifyProof(p, keyset).errors).toContain("SCHEMA_INVALID");
  });

  it("rejects v outside {1, 2, 3}", () => {
    expect(verifyProof({ ...proof, v: 4 }, keyset).errors).toContain(
      "UNSUPPORTED_VERSION",
    );
    expect(verifyProof({ ...proof, v: 0 }, keyset).errors).toContain(
      "UNSUPPORTED_VERSION",
    );
  });

  it("flags PROOF_EXPIRED only when opts.now is later than expires_at", () => {
    expect(
      verifyProof(proof, keyset, {
        now: new Date("2026-06-01T00:00:01Z"),
      }).errors,
    ).toContain("PROOF_EXPIRED");
    expect(
      verifyProof(proof, keyset, { now: new Date("2026-03-01T00:00:00Z") })
        .valid,
    ).toBe(true);
    expect(verifyProof(proof, keyset).valid).toBe(true);
  });

  it("rejects incoherent timestamps", () => {
    const p = JSON.parse(rawProof) as { issued_at: string; expires_at: string };
    p.issued_at = "2027-01-01T00:00:00Z";
    p.expires_at = "2027-01-01T00:00:00Z";
    expect(verifyProof(p, keyset).errors).toContain("TIMESTAMPS_INCOHERENT");
  });

  it("never throws on arbitrary mutated JSON (property)", () => {
    const dev = makeTestSigners();
    const raw = JSON.parse(rawProof) as Record<string, unknown>;
    delete raw.sig;
    delete raw._comment;
    const base = raw as unknown as UnsignedProof;
    const signed = signTestProof(base, dev);
    const keys = dev.keyset();
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 255 }), fc.nat(), (byte, pos) => {
        const buf = Buffer.from(JSON.stringify(signed), "utf8");
        if (buf.length === 0) return;
        const at = pos % buf.length;
        buf.set([byte], at);
        let mutated: unknown;
        try {
          mutated = JSON.parse(buf.toString("utf8"));
        } catch {
          return; // unparseable mutations are out of scope
        }
        const r = verifyProof(mutated, keys);
        expect(typeof r.valid).toBe("boolean");
      }),
      { numRuns: 100 },
    );
  });
});

/* ------------------------------------------------------------------ */
/* Étape 5 : bloc presence (v:2) + non-régression v:1                  */
/* ------------------------------------------------------------------ */

const PRESENCE = {
  model: "presence-v1",
  calibrated: false,
  band: "unrated",
  challenge: { kind: "numeric", trials: 8, completed: true },
  signals: "trusted",
  automation_indicators: 0,
  profile_sha256: "a".repeat(64),
  rotation: { tw: 12, ok: true, replayed: false },
  flags: ["synced_passkey"],
};

describe("verifyProof — presence block (étape 5)", () => {
  const dev = makeTestSigners();
  const keys = dev.keyset();

  it("v:2 proof with presence signs and verifies (ES256 + ML-DSA)", () => {
    const raw = JSON.parse(rawProof) as Record<string, unknown>;
    delete raw.sig;
    delete raw._comment;
    const signed = signTestProof(
      { ...raw, v: 2, presence: PRESENCE } as unknown as UnsignedProof,
      dev,
    );
    expect(signed.v).toBe(2);
    const r = verifyProof(signed, keys);
    expect(r).toMatchObject({ valid: true, errors: [] });
  });

  it("malformed presence is rejected (schema)", () => {
    const raw = JSON.parse(rawProof) as Record<string, unknown>;
    delete raw.sig;
    delete raw._comment;
    const signed = signTestProof(
      { ...raw, v: 2, presence: PRESENCE } as unknown as UnsignedProof,
      dev,
    );
    const bad = {
      ...signed,
      presence: { ...PRESENCE, model: "presence-v9" },
    };
    expect(verifyProof(bad, keys).valid).toBe(false);
  });

  it("non-regression: v:1 proof without presence still verifies", () => {
    expect(proof.v).toBe(1);
    const r = verifyProof(proof, keyset);
    expect(r).toMatchObject({ valid: true, errors: [] });
  });
});

describe("keysetSha256 — keyset pinning", () => {
  it("stable sha256 of the canonical JCS keyset (ETag vector)", () => {
    // Même calcul que l'ETag de /.well-known/hcs-witness-keys.json :
    // sha256(JCS(keyset)). Vecteur commun avec gateguard-platform.
    expect(keysetSha256(keyset)).toBe(
      "46436272806d3c0e9ef7b99a42fe4ca57301f898f483d24e9220bff4aa807551",
    );
  });

  it("changes when any key material changes", () => {
    const other = JSON.parse(JSON.stringify(keyset)) as {
      keys: { kid: string }[];
    };
    other.keys[0]!.kid = "other-kid";
    expect(keysetSha256(other)).not.toBe(keysetSha256(keyset));
  });

  it("accepts the proof when the pin matches", () => {
    const r = verifyProof(proof, keyset, {
      expectedKeysetSha256: keysetSha256(keyset),
    });
    expect(r.valid).toBe(true);
  });

  it("rejects with KEYSET_PIN_MISMATCH when the pin differs", () => {
    const r = verifyProof(proof, keyset, {
      expectedKeysetSha256: "0".repeat(64),
    });
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("KEYSET_PIN_MISMATCH");
  });
});

/* ------------------------------------------------------------------ */
/* V1.4 : vecteur fixe v3 — mutation de chaque champ ajouté            */
/* ------------------------------------------------------------------ */

const rawV3Proof = readFileSync("test/vectors/proof-v3-valid.json", "utf8");
const rawV3Keys = readFileSync("test/vectors/keys-v3-test.json", "utf8");
const v3Proof = JSON.parse(rawV3Proof) as {
  human_factor: Record<string, unknown>;
  assurance: { level: string; controls: string[] };
} & Record<string, unknown>;
const v3Keyset = JSON.parse(rawV3Keys) as Record<string, unknown>;

describe("verifyProof — vecteur v3", () => {
  it("accepts the fixed signed v3 vector", () => {
    expect(verifyProof(v3Proof, v3Keyset)).toMatchObject({
      valid: true,
      errors: [],
    });
  });

  it.each([
    "enrolled_at",
    "confirmed_at",
    "invited_by_ref",
    "confirmed_by_ref",
    "self_confirmed",
    "enrollment_code_verified",
  ])("fails when human_factor.%s is mutated", (field) => {
    const mutated = {
      ...v3Proof,
      human_factor: {
        ...v3Proof.human_factor,
        [field]:
          field === "enrolled_at" || field === "confirmed_at"
            ? "2026-01-01T00:00:00Z"
            : typeof v3Proof.human_factor[field] === "boolean"
              ? !v3Proof.human_factor[field]
              : "other-ref",
      },
    };
    expect(verifyProof(mutated, v3Keyset).valid).toBe(false);
  });

  it("fails when assurance.level is mutated", () => {
    const mutated = {
      ...v3Proof,
      assurance: { ...v3Proof.assurance, level: "N1" },
    };
    expect(verifyProof(mutated, v3Keyset).valid).toBe(false);
  });

  it("fails when assurance.controls is mutated", () => {
    const mutated = {
      ...v3Proof,
      assurance: {
        ...v3Proof.assurance,
        controls: v3Proof.assurance.controls.filter(
          (c) => c !== "presence_measured",
        ),
      },
    };
    expect(verifyProof(mutated, v3Keyset).valid).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* V1.6 : cohérence interne des preuves v3 (ASSURANCE_INCONSISTENT)    */
/* ------------------------------------------------------------------ */

describe("verifyProof — v3 assurance coherence", () => {
  const v3Signers = makeTestSigners();
  const v3Keys = v3Signers.keyset();

  const v3Unsigned = (over: Record<string, unknown>): UnsignedProof => {
    const base = JSON.parse(rawV3Proof) as Record<string, unknown>;
    delete base.sig;
    delete base.anchor;
    return { ...base, ...over } as unknown as UnsignedProof;
  };

  it("controls enrollment_confirmed + confirmed_at null → motif", () => {
    const hf = {
      ...v3Proof.human_factor,
      confirmed_at: null,
    };
    const signed = signTestProof(v3Unsigned({ human_factor: hf }), v3Signers);
    const r = verifyProof(signed, v3Keys);
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("ASSURANCE_INCONSISTENT");
    expect(r.reasons).toContain("enrollment_confirmed_but_confirmed_at_null");
  });

  it("controls enrollment_code_verified + flag false → motif", () => {
    const hf = {
      ...v3Proof.human_factor,
      enrollment_code_verified: false,
    };
    const signed = signTestProof(v3Unsigned({ human_factor: hf }), v3Signers);
    const r = verifyProof(signed, v3Keys);
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("ASSURANCE_INCONSISTENT");
    expect(r.reasons).toContain("enrollment_code_verified_but_flag_false");
  });

  it("confirmed_at before enrolled_at → motif", () => {
    const hf = {
      ...v3Proof.human_factor,
      enrolled_at: "2026-03-01T00:00:00Z",
      confirmed_at: "2026-02-01T00:00:00Z",
    };
    const signed = signTestProof(v3Unsigned({ human_factor: hf }), v3Signers);
    const r = verifyProof(signed, v3Keys);
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("ASSURANCE_INCONSISTENT");
    expect(r.reasons).toContain("confirmed_at_before_enrolled_at");
  });

  it("coherent re-signed v3 proof stays valid (no reasons)", () => {
    const signed = signTestProof(v3Unsigned({}), v3Signers);
    const r = verifyProof(signed, v3Keys);
    expect(r.valid).toBe(true);
    expect(r.reasons).toBeUndefined();
  });

  it("mutated v3 vector still reports the inconsistency", () => {
    const mutated = {
      ...v3Proof,
      human_factor: { ...v3Proof.human_factor, confirmed_at: null },
    };
    const r = verifyProof(mutated, v3Keyset);
    expect(r.errors).toContain("ASSURANCE_INCONSISTENT");
    expect(r.reasons).toContain("enrollment_confirmed_but_confirmed_at_null");
  });

  it("v1 and v2 proofs are not affected", () => {
    const r1 = verifyProof(proof, keyset);
    expect(r1.valid).toBe(true);
    expect(r1.reasons).toBeUndefined();
    const r2 = verifyProof(
      JSON.parse(readFileSync("test/vectors/proof-v2-anchored.json", "utf8")),
      JSON.parse(readFileSync("test/vectors/keys-local.json", "utf8")),
    );
    expect(r2.valid).toBe(true);
    expect(r2.reasons).toBeUndefined();
  });
});
