import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { verifyProof, type UnsignedProof } from "../src/index.js";
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

  it("rejects v outside {1, 2}", () => {
    expect(verifyProof({ ...proof, v: 3 }, keyset).errors).toContain(
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
