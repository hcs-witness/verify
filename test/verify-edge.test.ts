import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  b64urlToBytes,
  bytesToB64url,
  canonicalBytes,
  NonJsonValueError,
  verifyProof,
} from "../src/index.js";

const proof = JSON.parse(
  readFileSync("test/vectors/proof-v1-valid.json", "utf8"),
) as Record<string, unknown>;
const keyset = JSON.parse(
  readFileSync("test/vectors/keys-test.json", "utf8"),
) as Record<string, unknown>;

describe("verifyProof edge cases", () => {
  it("rejects non-object proofs", () => {
    expect(verifyProof("nope", keyset).errors).toContain("SCHEMA_INVALID");
    expect(verifyProof([1], keyset).valid).toBe(false);
    expect(verifyProof(null, keyset).valid).toBe(false);
  });

  it("rejects regex-valid but unparsable timestamps", () => {
    const p = { ...proof, issued_at: "2026-13-01T00:00:00Z" };
    expect(verifyProof(p, keyset).errors).toContain("SCHEMA_INVALID");
  });

  it("maps a non-JSON signals value to SCHEMA_INVALID", () => {
    const p = { ...proof, signals: { bad: undefined } };
    expect(verifyProof(p, keyset).errors).toContain("SCHEMA_INVALID");
  });

  it("survives a crypto exception on an off-curve ES256 key", () => {
    const ks = JSON.parse(JSON.stringify(keyset)) as {
      keys: { alg: string; x?: string; y?: string }[];
    };
    const ec = ks.keys.find((k) => k.alg === "ES256");
    expect(ec).toBeDefined();
    if (ec !== undefined) {
      // Valid b64url, right length, but (almost surely) off-curve.
      ec.x = bytesToB64url(new Uint8Array(32).fill(0xff));
      ec.y = bytesToB64url(new Uint8Array(32).fill(0xee));
    }
    const r = verifyProof(proof, ks);
    expect(r.errors).toContain("ES256_SIG_INVALID");
  });

  it("rejects an ES256 key with wrong-length coordinates", () => {
    const ks = JSON.parse(JSON.stringify(keyset)) as {
      keys: { alg: string; x?: string }[];
    };
    const ec = ks.keys.find((k) => k.alg === "ES256");
    if (ec !== undefined) {
      ec.x = bytesToB64url(new Uint8Array(16).fill(1));
    }
    expect(verifyProof(proof, ks).errors).toContain("ES256_SIG_INVALID");
  });

  it("survives a crypto exception on a short ML-DSA public key", () => {
    const ks = JSON.parse(JSON.stringify(keyset)) as {
      keys: { alg: string; pub?: string }[];
    };
    const ml = ks.keys.find((k) => k.alg === "ML-DSA-65");
    expect(ml).toBeDefined();
    if (ml !== undefined) {
      ml.pub = bytesToB64url(new Uint8Array(16).fill(1));
    }
    const r = verifyProof(proof, ks);
    expect(r.errors).toContain("MLDSA_SIG_INVALID");
  });

  it("accepts a key with a valid not_after window", () => {
    const ks = JSON.parse(JSON.stringify(keyset)) as {
      keys: { not_after?: string }[];
    };
    for (const k of ks.keys) k.not_after = "2027-01-01T00:00:00Z";
    expect(verifyProof(proof, ks).valid).toBe(true);
  });

  it("treats a regex-valid unparsable not_before as invalid window", () => {
    const ks = JSON.parse(JSON.stringify(keyset)) as {
      keys: { not_before: string }[];
    };
    for (const k of ks.keys) k.not_before = "2026-13-01T00:00:00Z";
    expect(verifyProof(proof, ks).errors).toContain(
      "KEY_NOT_VALID_AT_ISSUANCE",
    );
  });

  it("rejects a malformed keyset", () => {
    expect(verifyProof(proof, { keys: "x" }).errors).toContain(
      "KEYSET_INVALID",
    );
    expect(verifyProof(proof, {}).errors).toContain("KEYSET_INVALID");
  });

  it("rejects a non-decodable base64url ES256 signature", () => {
    const p = JSON.parse(JSON.stringify(proof)) as {
      sig: { es256: { value: string } };
    };
    // Valid charset but length % 4 === 1 → undecodable.
    p.sig.es256.value = "AAAAA";
    expect(verifyProof(p, keyset).errors).toContain("ES256_SIG_INVALID");
  });

  it("rejects a base64url ES256 signature of wrong length", () => {
    const p = JSON.parse(JSON.stringify(proof)) as {
      sig: { es256: { value: string } };
    };
    p.sig.es256.value = bytesToB64url(new Uint8Array(63).fill(1));
    expect(verifyProof(p, keyset).errors).toContain("ES256_SIG_INVALID");
  });

  it("rejects a malformed ML-DSA signature", () => {
    const p = JSON.parse(JSON.stringify(proof)) as {
      sig: { mldsa65: { value: string } };
    };
    p.sig.mldsa65.value = bytesToB64url(new Uint8Array(100).fill(2));
    expect(verifyProof(p, keyset).errors).toContain("MLDSA_SIG_INVALID");
  });

  it("rejects signals larger than 8 KiB canonicalized", () => {
    const p = {
      ...proof,
      signals: { blob: "x".repeat(9000) },
    };
    expect(verifyProof(p, keyset).errors).toContain("SCHEMA_INVALID");
  });

  it("invalidates signatures when signals is added post-hoc (it is signed)", () => {
    const p = { ...proof, signals: { ok: true } };
    const r = verifyProof(p, keyset);
    expect(r.errors).toContain("ES256_SIG_INVALID");
    expect(r.errors).toContain("MLDSA_SIG_INVALID");
  });
});

describe("base64url helpers", () => {
  it("round-trips arbitrary lengths", () => {
    for (const len of [0, 1, 2, 3, 4, 31, 32, 33, 64]) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 7) & 0xff);
      const enc = bytesToB64url(bytes);
      expect(enc).not.toContain("=");
      expect(b64urlToBytes(enc)).toEqual(bytes);
    }
  });

  it("rejects invalid input", () => {
    expect(b64urlToBytes("a")).toBeNull();
    expect(b64urlToBytes("a+b")).toBeNull();
    expect(b64urlToBytes("a/b")).toBeNull();
  });
});

describe("canonicalBytes edge", () => {
  it("throws NonJsonValueError for a symbol property value", () => {
    expect(() => canonicalBytes({ s: Symbol("x") })).toThrow(NonJsonValueError);
  });
});
