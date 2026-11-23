import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { b64urlToBytes } from "./base64.js";
import { canonicalBytes } from "./jcs.js";
import {
  isKeyset,
  keysetSha256,
  type Keyset,
  type KeysetKey,
  type Es256KeysetKey,
  type MlDsaKeysetKey,
} from "./keyset.js";
import { isProof, signedPayload, type Proof } from "./schema.js";

export const ML_DSA_CONTEXT = new TextEncoder().encode("gateguard:proof:v1");
const SIGNALS_MAX_BYTES = 8192;
const ES256_SIG_BYTES = 64;
const MLDSA_SIG_BYTES = 3309;
/** Ordre du groupe P-256 (secp256r1) — constante publique NIST. */
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export type VerifyErrorCode =
  | "SCHEMA_INVALID"
  | "UNSUPPORTED_VERSION"
  | "KEYSET_INVALID"
  | "KEYSET_PIN_MISMATCH"
  | "ASSURANCE_INCONSISTENT"
  | "ES256_KID_UNKNOWN"
  | "MLDSA_KID_UNKNOWN"
  | "ES256_SIG_INVALID"
  | "MLDSA_SIG_INVALID"
  | "ES256_HIGH_S"
  | "KEY_NOT_VALID_AT_ISSUANCE"
  | "PROOF_EXPIRED"
  | "TIMESTAMPS_INCOHERENT";

export interface VerifyResult {
  readonly valid: boolean;
  readonly errors: readonly VerifyErrorCode[];
  readonly proof_id?: string;
  /** Motifs précis des erreurs de cohérence interne (v3). */
  readonly reasons?: readonly string[];
}

export interface VerifyOptions {
  readonly now?: Date;
  readonly expectedKeysetSha256?: string;
}

function parseTime(value: string): number {
  const t = Date.parse(value);
  return Number.isNaN(t) ? Number.NaN : t;
}

function keyCoversIssuance(key: KeysetKey, issuedMs: number): boolean {
  const nb = parseTime(key.not_before);
  if (Number.isNaN(nb) || issuedMs < nb) return false;
  const na = key.not_after === undefined ? undefined : parseTime(key.not_after);
  return na === undefined || Number.isNaN(na) || issuedMs <= na;
}

export function verifyProof(
  proof: unknown,
  keyset: unknown,
  opts?: VerifyOptions,
): VerifyResult {
  const errors: VerifyErrorCode[] = [];
  const reasons: string[] = [];
  const fail = (codes: VerifyErrorCode[]): VerifyResult => ({
    valid: false,
    errors: codes,
  });
  const done = (): VerifyResult => ({
    valid: errors.length === 0,
    errors,
    ...(reasons.length === 0 ? {} : { reasons }),
  });

  if (typeof proof !== "object" || proof === null || Array.isArray(proof)) {
    return fail(["SCHEMA_INVALID"]);
  }
  const v = (proof as { v?: unknown }).v;
  if (v !== 1 && v !== 2 && v !== 3) {
    return fail(v === undefined ? ["SCHEMA_INVALID"] : ["UNSUPPORTED_VERSION"]);
  }
  if (!isProof(proof)) {
    return fail(["SCHEMA_INVALID"]);
  }
  const p: Proof = proof;

  const issuedMs = parseTime(p.issued_at);
  const expiresMs = parseTime(p.expires_at);
  if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs)) {
    errors.push("SCHEMA_INVALID");
  } else if (expiresMs <= issuedMs) {
    errors.push("TIMESTAMPS_INCOHERENT");
  }
  if (p.signals !== undefined) {
    try {
      if (canonicalBytes(p.signals).length > SIGNALS_MAX_BYTES) {
        errors.push("SCHEMA_INVALID");
      }
    } catch {
      errors.push("SCHEMA_INVALID");
    }
  }

  if (!isKeyset(keyset)) {
    errors.push("KEYSET_INVALID");
    return { ...done(), proof_id: p.proof_id };
  }
  const ks: Keyset = keyset;

  if (
    opts?.expectedKeysetSha256 !== undefined &&
    opts.expectedKeysetSha256 !== keysetSha256(ks)
  ) {
    errors.push("KEYSET_PIN_MISMATCH");
  }

  const authErrorsStart = errors.length;
  const esKey = ks.keys.find(
    (k): k is Es256KeysetKey => k.alg === "ES256" && k.kid === p.sig.es256.kid,
  );
  const mlKey = ks.keys.find(
    (k): k is MlDsaKeysetKey =>
      k.alg === "ML-DSA-65" && k.kid === p.sig.mldsa65.kid,
  );
  if (esKey === undefined) errors.push("ES256_KID_UNKNOWN");
  if (mlKey === undefined) errors.push("MLDSA_KID_UNKNOWN");

  if (
    !Number.isNaN(issuedMs) &&
    ((esKey !== undefined && !keyCoversIssuance(esKey, issuedMs)) ||
      (mlKey !== undefined && !keyCoversIssuance(mlKey, issuedMs)))
  ) {
    errors.push("KEY_NOT_VALID_AT_ISSUANCE");
  }

  let payload: Uint8Array;
  try {
    payload = signedPayload(p);
  } catch {
    errors.push("SCHEMA_INVALID");
    return { ...done(), proof_id: p.proof_id };
  }

  if (esKey !== undefined) {
    const sig = b64urlToBytes(p.sig.es256.value);
    if (sig?.length !== ES256_SIG_BYTES) {
      errors.push("ES256_SIG_INVALID");
    } else {
      const s = BigInt(
        `0x${[...sig.subarray(32)].map((b) => b.toString(16).padStart(2, "0")).join("")}`,
      );
      if (s > P256_ORDER / 2n) {
        errors.push("ES256_HIGH_S");
      } else {
        let ok = false;
        try {
          const pub = createPublicKey({
            key: {
              kty: "EC",
              crv: "P-256",
              x: esKey.x,
              y: esKey.y,
            },
            format: "jwk",
          });
          // Signature brute r‖s (IEEE P1363) sur SHA-256(payload).
          ok = cryptoVerify(
            "sha256",
            payload,
            { key: pub, dsaEncoding: "ieee-p1363" },
            sig,
          );
        } catch {
          ok = false;
        }
        if (!ok) errors.push("ES256_SIG_INVALID");
      }
    }
  }

  if (mlKey !== undefined) {
    const sig = b64urlToBytes(p.sig.mldsa65.value);
    const pub = b64urlToBytes(mlKey.pub);
    if (sig?.length !== MLDSA_SIG_BYTES) {
      errors.push("MLDSA_SIG_INVALID");
    } else {
      let ok = false;
      try {
        ok =
          pub === null
            ? false
            : ml_dsa65.verify(sig, payload, pub, {
                context: ML_DSA_CONTEXT,
              });
      } catch {
        ok = false;
      }
      if (!ok) errors.push("MLDSA_SIG_INVALID");
    }
  }

  // Cohérence interne v3, après les signatures : on n'analyse le
  // contenu d'une preuve qu'authentifiée — toute erreur de
  // keyset/kid/signature empêche le rapport d'incohérence.
  if (p.v === 3 && errors.length === authErrorsStart) {
    const hf = p.human_factor;
    const controls = p.assurance.controls;
    if (controls.includes("enrollment_confirmed") && hf.confirmed_at === null) {
      reasons.push("enrollment_confirmed_but_confirmed_at_null");
    }
    if (
      controls.includes("enrollment_code_verified") &&
      !hf.enrollment_code_verified
    ) {
      reasons.push("enrollment_code_verified_but_flag_false");
    }
    if (hf.confirmed_at !== null) {
      const enrolled = parseTime(hf.enrolled_at);
      const confirmed = parseTime(hf.confirmed_at);
      if (
        !Number.isNaN(enrolled) &&
        !Number.isNaN(confirmed) &&
        confirmed < enrolled
      ) {
        reasons.push("confirmed_at_before_enrolled_at");
      }
    }
    if (reasons.length > 0) {
      errors.push("ASSURANCE_INCONSISTENT");
    }
  }

  if (
    opts?.now !== undefined &&
    !Number.isNaN(expiresMs) &&
    opts.now.getTime() > expiresMs
  ) {
    errors.push("PROOF_EXPIRED");
  }

  return { ...done(), proof_id: p.proof_id };
}
