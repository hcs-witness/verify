import { describe, expect, it } from "vitest";

import {
  isProof,
  isProofV1,
  isProofV2,
  isProofV3,
  isUnsignedProof,
  isUnsignedProofV3,
  signedPayload,
  type Proof,
} from "../src/index.js";

const HEX64 = "a".repeat(64);

const validUnsigned = {
  v: 1,
  proof_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  tenant_id: "tnt_01ARZ3NDEKTSV4RRFFQ69G5FAW",
  approval_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAX",
  action: "armoury.firearm.release",
  subject_ref: "operator-42",
  context_sha256: HEX64,
  display_sha256: HEX64,
  decision: "approved",
  human_factor: {
    method: "webauthn",
    user_verified: true,
    credential_id_sha256: HEX64,
    authenticator_aaguid: "3f6b0f42-3d5a-4b8e-9c1d-2e4f5a6b7c8d",
  },
  issued_at: "2026-01-01T00:00:00Z",
  expires_at: "2026-01-01T00:05:00Z",
} as const;

const validProof = {
  ...validUnsigned,
  sig: {
    es256: { kid: "k1", value: "A_-z" },
    mldsa65: { kid: "k2", value: "B_x0" },
  },
} as const;

describe("proofSchema", () => {
  it("accepts a valid v1 proof", () => {
    expect(isProof(validProof)).toBe(true);
  });

  it("accepts optional anchor and signals", () => {
    const p = {
      ...validProof,
      signals: { mouse: 1 },
      anchor: {
        batch_id: "b1",
        merkle_root: HEX64,
        leaf_index: 0,
        path: [HEX64],
      },
    };
    expect(isProof(p)).toBe(true);
  });

  it.each([
    ["v", { v: 3 }],
    ["proof_id bad prefix", { proof_id: "x_01ARZ3NDEKTSV4RRFFQ69G5FAV" }],
    ["proof_id short", { proof_id: "ggp_01J8" }],
    ["proof_id bad char", { proof_id: "ggp_01J8EXAMPLE0TESTINGONLYABI" }],
    ["tenant_id prefix", { tenant_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAW" }],
    ["action upper", { action: "Armoury.firearm" }],
    ["action no dot", { action: "armoury" }],
    ["context hex upper", { context_sha256: "A".repeat(64) }],
    ["context hex short", { context_sha256: "ab" }],
    ["display hex upper", { display_sha256: "A".repeat(64) }],
    ["display missing", { display_sha256: undefined }],
    ["decision", { decision: "maybe" }],
    ["issued_at no Z", { issued_at: "2026-01-01T00:00:00+01:00" }],
    ["issued_at 4 decimals", { issued_at: "2026-01-01T00:00:00.0001Z" }],
    [
      "aaguid",
      {
        human_factor: {
          ...validUnsigned.human_factor,
          authenticator_aaguid: "nope",
        },
      },
    ],
    ["extra field", { extra: 1 }],
  ])("rejects %s", (_name, patch) => {
    const p = { ...validProof, ...patch };
    expect(isProof(p)).toBe(false);
  });

  it("rejects extra fields in nested objects", () => {
    const p = {
      ...validProof,
      human_factor: { ...validProof.human_factor, x: 1 },
    };
    expect(isProof(p)).toBe(false);
  });
});

describe("unsignedProofSchema", () => {
  it("accepts the unsigned part", () => {
    expect(isUnsignedProof(validUnsigned)).toBe(true);
  });

  it("rejects a signed proof (sig is an extra field)", () => {
    expect(isUnsignedProof(validProof)).toBe(false);
  });
});

describe("signedPayload", () => {
  it("equals canonical bytes of proof without sig and anchor", () => {
    const withAnchor = {
      ...validProof,
      anchor: { batch_id: "b", merkle_root: HEX64, leaf_index: 0, path: [] },
    };
    const expected = new TextEncoder().encode(
      JSON.stringify({
        action: "armoury.firearm.release",
        approval_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAX",
        context_sha256: HEX64,
        decision: "approved",
        display_sha256: HEX64,
        expires_at: "2026-01-01T00:05:00Z",
        human_factor: {
          authenticator_aaguid: "3f6b0f42-3d5a-4b8e-9c1d-2e4f5a6b7c8d",
          credential_id_sha256: HEX64,
          method: "webauthn",
          user_verified: true,
        },
        issued_at: "2026-01-01T00:00:00Z",
        proof_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        subject_ref: "operator-42",
        tenant_id: "tnt_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        v: 1,
      }),
    );
    expect(signedPayload(withAnchor as Proof)).toEqual(expected);
  });
});

const validV3HumanFactor = {
  ...validUnsigned.human_factor,
  enrolled_at: "2025-12-01T10:00:00Z",
  confirmed_at: "2025-12-01T12:00:00Z",
  invited_by_ref: "cu_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  confirmed_by_ref: "cu_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  self_confirmed: false,
  enrollment_code_verified: true,
} as const;

const validV3Proof = {
  ...validProof,
  v: 3,
  human_factor: validV3HumanFactor,
  assurance: {
    level: "N2",
    controls: [
      "passkey_uv",
      "enrollment_code_verified",
      "enrollment_confirmed",
      "maturation_satisfied",
      "presence_measured",
    ],
  },
} as const;

describe("proofV3Schema — version dispatch", () => {
  it("accepts a full v3 proof (enrollment fields + assurance)", () => {
    expect(isProofV3(validV3Proof)).toBe(true);
    expect(isProof(validV3Proof)).toBe(true);
  });

  it("v1 and v2 proofs unchanged (non-regression)", () => {
    expect(isProofV1(validProof)).toBe(true);
    expect(isProof({ ...validProof, v: 2 })).toBe(true);
    expect(isProofV2({ ...validProof, v: 2 })).toBe(true);
  });

  it("rejects v3 fields on a v:1 proof", () => {
    const p = { ...validV3Proof, v: 1 };
    expect(isProofV1(p)).toBe(false);
    expect(isProof(p)).toBe(false);
  });

  it("rejects v3 fields on a v:2 proof", () => {
    const p = { ...validV3Proof, v: 2 };
    expect(isProofV2(p)).toBe(false);
    expect(isProof(p)).toBe(false);
  });

  it("rejects an unknown version", () => {
    expect(isProof({ ...validProof, v: 4 })).toBe(false);
    expect(isProofV1({ ...validProof, v: 4 })).toBe(false);
    expect(isProofV2({ ...validProof, v: 4 })).toBe(false);
    expect(isProofV3({ ...validProof, v: 4 })).toBe(false);
  });

  it("rejects non-object input", () => {
    expect(isProof("x")).toBe(false);
    expect(isProofV3(42)).toBe(false);
  });

  it("accepts nullable enrollment fields", () => {
    const p = {
      ...validV3Proof,
      human_factor: {
        ...validV3HumanFactor,
        confirmed_at: null,
        invited_by_ref: null,
        confirmed_by_ref: null,
      },
    };
    expect(isProofV3(p)).toBe(true);
  });
});

describe("proofV3Schema — strictness per level", () => {
  it.each([
    ["root", (p: Record<string, unknown>) => ({ ...p, extra_v2: 1 })],
    [
      "human_factor",
      (p: Record<string, unknown>) => ({
        ...p,
        human_factor: { ...validV3HumanFactor, x: 1 },
      }),
    ],
    [
      "assurance",
      (p: Record<string, unknown>) => ({
        ...p,
        assurance: { level: "N2", controls: [], other: true },
      }),
    ],
    [
      "sig.es256",
      (p: Record<string, unknown>) => ({
        ...p,
        sig: { ...(p.sig as object), es256: { kid: "k", value: "A", x: 1 } },
      }),
    ],
  ])("rejects an unknown field at %s level", (_n, mutateFn) => {
    expect(isProofV3(mutateFn(validV3Proof) as object)).toBe(false);
  });

  it.each([
    ["level N3", { level: "N3", controls: ["passkey_uv"] }],
    [
      "unknown control",
      { level: "N1", controls: ["passkey_uv", "magic_check"] },
    ],
    [
      "duplicate control",
      { level: "N1", controls: ["passkey_uv", "passkey_uv"] },
    ],
    ["control non-string", { level: "N1", controls: ["passkey_uv", 3] }],
  ])("rejects assurance with %s", (_n, assurance) => {
    const p = { ...validV3Proof, assurance };
    expect(isProofV3(p)).toBe(false);
  });

  it("rejects a v3 proof without assurance", () => {
    const p = JSON.parse(JSON.stringify(validV3Proof)) as Record<
      string,
      unknown
    >;
    delete p.assurance;
    expect(isProofV3(p)).toBe(false);
  });

  it.each([
    "enrolled_at",
    "confirmed_at",
    "invited_by_ref",
    "confirmed_by_ref",
    "self_confirmed",
    "enrollment_code_verified",
  ])("rejects a v3 proof missing human_factor.%s", (field) => {
    const hf = Object.fromEntries(
      Object.entries(validV3HumanFactor).filter(([k]) => k !== field),
    );
    const p = { ...validV3Proof, human_factor: hf };
    expect(isProofV3(p)).toBe(false);
  });

  it.each([
    ["enrolled_at not rfc3339", { enrolled_at: "hier" }],
    ["confirmed_at number", { confirmed_at: 42 }],
    ["self_confirmed string", { self_confirmed: "oui" }],
    [
      "enrollment_code_verified missing type",
      { enrollment_code_verified: "true" },
    ],
    ["invited_by_ref empty", { invited_by_ref: "" }],
  ])("rejects human_factor.%s", (_n, patch) => {
    const p = {
      ...validV3Proof,
      human_factor: { ...validV3HumanFactor, ...patch },
    };
    expect(isProofV3(p)).toBe(false);
  });
});

describe("unsignedProofV3Schema", () => {
  it("accepts the unsigned v3 part", () => {
    const unsigned = JSON.parse(JSON.stringify(validV3Proof)) as Record<
      string,
      unknown
    >;
    delete unsigned.sig;
    expect(isUnsignedProofV3(unsigned)).toBe(true);
    expect(isUnsignedProof(unsigned)).toBe(true);
  });

  it("rejects a signed v3 proof (sig is extra)", () => {
    expect(isUnsignedProofV3(validV3Proof)).toBe(false);
  });

  it("isUnsignedProof rejects v3 fields on v:1 and v:2", () => {
    const unsigned = JSON.parse(JSON.stringify(validV3Proof)) as Record<
      string,
      unknown
    >;
    delete unsigned.sig;
    expect(isUnsignedProof({ ...unsigned, v: 1 })).toBe(false);
    expect(isUnsignedProof({ ...unsigned, v: 2 })).toBe(false);
  });
});
