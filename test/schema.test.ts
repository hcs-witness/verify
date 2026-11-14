import { describe, expect, it } from "vitest";

import {
  isProof,
  isUnsignedProof,
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
