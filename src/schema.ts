import { checkSchema, type JsonSchema } from "./check.js";
import { canonicalBytes } from "./jcs.js";

const ULID_CHARS = "[0-9A-HJKMNP-TV-Z]{26}";

const ulidString = (prefix: string): JsonSchema => ({
  type: "string",
  pattern: `^${prefix}_${ULID_CHARS}$`,
});

const hex64: JsonSchema = { type: "string", pattern: "^[0-9a-f]{64}$" };
const b64url: JsonSchema = { type: "string", pattern: "^[A-Za-z0-9_-]+$" };
const rfc3339Utc: JsonSchema = {
  type: "string",
  pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$",
};
const uuid: JsonSchema = {
  type: "string",
  pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
};

const presenceChallengeSchema: JsonSchema = {
  type: "object",
  required: ["kind", "trials", "completed"],
  additionalProperties: false,
  properties: {
    kind: {
      anyOf: [
        { const: "color", type: "string" },
        { const: "numeric", type: "string" },
        { const: "stroop", type: "string" },
        { const: "size", type: "string" },
      ],
    },
    level: {
      anyOf: [
        { const: "standard", type: "string" },
        { const: "enhanced", type: "string" },
      ],
    },
    trials: { type: "integer", minimum: 0 },
    completed: { type: "boolean" },
  },
};

const presenceSchema: JsonSchema = {
  type: "object",
  required: [
    "model",
    "calibrated",
    "band",
    "challenge",
    "signals",
    "automation_indicators",
    "profile_sha256",
    "rotation",
    "flags",
  ],
  additionalProperties: false,
  properties: {
    model: { const: "presence-v1", type: "string" },
    calibrated: { const: false, type: "boolean" },
    band: { const: "unrated", type: "string" },
    challenge: presenceChallengeSchema,
    signals: {
      anyOf: [
        { const: "trusted", type: "string" },
        { const: "untrusted", type: "string" },
        { const: "absent", type: "string" },
      ],
    },
    automation_indicators: { type: "integer", minimum: 0 },
    profile_sha256: { anyOf: [hex64, { type: "null" }] },
    rotation: {
      type: "object",
      required: ["tw", "ok", "replayed"],
      additionalProperties: false,
      properties: {
        tw: { type: "integer", minimum: 0 },
        ok: { type: "boolean" },
        replayed: { type: "boolean" },
      },
    },
    flags: { type: "array", items: { type: "string" } },
  },
};

const signatureSchema: JsonSchema = {
  type: "object",
  required: ["kid", "value"],
  additionalProperties: false,
  properties: {
    kid: { type: "string", minLength: 1 },
    value: b64url,
  },
};

const humanFactorSchema: JsonSchema = {
  type: "object",
  required: [
    "method",
    "user_verified",
    "credential_id_sha256",
    "authenticator_aaguid",
  ],
  additionalProperties: false,
  properties: {
    method: { const: "webauthn", type: "string" },
    user_verified: { const: true, type: "boolean" },
    credential_id_sha256: hex64,
    authenticator_aaguid: uuid,
  },
};

const unsignedProofProperties: Record<string, JsonSchema> = {
  v: {
    anyOf: [
      { const: 1, type: "number" },
      { const: 2, type: "number" },
    ],
  },
  proof_id: ulidString("ggp"),
  tenant_id: ulidString("tnt"),
  approval_id: ulidString("apr"),
  action: { type: "string", pattern: "^[a-z0-9]+(\\.[a-z0-9_]+){1,5}$" },
  subject_ref: { type: "string", minLength: 1 },
  context_sha256: hex64,
  display_sha256: hex64,
  decision: {
    anyOf: [
      { const: "approved", type: "string" },
      { const: "denied", type: "string" },
      { const: "expired", type: "string" },
    ],
  },
  human_factor: humanFactorSchema,
  signals: {
    type: "object",
    patternProperties: { "^(.*)$": {} },
  },
  presence: presenceSchema,
  issued_at: rfc3339Utc,
  expires_at: rfc3339Utc,
};

const unsignedProofRequired = [
  "v",
  "proof_id",
  "tenant_id",
  "approval_id",
  "action",
  "subject_ref",
  "context_sha256",
  "display_sha256",
  "decision",
  "human_factor",
  "issued_at",
  "expires_at",
];

/** Schéma JSON du document signé — contrat de format, immuable sans ADR. */
export const proofSchema: JsonSchema = {
  type: "object",
  required: [...unsignedProofRequired, "sig"],
  additionalProperties: false,
  properties: {
    ...unsignedProofProperties,
    sig: {
      type: "object",
      required: ["es256", "mldsa65"],
      additionalProperties: false,
      properties: {
        es256: signatureSchema,
        mldsa65: signatureSchema,
      },
    },
    anchor: {
      type: "object",
      required: ["batch_id", "merkle_root", "leaf_index", "path"],
      additionalProperties: false,
      properties: {
        batch_id: { type: "string", minLength: 1 },
        merkle_root: hex64,
        leaf_index: { type: "integer", minimum: 0 },
        path: { type: "array", items: hex64 },
        ots: { type: "string", minLength: 1 },
        bitcoin_block_height: { type: "integer", minimum: 0 },
      },
    },
  },
};

/** Partie signée de la preuve (payload JCS sans `sig` ni `anchor`). */
export const unsignedProofSchema: JsonSchema = {
  type: "object",
  required: unsignedProofRequired,
  additionalProperties: false,
  properties: unsignedProofProperties,
};

export interface PresenceChallenge {
  kind: "color" | "numeric" | "stroop" | "size";
  /** Niveau de décision : absent sur les preuves antérieures à prof-3. */
  level?: "standard" | "enhanced";
  trials: number;
  completed: boolean;
}

/** Bloc présence : consigné dans la preuve signée, JAMAIS utilisé pour la
 *  validité cryptographique. Présent sur v:2, absent sur v:1. */
export interface Presence {
  model: "presence-v1";
  calibrated: false;
  band: "unrated";
  challenge: PresenceChallenge;
  signals: "trusted" | "untrusted" | "absent";
  automation_indicators: number;
  profile_sha256: string | null;
  rotation: {
    tw: number;
    ok: boolean;
    replayed: boolean;
  };
  flags: string[];
}

export interface ProofSignature {
  kid: string;
  value: string;
}

export interface ProofAnchor {
  batch_id: string;
  merkle_root: string;
  leaf_index: number;
  path: string[];
  ots?: string;
  bitcoin_block_height?: number;
}

export interface UnsignedProof {
  v: 1 | 2;
  proof_id: string;
  tenant_id: string;
  approval_id: string;
  action: string;
  subject_ref: string;
  context_sha256: string;
  display_sha256: string;
  decision: "approved" | "denied" | "expired";
  human_factor: {
    method: "webauthn";
    user_verified: true;
    credential_id_sha256: string;
    authenticator_aaguid: string;
  };
  signals?: Record<string, unknown>;
  presence?: Presence;
  issued_at: string;
  expires_at: string;
}

export interface Proof extends UnsignedProof {
  sig: {
    es256: ProofSignature;
    mldsa65: ProofSignature;
  };
  anchor?: ProofAnchor;
}

export function isProof(value: unknown): value is Proof {
  return checkSchema(proofSchema, value);
}

export function isUnsignedProof(value: unknown): value is UnsignedProof {
  return checkSchema(unsignedProofSchema, value);
}

/** Canonical JCS bytes of the proof without `sig` and `anchor` (SPEC §3). */
export function signedPayload(proof: UnsignedProof): Uint8Array {
  const unsigned = { ...proof } as Record<string, unknown>;
  delete unsigned.sig;
  delete unsigned.anchor;
  return canonicalBytes(unsigned);
}
