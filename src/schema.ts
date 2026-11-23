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

const opaqueRef: JsonSchema = {
  anyOf: [{ type: "string", minLength: 1 }, { type: "null" }],
};

/** human_factor v3 : champs v1/v2 + historique d'enrôlement, tous
 *  OBLIGATOIRES (la valeur peut être null quand le contrat le prévoit).
 *  Les références sont des identifiants opaques, jamais des adresses
 *  ni des noms (contrat H3). */
const humanFactorV3Schema: JsonSchema = {
  type: "object",
  required: [
    "method",
    "user_verified",
    "credential_id_sha256",
    "authenticator_aaguid",
    "enrolled_at",
    "confirmed_at",
    "invited_by_ref",
    "confirmed_by_ref",
    "self_confirmed",
    "enrollment_code_verified",
  ],
  additionalProperties: false,
  properties: {
    method: { const: "webauthn", type: "string" },
    user_verified: { const: true, type: "boolean" },
    credential_id_sha256: hex64,
    authenticator_aaguid: uuid,
    enrolled_at: rfc3339Utc,
    confirmed_at: { anyOf: [rfc3339Utc, { type: "null" }] },
    invited_by_ref: opaqueRef,
    confirmed_by_ref: opaqueRef,
    self_confirmed: { type: "boolean" },
    enrollment_code_verified: { type: "boolean" },
  },
};

const ASSURANCE_CONTROLS = [
  "passkey_uv",
  "enrollment_code_verified",
  "enrollment_confirmed",
  "maturation_satisfied",
  "presence_measured",
] as const;

/** Niveau de garantie déclaré par l'émetteur : le vérificateur contrôle
 *  la FORME, pas la véracité — un contrôle listé doit refléter une
 *  vérification réellement passée côté émetteur. */
const assuranceSchema: JsonSchema = {
  type: "object",
  required: ["level", "controls"],
  additionalProperties: false,
  properties: {
    level: {
      anyOf: [
        { const: "N1", type: "string" },
        { const: "N2", type: "string" },
      ],
    },
    controls: {
      type: "array",
      uniqueItems: true,
      items: {
        anyOf: ASSURANCE_CONTROLS.map((c) => ({
          const: c,
          type: "string",
        })),
      },
    },
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

const sigSchema: JsonSchema = {
  type: "object",
  required: ["es256", "mldsa65"],
  additionalProperties: false,
  properties: {
    es256: signatureSchema,
    mldsa65: signatureSchema,
  },
};

const anchorSchema: JsonSchema = {
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
    sig: sigSchema,
    anchor: anchorSchema,
  },
};

/** Partie signée de la preuve (payload JCS sans `sig` ni `anchor`). */
export const unsignedProofSchema: JsonSchema = {
  type: "object",
  required: unsignedProofRequired,
  additionalProperties: false,
  properties: unsignedProofProperties,
};

/* ---- v3 : v2 + historique d'enrôlement sous human_factor + objet
 * assurance, tous OBLIGATOIRES. Les schémas v1/v2 restent octet pour
 * octet le schéma historique : toute preuve v:1 ou v:2 déjà émise
 * reste vérifiable indéfiniment. ---- */

const unsignedProofV3Properties: Record<string, JsonSchema> = {
  ...unsignedProofProperties,
  v: { const: 3, type: "number" },
  human_factor: humanFactorV3Schema,
  assurance: assuranceSchema,
};

const unsignedProofV3Required = [...unsignedProofRequired, "assurance"];

/** Schémas v1 et v2 — alias explicites du schéma historique, octet
 *  pour octet (le champ `v` du document sélectionne le schéma). */
export const proofV1Schema: JsonSchema = proofSchema;
export const unsignedProofV1Schema: JsonSchema = unsignedProofSchema;
export const proofV2Schema: JsonSchema = proofSchema;
export const unsignedProofV2Schema: JsonSchema = unsignedProofSchema;

/** Document signé v3. */
export const proofV3Schema: JsonSchema = {
  type: "object",
  required: [...unsignedProofV3Required, "sig"],
  additionalProperties: false,
  properties: {
    ...unsignedProofV3Properties,
    sig: sigSchema,
    anchor: anchorSchema,
  },
};

export const unsignedProofV3Schema: JsonSchema = {
  type: "object",
  required: unsignedProofV3Required,
  additionalProperties: false,
  properties: unsignedProofV3Properties,
};

/** Schéma du document signé selon `v` — null pour une version inconnue. */
export function proofSchemaForVersion(v: unknown): JsonSchema | null {
  if (v === 1) return proofV1Schema;
  if (v === 2) return proofV2Schema;
  if (v === 3) return proofV3Schema;
  return null;
}

/** Schéma de la partie signée selon `v` — null pour version inconnue. */
export function unsignedSchemaForVersion(v: unknown): JsonSchema | null {
  if (v === 1) return unsignedProofV1Schema;
  if (v === 2) return unsignedProofV2Schema;
  if (v === 3) return unsignedProofV3Schema;
  return null;
}

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

export interface HumanFactor {
  method: "webauthn";
  user_verified: true;
  credential_id_sha256: string;
  authenticator_aaguid: string;
}

/** human_factor v3 : ajoute l'historique d'enrôlement, tous les
 *  champs obligatoires (nullable quand le contrat le prévoit).
 *  Références opaques résolvables par un admin du tenant — jamais
 *  d'adresse ni de nom (contrat H3). */
export interface HumanFactorV3 extends HumanFactor {
  enrolled_at: string;
  confirmed_at: string | null;
  invited_by_ref: string | null;
  confirmed_by_ref: string | null;
  self_confirmed: boolean;
  enrollment_code_verified: boolean;
}

export type AssuranceControl =
  | "passkey_uv"
  | "enrollment_code_verified"
  | "enrollment_confirmed"
  | "maturation_satisfied"
  | "presence_measured";

/** Niveau de garantie déclaré par l'émetteur : N1 = passkey vérifiée
 *  seule ; N2 = au moins un contrôle de canal d'enrôlement passé. */
export interface ProofAssurance {
  level: "N1" | "N2";
  controls: AssuranceControl[];
}

interface UnsignedProofBase {
  proof_id: string;
  tenant_id: string;
  approval_id: string;
  action: string;
  subject_ref: string;
  context_sha256: string;
  display_sha256: string;
  decision: "approved" | "denied" | "expired";
  signals?: Record<string, unknown>;
  presence?: Presence;
  issued_at: string;
  expires_at: string;
}

export interface UnsignedProofV1 extends UnsignedProofBase {
  v: 1;
  human_factor: HumanFactor;
}

export interface UnsignedProofV2 extends UnsignedProofBase {
  v: 2;
  human_factor: HumanFactor;
}

export interface UnsignedProofV3 extends UnsignedProofBase {
  v: 3;
  human_factor: HumanFactorV3;
  assurance: ProofAssurance;
}

export type UnsignedProof = UnsignedProofV1 | UnsignedProofV2 | UnsignedProofV3;

interface ProofFields {
  sig: {
    es256: ProofSignature;
    mldsa65: ProofSignature;
  };
  anchor?: ProofAnchor;
}

export type ProofV1 = UnsignedProofV1 & ProofFields;
export type ProofV2 = UnsignedProofV2 & ProofFields;
export type ProofV3 = UnsignedProofV3 & ProofFields;
export type Proof = ProofV1 | ProofV2 | ProofV3;

function versionOf(value: unknown): unknown {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>).v
    : undefined;
}

export function isProofV1(value: unknown): value is ProofV1 {
  return checkSchema(proofV1Schema, value);
}

export function isProofV2(value: unknown): value is ProofV2 {
  return checkSchema(proofV2Schema, value);
}

export function isProofV3(value: unknown): value is ProofV3 {
  return checkSchema(proofV3Schema, value);
}

export function isProof(value: unknown): value is Proof {
  const schema = proofSchemaForVersion(versionOf(value));
  return schema !== null && checkSchema(schema, value);
}

export function isUnsignedProofV1(value: unknown): value is UnsignedProofV1 {
  return checkSchema(unsignedProofV1Schema, value);
}

export function isUnsignedProofV2(value: unknown): value is UnsignedProofV2 {
  return checkSchema(unsignedProofV2Schema, value);
}

export function isUnsignedProofV3(value: unknown): value is UnsignedProofV3 {
  return checkSchema(unsignedProofV3Schema, value);
}

export function isUnsignedProof(value: unknown): value is UnsignedProof {
  const schema = unsignedSchemaForVersion(versionOf(value));
  return schema !== null && checkSchema(schema, value);
}

/** Canonical JCS bytes of the proof without `sig` and `anchor` (SPEC §3). */
export function signedPayload(proof: UnsignedProof): Uint8Array {
  const unsigned = { ...proof } as Record<string, unknown>;
  delete unsigned.sig;
  delete unsigned.anchor;
  return canonicalBytes(unsigned);
}
