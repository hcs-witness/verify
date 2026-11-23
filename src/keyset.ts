import { checkSchema, type JsonSchema } from "./check.js";
import { sha256 } from "./hash.js";
import { canonicalBytes } from "./jcs.js";

const b64url: JsonSchema = { type: "string", pattern: "^[A-Za-z0-9_-]+$" };
const rfc3339Utc: JsonSchema = {
  type: "string",
  pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$",
};

const keyBase = {
  use: { const: "sig", type: "string" },
  kid: { type: "string", minLength: 1 },
  status: {
    anyOf: [
      { const: "active", type: "string" },
      { const: "retired", type: "string" },
    ],
  },
  not_before: rfc3339Utc,
  not_after: rfc3339Utc,
} satisfies Record<string, JsonSchema>;

const keyBaseRequired = ["use", "kid", "status", "not_before"];

/** Schéma JSON du jeu de clés publiques (/.well-known/hcs-keys.json). */
export const keysetSchema: JsonSchema = {
  type: "object",
  required: ["keys"],
  additionalProperties: false,
  properties: {
    _comment: { type: "string" },
    keys: {
      type: "array",
      items: {
        anyOf: [
          {
            type: "object",
            required: ["kty", "crv", "x", "y", "alg", ...keyBaseRequired],
            additionalProperties: false,
            properties: {
              kty: { const: "EC", type: "string" },
              crv: { const: "P-256", type: "string" },
              x: b64url,
              y: b64url,
              alg: { const: "ES256", type: "string" },
              ...keyBase,
            },
          },
          {
            type: "object",
            required: ["kty", "alg", "pub", ...keyBaseRequired],
            additionalProperties: false,
            properties: {
              kty: { const: "AKP", type: "string" },
              alg: { const: "ML-DSA-65", type: "string" },
              pub: b64url,
              ...keyBase,
            },
          },
        ],
      },
    },
  },
};

interface KeysetKeyBase {
  use: "sig";
  kid: string;
  status: "active" | "retired";
  not_before: string;
  not_after?: string;
}

export interface Es256KeysetKey extends KeysetKeyBase {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  alg: "ES256";
}

export interface MlDsaKeysetKey extends KeysetKeyBase {
  kty: "AKP";
  alg: "ML-DSA-65";
  pub: string;
}

export type KeysetKey = Es256KeysetKey | MlDsaKeysetKey;

export interface Keyset {
  _comment?: string;
  keys: KeysetKey[];
}

export function isKeyset(value: unknown): value is Keyset {
  return checkSchema(keysetSchema, value);
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Empreinte SHA-256 du jeu de clés sous sa forme canonique JCS — la
 * valeur exacte de l'ETag servi par /.well-known/hcs-witness-keys.json
 * (même calcul côté émetteur). Publiée hors bande : le document du jeu
 * de clés et son schéma restent inchangés.
 */
export function keysetSha256(keyset: unknown): string {
  return hex(sha256(canonicalBytes(keyset)));
}
