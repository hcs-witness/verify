/**
 * Générateur one-shot de test/vectors/proof-v3-valid.json et
 * test/vectors/keys-v3-test.json. Usage : node tools/gen-proof-v3-vector.ts
 * Le vecteur est commité ; jamais régénéré silencieusement — un test
 * épingle son empreinte SHA-256.
 */
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

import {
  makeSeededTestSigners,
  signTestProof,
} from "../test/helpers/signer.js";
import type { UnsignedProof } from "../src/index.js";

// Graine du vecteur — clés de test présentes uniquement dans les tests.
const SEED = new TextEncoder().encode("hcs-witness-v3-vector-seed-v1");

const DISPLAY_TEXT =
  "Approve deployment of release 2026-11 to production eu-west.";

const sha = (b: Uint8Array): string =>
  createHash("sha256").update(b).digest("hex");

const dev = makeSeededTestSigners(SEED);

const unsigned = {
  v: 3,
  proof_id: "ggp_01K9V3VECTPR00FV3TEST0000A",
  tenant_id: "tnt_01K9V3VECTPR00FV3TEST0000B",
  approval_id: "apr_01K9V3VECTPR00FV3TEST0000C",
  action: "deploy.release.promote",
  subject_ref: "release-manager-7",
  context_sha256: sha(new TextEncoder().encode("v3-vector-context")),
  display_sha256: sha(new TextEncoder().encode(DISPLAY_TEXT.normalize("NFC"))),
  decision: "approved",
  human_factor: {
    method: "webauthn",
    user_verified: true,
    credential_id_sha256: "c".repeat(64),
    authenticator_aaguid: "3f6b0f42-3d5a-4b8e-9c1d-2e4f5a6b7c8d",
    enrolled_at: "2026-01-10T09:00:00Z",
    confirmed_at: "2026-01-10T09:12:00Z",
    invited_by_ref: "apr_01K9V3VECT0R1NV1TER0000000",
    confirmed_by_ref: "adm_01K9V3VECT0RC0NF1RM0000000",
    self_confirmed: false,
    enrollment_code_verified: true,
  },
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
  presence: {
    model: "presence-v1",
    calibrated: false,
    band: "unrated",
    challenge: { kind: "numeric", trials: 8, completed: true },
    signals: "trusted",
    automation_indicators: 0,
    profile_sha256: "d".repeat(64),
    rotation: { tw: 12, ok: true, replayed: false },
    flags: ["synced_passkey"],
  },
  issued_at: "2026-02-01T10:00:00Z",
  expires_at: "2026-08-01T10:00:00Z",
} as unknown as UnsignedProof;

const proof = signTestProof(unsigned, dev);

const keyset = {
  _comment: "TEST ONLY - never use in production",
  keys: [
    {
      ...dev.es256.publicJwk(),
      status: "active",
      not_before: "2020-01-01T00:00:00Z",
    },
    {
      ...dev.mldsa65.publicJwk(),
      status: "active",
      not_before: "2020-01-01T00:00:00Z",
    },
  ],
};

writeFileSync(
  "test/vectors/proof-v3-valid.json",
  `${JSON.stringify(proof, null, 2)}\n`,
);
writeFileSync(
  "test/vectors/keys-v3-test.json",
  `${JSON.stringify(keyset, null, 2)}\n`,
);
process.stdout.write(
  `written ${proof.proof_id} ${dev.es256.kid} ${dev.mldsa65.kid}\n`,
);
