export { canonicalBytes, NonJsonValueError } from "./jcs.js";
export { bytesToB64url, b64urlToBytes } from "./base64.js";
export { checkSchema, type JsonSchema } from "./check.js";
export {
  keysetSchema,
  isKeyset,
  type Keyset,
  type KeysetKey,
  type Es256KeysetKey,
  type MlDsaKeysetKey,
} from "./keyset.js";
export {
  verifyProof,
  ML_DSA_CONTEXT,
  type VerifyResult,
  type VerifyErrorCode,
  type VerifyOptions,
} from "./verify.js";
export {
  proofSchema,
  unsignedProofSchema,
  proofV1Schema,
  unsignedProofV1Schema,
  proofV2Schema,
  unsignedProofV2Schema,
  proofV3Schema,
  unsignedProofV3Schema,
  proofSchemaForVersion,
  unsignedSchemaForVersion,
  isProof,
  isProofV1,
  isProofV2,
  isProofV3,
  isUnsignedProof,
  isUnsignedProofV1,
  isUnsignedProofV2,
  isUnsignedProofV3,
  signedPayload,
  type AssuranceControl,
  type HumanFactor,
  type HumanFactorV3,
  type Proof,
  type ProofAssurance,
  type ProofV1,
  type ProofV2,
  type ProofV3,
  type Presence,
  type PresenceChallenge,
  type ProofAnchor,
  type ProofSignature,
  type UnsignedProof,
  type UnsignedProofV1,
  type UnsignedProofV2,
  type UnsignedProofV3,
} from "./schema.js";
export {
  checkActionBinding,
  type BindingCheck,
  type BindingErrorCode,
  type BindingResult,
} from "./binding.js";
export {
  merkleLeafHash,
  merkleNodeHash,
  merkleRoot,
  merklePath,
  verifyMerkleInclusion,
} from "./merkle.js";
export {
  OtsError,
  parseOtsFile,
  serializeOtsFile,
  serializeTimestamp,
  allAttestations,
  bitcoinBlockHeight,
  type OtsFile,
  type OtsOp,
  type OtsAttestation,
  type OtsTimestamp,
} from "./ots.js";
export { verifyAnchor, type AnchorResult } from "./anchor.js";
