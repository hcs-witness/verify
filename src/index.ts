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
  isProof,
  isUnsignedProof,
  signedPayload,
  type Proof,
  type Presence,
  type PresenceChallenge,
  type ProofAnchor,
  type ProofSignature,
  type UnsignedProof,
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
