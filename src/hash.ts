import { createHash } from "node:crypto";

/** SHA-256 via node:crypto — retourne un Uint8Array (Buffer). */
export function sha256(data: Uint8Array): Uint8Array {
  return createHash("sha256").update(data).digest();
}
