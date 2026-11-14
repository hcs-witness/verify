import { sha256 } from "./hash.js";

import { canonicalBytes } from "./jcs.js";
import { isProof, type Proof } from "./schema.js";

export type BindingErrorCode =
  | "SCHEMA_INVALID"
  | "ACTION_MISMATCH"
  | "CONTEXT_MISMATCH"
  | "DISPLAY_MISMATCH";

export interface BindingCheck {
  /** Action about to be executed, e.g. "armoury.firearm.release". */
  readonly action: string;
  /** Same context object that was sent with the approval request. */
  readonly context: Record<string, unknown>;
  /** Exact text the human was shown (NFC normalization applied). */
  readonly displayText: string;
}

export interface BindingResult {
  readonly valid: boolean;
  readonly errors: readonly BindingErrorCode[];
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Binds the proof to what is about to be executed: the caller MUST run
 * this check right before performing the action, with the action, the
 * context and the exact display text. It closes the loop between what
 * the human saw on the approval page and what the system executes —
 * a mismatch means the proof was issued for something else.
 */
export function checkActionBinding(
  proof: unknown,
  expected: BindingCheck,
): BindingResult {
  if (!isProof(proof)) {
    return { valid: false, errors: ["SCHEMA_INVALID"] };
  }
  const p: Proof = proof;
  const errors: BindingErrorCode[] = [];

  if (p.action !== expected.action) {
    errors.push("ACTION_MISMATCH");
  }

  let contextHex: string;
  try {
    contextHex = hex(sha256(canonicalBytes(expected.context)));
  } catch {
    contextHex = "";
  }
  if (contextHex !== p.context_sha256) {
    errors.push("CONTEXT_MISMATCH");
  }

  const displayHex = hex(
    sha256(new TextEncoder().encode(expected.displayText.normalize("NFC"))),
  );
  if (displayHex !== p.display_sha256) {
    errors.push("DISPLAY_MISMATCH");
  }

  return { valid: errors.length === 0, errors };
}
