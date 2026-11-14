import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  canonicalBytes,
  checkActionBinding,
  verifyProof,
  type UnsignedProof,
} from "../src/index.js";
import { makeTestSigners, signTestProof } from "./helpers/signer.js";

const signers = makeTestSigners();

const keyset = signers.keyset();

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function makeProof(
  displayText: string,
  context: Record<string, unknown>,
  action = "armoury.firearm.release",
) {
  const contextSha = createHash("sha256")
    .update(canonicalBytes(context))
    .digest("hex");
  const unsigned = {
    v: 1,
    proof_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    tenant_id: "tnt_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    approval_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAX",
    action,
    subject_ref: "operator-42",
    context_sha256: contextSha,
    display_sha256: sha256HexUtf8(displayText.normalize("NFC")),
    decision: "approved",
    human_factor: {
      method: "webauthn",
      user_verified: true,
      credential_id_sha256: "b".repeat(64),
      authenticator_aaguid: "3f6b0f42-3d5a-4b8e-9c1d-2e4f5a6b7c8d",
    },
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
  } as UnsignedProof;
  return signTestProof(unsigned, signers);
}

describe("checkActionBinding", () => {
  it("accepts the exact action, context and display text", () => {
    const displayText = "Sortie HK416 — rack 4 🔫\nOpérateur requis";
    const context = { weapon: "HK416", rack: 4 };
    const proof = makeProof(displayText, context);
    expect(verifyProof(proof, keyset).valid).toBe(true);
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release",
      context,
      displayText,
    });
    expect(r).toEqual({ valid: true, errors: [] });
  });

  it("gives the same fingerprint for emoji, accents and a newline", () => {
    const displayText = "Libérer 🔫\nCafé";
    const proof = makeProof(displayText, {});
    // Decomposed vs composed input : même empreinte (NFC des deux côtés).
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release",
      context: {},
      displayText: "Libérer 🔫\nCafé".normalize("NFD"),
    });
    expect(r.valid).toBe(true);
    expect(proof.display_sha256).toBe(
      sha256HexUtf8(displayText.normalize("NFC")),
    );
  });

  it("rejects a modified action", () => {
    const proof = makeProof("Release", { a: 1 });
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release_v2",
      context: { a: 1 },
      displayText: "Release",
    });
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("ACTION_MISMATCH");
  });

  it("rejects a modified context", () => {
    const proof = makeProof("Release", { weapon: "HK416" });
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release",
      context: { weapon: "MP5" },
      displayText: "Release",
    });
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("CONTEXT_MISMATCH");
  });

  it("rejects a modified display text", () => {
    const proof = makeProof("Release HK416 from rack 4", {});
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release",
      context: {},
      displayText: "Release MP5 from rack 4",
    });
    expect(r.valid).toBe(false);
    expect(r.errors).toContain("DISPLAY_MISMATCH");
  });

  it("rejects a non-proof input", () => {
    const r = checkActionBinding(
      { action: "x" },
      { action: "x", context: {}, displayText: "y" },
    );
    expect(r).toEqual({ valid: false, errors: ["SCHEMA_INVALID"] });
  });

  it("the reference vector binds its documented display text", () => {
    const proof = JSON.parse(
      readFileSync("test/vectors/proof-v1-valid.json", "utf8"),
    ) as Record<string, unknown>;
    // context_sha256 = "aa…" — le contexte du vecteur ne peut pas être
    // reproduit : on vérifie action + texte affiché.
    const r = checkActionBinding(proof, {
      action: "armoury.firearm.release",
      context: {},
      displayText: "Release firearm HK416 (serial FA-17) from rack 4.",
    });
    expect(r.errors).toEqual(["CONTEXT_MISMATCH"]);
    expect(r.errors).not.toContain("ACTION_MISMATCH");
    expect(r.errors).not.toContain("DISPLAY_MISMATCH");
  });
});
