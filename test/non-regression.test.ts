import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { verifyAnchor, verifyProof } from "../src/index.js";

/**
 * Non-régression sur les fixtures réelles :
 * - proof-v1-valid.json : preuve v1 émise par la plateforme (vecteur
 *   épinglé en amont, régénération interdite).
 * - proof-v2-anchored.json : preuve v2 + presence émise localement par
 *   le chemin de signature réel (buildUnsignedProof + signProof), avec
 *   ancre Merkle + fichier .ots attestant la racine.
 */

const rawV1 = readFileSync("test/vectors/proof-v1-valid.json", "utf8");
const rawKeys = readFileSync("test/vectors/keys-test.json", "utf8");
const rawV2 = readFileSync("test/vectors/proof-v2-anchored.json", "utf8");
const rawKeysLocal = readFileSync("test/vectors/keys-local.json", "utf8");

// Empreinte de la fixture v1 — la même que celle épinglée en amont.
const V1_SHA256 =
  "c99201f9ec594e5eae2bb1d2f6691572f82ab734250244285b11cd6a9cb48409";
// Empreinte de la fixture v2 générée une fois pour ce dépôt.
const V2_SHA256 =
  "5508f22c262ec8a021c04d27c65b82b7ea48a80f3c581d2a17877cb25853f194";

describe("fixtures réellement émises", () => {
  it("la fixture v1 est épinglée (pas de régénération silencieuse)", () => {
    expect(createHash("sha256").update(rawV1).digest("hex")).toBe(V1_SHA256);
  });

  it("la fixture v2+ancre est épinglée", () => {
    expect(createHash("sha256").update(rawV2).digest("hex")).toBe(V2_SHA256);
  });

  it("la preuve v1 vérifie à l'identique", () => {
    const r = verifyProof(JSON.parse(rawV1), JSON.parse(rawKeys));
    expect(r).toMatchObject({
      valid: true,
      errors: [],
      proof_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    });
  });

  it("la preuve v2+ancre vérifie à l'identique (signatures + ancrage)", () => {
    const proof = JSON.parse(rawV2) as unknown;
    const keyset = JSON.parse(rawKeysLocal) as unknown;
    expect(verifyProof(proof, keyset)).toMatchObject({
      valid: true,
      errors: [],
    });
    expect(verifyAnchor(proof)).toMatchObject({
      present: true,
      inclusion: true,
      otsMatchesRoot: true,
      bitcoinBlockHeight: 915042,
    });
  });
});
