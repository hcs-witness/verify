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
 * - proof-v3-valid.json : preuve v3 (historique d'enrôlement + objet
 *   assurance obligatoires) signée par les clés seedées de test —
 *   régénérable via tools/gen-proof-v3-vector.ts, empreinte épinglée.
 */

const rawV1 = readFileSync("test/vectors/proof-v1-valid.json", "utf8");
const rawKeys = readFileSync("test/vectors/keys-test.json", "utf8");
const rawV2 = readFileSync("test/vectors/proof-v2-anchored.json", "utf8");
const rawKeysLocal = readFileSync("test/vectors/keys-local.json", "utf8");
const rawV3 = readFileSync("test/vectors/proof-v3-valid.json", "utf8");
const rawKeysV3 = readFileSync("test/vectors/keys-v3-test.json", "utf8");

// Empreinte de la fixture v1 — la même que celle épinglée en amont.
const V1_SHA256 =
  "c99201f9ec594e5eae2bb1d2f6691572f82ab734250244285b11cd6a9cb48409";
// Empreinte de la fixture v2 générée une fois pour ce dépôt.
const V2_SHA256 =
  "5508f22c262ec8a021c04d27c65b82b7ea48a80f3c581d2a17877cb25853f194";
// Empreinte de la fixture v3 (clés seedées, régénérable).
const V3_SHA256 =
  "e2844f39be64979ab698e4f032a4567e22fc10e00f870753b97816932cf9ba3c";
const V3_KEYSET_SHA256 =
  "5877d9a619a38b55151fc2b2bcaf7a4508d6c2ad167037292bd14d08665568a6";

describe("fixtures réellement émises", () => {
  it("la fixture v1 est épinglée (pas de régénération silencieuse)", () => {
    expect(createHash("sha256").update(rawV1).digest("hex")).toBe(V1_SHA256);
  });

  it("la fixture v2+ancre est épinglée", () => {
    expect(createHash("sha256").update(rawV2).digest("hex")).toBe(V2_SHA256);
  });

  it("la fixture v3 et son jeu de clés sont épinglés", () => {
    expect(createHash("sha256").update(rawV3).digest("hex")).toBe(V3_SHA256);
    expect(createHash("sha256").update(rawKeysV3).digest("hex")).toBe(
      V3_KEYSET_SHA256,
    );
  });

  it("la preuve v3 vérifie à l'identique", () => {
    const r = verifyProof(JSON.parse(rawV3), JSON.parse(rawKeysV3));
    expect(r).toMatchObject({
      valid: true,
      errors: [],
      proof_id: "ggp_01K9V3VECTPR00FV3TEST0000A",
    });
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
