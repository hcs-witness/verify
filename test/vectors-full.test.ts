import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

const keygenVectors = JSON.parse(
  readFileSync("test/vectors/mldsa-keygen-acvp.json", "utf8"),
) as { tests: { tcId: number; seed: string; pk: string }[] };

const sigverVectors = JSON.parse(
  readFileSync("test/vectors/mldsa-sigver-acvp.json", "utf8"),
) as {
  tests: {
    tcId: number;
    testPassed: boolean;
    pk: string;
    message: string;
    context: string;
    signature: string;
  }[];
};

const wycheproof = JSON.parse(
  readFileSync("test/vectors/ecdsa-p256-wycheproof.json", "utf8"),
) as {
  testGroups: {
    publicKey: { uncompressed: string };
    tests: {
      tcId: number;
      comment: string;
      msg: string;
      sig: string;
      result: "valid" | "invalid" | "acceptable";
    }[];
  }[];
};

describe("ACVP ML-DSA-65 keyGen — all cases", () => {
  it.each(keygenVectors.tests)("tcId $tcId", ({ seed, pk }) => {
    const keys = ml_dsa65.keygen(hexToBytes(seed));
    expect(Buffer.from(keys.publicKey).toString("hex").toUpperCase()).toBe(pk);
  });
});

describe("ACVP ML-DSA-65 sigVer (external/pure) — all cases", () => {
  it.each(sigverVectors.tests)(
    "tcId $tcId expects $testPassed",
    ({ testPassed, pk, message, context, signature }) => {
      const ok = ml_dsa65.verify(
        hexToBytes(signature),
        hexToBytes(message),
        hexToBytes(pk),
        { context: hexToBytes(context) },
      );
      expect(ok).toBe(testPassed);
    },
  );
});

describe("Wycheproof ECDSA P-256/SHA-256 P1363 via node:crypto — all cases", () => {
  // This file contains zero "acceptable" cases (173 valid, 89 invalid);
  // if upstream adds any, each must be documented individually below.
  const ACCEPTABLE_DECISIONS = new Map<
    number,
    { accept: boolean; reason: string }
  >();

  for (const [groupIndex, group] of wycheproof.testGroups.entries()) {
    const pub = hexToBytes(group.publicKey.uncompressed);
    expect(pub[0]).toBe(4);
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(pub.subarray(1, 33)).toString("base64url"),
      y: Buffer.from(pub.subarray(33, 65)).toString("base64url"),
    };
    let pubKey: ReturnType<typeof createPublicKey> | undefined;
    try {
      pubKey = createPublicKey({ key: jwk, format: "jwk" });
    } catch {
      pubKey = undefined;
    }
    describe(`group ${String(groupIndex)}`, () => {
      it.each(group.tests)(
        "tcId $tcId ($result)",
        ({ tcId, comment, msg, sig, result }) => {
          // Vérification mathématique via le même chemin que
          // verifyProof : JWK P-256 + signature brute r‖s (P1363).
          // node:crypto accepte aussi les high-S (malléables) ;
          // verifyProof les rejette en amont avec ES256_HIGH_S —
          // testé dans verify.test.ts, hors de ce contrôle.
          let ok = false;
          if (pubKey !== undefined) {
            try {
              ok = nodeVerify(
                "sha256",
                Buffer.from(msg, "hex"),
                { key: pubKey, dsaEncoding: "ieee-p1363" },
                Buffer.from(sig, "hex"),
              );
            } catch {
              ok = false;
            }
          }
          const accepted = ACCEPTABLE_DECISIONS.get(tcId);
          if (result === "acceptable") {
            expect(
              accepted,
              `tcId ${String(tcId)} (${comment}) undocumented`,
            ).toBeDefined();
            expect(ok).toBe(accepted?.accept);
          } else {
            expect(ok, `tcId ${String(tcId)} (${comment})`).toBe(
              result === "valid",
            );
          }
        },
      );
    });
  }
});
