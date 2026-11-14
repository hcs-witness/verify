import {
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  b64urlToBytes,
  bytesToB64url,
  ML_DSA_CONTEXT,
  signedPayload,
  verifyProof,
  type UnsignedProof,
} from "../src/index.js";
import {
  es256Kid,
  makeTestSigners,
  mlDsaKid,
  signTestProof,
} from "./helpers/signer.js";

const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const baseProof = JSON.parse(
  readFileSync("test/vectors/proof-v1-valid.json", "utf8"),
) as Record<string, unknown>;
delete baseProof.sig;
delete baseProof.anchor;
const unsigned = baseProof as unknown as UnsignedProof;
const payload = signedPayload(unsigned);

describe("ES256: signatures node:crypto vérifiées par verifyProof", () => {
  it("une preuve signée node:crypto (P1363 low-S) est valide", () => {
    const signers = makeTestSigners();
    const proof = signTestProof(unsigned, signers);
    const r = verifyProof(proof, signers.keyset());
    expect(r).toMatchObject({ valid: true, errors: [] });
  });

  it("une signature high-S produite par node:crypto est refusée", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const sig = nodeSign("sha256", Buffer.from(payload), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    // force s := n - s → high-S
    const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
    const s2 = s > P256_ORDER / 2n ? s : P256_ORDER - s;
    const highS = Buffer.concat([
      sig.subarray(0, 32),
      Buffer.from(s2.toString(16).padStart(64, "0"), "hex"),
    ]);
    const jwk = publicKey.export({ format: "jwk" }) as {
      x: string;
      y: string;
    };
    const kid = es256Kid(jwk.x, jwk.y);
    const proof = {
      ...unsigned,
      sig: {
        es256: { kid, value: bytesToB64url(new Uint8Array(highS)) },
        mldsa65: { kid: "irrelevant", value: "AA" },
      },
    };
    const keyset = {
      keys: [
        {
          kty: "EC",
          crv: "P-256",
          x: jwk.x,
          y: jwk.y,
          alg: "ES256",
          use: "sig",
          kid,
          status: "active",
          not_before: "2020-01-01T00:00:00Z",
        },
      ],
    };
    const r = verifyProof(proof, keyset);
    expect(r.errors).toContain("ES256_HIGH_S");
  });
});

// ML-DSA-65 natif dans node:crypto : Node ≥ 24 uniquement — ces tests
// sont sautés sous Node 22 (le paquet lui-même n'en a pas besoin).
const NODE_MAJOR = Number(process.versions.node.split(".")[0]);
describe.runIf(NODE_MAJOR >= 24)(
  "ML-DSA-65: signature node:crypto vérifiée par le paquet (noble)",
  () => {
    it("node:crypto ml-dsa-65 + contexte → noble verify OK", () => {
      const { publicKey, privateKey } = generateKeyPairSync("ml-dsa-65");
      const sig = nodeSign(null, payload, {
        key: privateKey,
        context: ML_DSA_CONTEXT,
      });
      const jwk = publicKey.export({ format: "jwk" }) as { pub: string };
      expect(
        ml_dsa65.verify(
          new Uint8Array(sig),
          payload,
          b64urlToBytes(jwk.pub) ?? new Uint8Array(),
          { context: ML_DSA_CONTEXT },
        ),
      ).toBe(true);
    });

    it("une preuve signée ML-DSA node:crypto est valide via verifyProof", () => {
      const { publicKey, privateKey } = generateKeyPairSync("ml-dsa-65");
      const jwk = publicKey.export({ format: "jwk" }) as { pub: string };
      const pub = b64urlToBytes(jwk.pub);
      expect(pub).not.toBeNull();
      const kid = mlDsaKid(pub as Uint8Array);
      const sig = nodeSign(null, payload, {
        key: privateKey,
        context: ML_DSA_CONTEXT,
      });
      const signers = makeTestSigners();
      const es = signers.es256.sign(payload);
      const proof = {
        ...unsigned,
        sig: {
          es256: { kid: signers.es256.kid, value: bytesToB64url(es) },
          mldsa65: { kid, value: bytesToB64url(new Uint8Array(sig)) },
        },
      };
      const keyset = {
        keys: [
          {
            ...signers.es256.publicJwk(),
            status: "active",
            not_before: "2020-01-01T00:00:00Z",
          },
          {
            kty: "AKP",
            alg: "ML-DSA-65",
            pub: jwk.pub,
            use: "sig",
            kid,
            status: "active",
            not_before: "2020-01-01T00:00:00Z",
          },
        ],
      };
      const r = verifyProof(proof, keyset);
      expect(r).toMatchObject({ valid: true, errors: [] });
    });
  },
);

describe("vérification croisée : notre sortie relue par node:crypto", () => {
  it("node:crypto vérifie la signature ES256 produite par signTestProof", () => {
    const signers = makeTestSigners();
    const proof = signTestProof(unsigned, signers);
    const esJwk = signers.es256.publicJwk();
    const sig = b64urlToBytes(proof.sig.es256.value);
    expect(sig).not.toBeNull();
    expect(
      nodeVerify(
        "sha256",
        Buffer.from(payload),
        {
          key: createPublicKey({
            key: { kty: "EC", crv: "P-256", x: esJwk.x, y: esJwk.y },
            format: "jwk",
          }),
          dsaEncoding: "ieee-p1363",
        },
        Buffer.from(sig as Uint8Array),
      ),
    ).toBe(true);
  });
});
