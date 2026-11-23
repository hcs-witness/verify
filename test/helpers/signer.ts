/**
 * Signataire de test : produit de vraies signatures ES256 / ML-DSA-65
 * pour les fixtures de test. Miroir du chemin de signature de la
 * plateforme (signDigest sur SHA-256(payload), low-S, contexte FIPS 204).
 * Vit sous test/ uniquement — jamais dans le paquet publié.
 */
import {
  createECDH,
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  bytesToB64url,
  canonicalBytes,
  ML_DSA_CONTEXT,
  signedPayload,
  type Proof,
  type UnsignedProof,
} from "../../src/index.js";

const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function sha256(data: Uint8Array): Uint8Array {
  return createHash("sha256").update(data).digest();
}

/** Empreinte RFC 7638 de la JWK publique (crv, kty, x, y en JCS). */
export function es256Kid(x: string, y: string): string {
  const thumbprint = canonicalBytes({ crv: "P-256", kty: "EC", x, y });
  return bytesToB64url(sha256(thumbprint));
}

export function mlDsaKid(publicKey: Uint8Array): string {
  return bytesToB64url(sha256(publicKey));
}

export interface TestEs256Signer {
  readonly alg: "ES256";
  readonly kid: string;
  publicJwk(): {
    kty: "EC";
    crv: "P-256";
    x: string;
    y: string;
    alg: "ES256";
    use: "sig";
    kid: string;
  };
  /** Signe le message : ECDSA sur SHA-256(message), r‖s P1363 low-S. */
  sign(message: Uint8Array): Uint8Array;
}

export interface TestMlDsaSigner {
  readonly alg: "ML-DSA-65";
  readonly kid: string;
  publicJwk(): {
    kty: "AKP";
    alg: "ML-DSA-65";
    pub: string;
    use: "sig";
    kid: string;
  };
  sign(message: Uint8Array): Uint8Array;
}

export interface TestSigners {
  readonly es256: TestEs256Signer;
  readonly mldsa65: TestMlDsaSigner;
  /** Keyset complet correspondant aux deux signataires. */
  keyset(notBefore?: string): {
    keys: Record<string, unknown>[];
  };
}

/** Normalise s := n − s si s > n/2 (node:crypto n'impose pas low-S). */
function lowS(sig: Uint8Array): Uint8Array {
  const s = BigInt(`0x${Buffer.from(sig.subarray(32)).toString("hex")}`);
  if (s <= P256_ORDER / 2n) return sig;
  const s2 = P256_ORDER - s;
  return Uint8Array.from(
    Buffer.concat([
      Buffer.from(sig.subarray(0, 32)),
      Buffer.from(s2.toString(16).padStart(64, "0"), "hex"),
    ]),
  );
}

export function makeTestSigners(): TestSigners {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const esKid = es256Kid(jwk.x, jwk.y);
  const esKey: KeyObject = privateKey;

  const mlKeys = ml_dsa65.keygen(
    createHash("sha256").update("mldsa-test-seed").digest(),
  );
  const mlKid = mlDsaKid(mlKeys.publicKey);

  const es256: TestEs256Signer = {
    alg: "ES256",
    kid: esKid,
    publicJwk: () => ({
      kty: "EC",
      crv: "P-256",
      x: jwk.x,
      y: jwk.y,
      alg: "ES256",
      use: "sig",
      kid: esKid,
    }),
    sign: (message: Uint8Array) =>
      // Equivalent du signDigest(sha256(payload)) de la plateforme :
      // ECDSA sur SHA-256(message), encodage brut r‖s.
      lowS(
        new Uint8Array(
          nodeSign("sha256", Buffer.from(message), {
            key: esKey,
            dsaEncoding: "ieee-p1363",
          }),
        ),
      ),
  };

  const mldsa65: TestMlDsaSigner = {
    alg: "ML-DSA-65",
    kid: mlKid,
    publicJwk: () => ({
      kty: "AKP",
      alg: "ML-DSA-65",
      pub: bytesToB64url(mlKeys.publicKey),
      use: "sig",
      kid: mlKid,
    }),
    sign: (message: Uint8Array) =>
      ml_dsa65.sign(message, mlKeys.secretKey, { context: ML_DSA_CONTEXT }),
  };

  return {
    es256,
    mldsa65,
    keyset: (notBefore = "2020-01-01T00:00:00Z") => ({
      keys: [
        { ...es256.publicJwk(), status: "active", not_before: notBefore },
        { ...mldsa65.publicJwk(), status: "active", not_before: notBefore },
      ],
    }),
  };
}

/** Miroir de signProof : ES256 sur SHA-256(payload), ML-DSA sur payload. */
export function signTestProof(
  unsigned: UnsignedProof,
  signers: TestSigners,
): Proof {
  const payload = signedPayload(unsigned);
  const es = signers.es256.sign(payload);
  const ml = signers.mldsa65.sign(payload);
  const proof = {
    ...unsigned,
    sig: {
      es256: { kid: signers.es256.kid, value: bytesToB64url(es) },
      mldsa65: { kid: signers.mldsa65.kid, value: bytesToB64url(ml) },
    },
  };
  return proof;
}

/**
 * Signataires de test DETERMINISTES dérivés d'un seed — utilisés pour
 * produire des vecteurs fixes régénérables (la graine vit dans les
 * tests, jamais en production).
 * ES256 : scalaire privé = sha256(seed ‖ "|es256"), importé en JWK P-256.
 * ML-DSA-65 : ml_dsa65.keygen(sha256(seed ‖ "|mldsa65")).
 */
export function makeSeededTestSigners(seed: Uint8Array): TestSigners {
  const derive = (label: string): Uint8Array =>
    createHash("sha256")
      .update(seed)
      .update(new TextEncoder().encode(`|${label}`))
      .digest();

  const esDBytes = derive("es256");
  // x,y dérivés via ECDH (node:crypto exige x,y,d dans le JWK privé).
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(esDBytes));
  const pub = ecdh.getPublicKey(null, "uncompressed");
  const esJwk = {
    x: pub.subarray(1, 33).toString("base64url"),
    y: pub.subarray(33, 65).toString("base64url"),
  };
  const esPrivate = createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: esJwk.x,
      y: esJwk.y,
      d: Buffer.from(esDBytes).toString("base64url"),
    },
    format: "jwk",
  });
  const esKid = es256Kid(esJwk.x, esJwk.y);

  const mlKeys = ml_dsa65.keygen(derive("mldsa65"));
  const mlKid = mlDsaKid(mlKeys.publicKey);

  const es256: TestEs256Signer = {
    alg: "ES256",
    kid: esKid,
    publicJwk: () => ({
      kty: "EC",
      crv: "P-256",
      x: esJwk.x,
      y: esJwk.y,
      alg: "ES256",
      use: "sig",
      kid: esKid,
    }),
    sign: (message: Uint8Array) =>
      lowS(
        new Uint8Array(
          nodeSign("sha256", Buffer.from(message), {
            key: esPrivate,
            dsaEncoding: "ieee-p1363",
          }),
        ),
      ),
  };

  const mldsa65: TestMlDsaSigner = {
    alg: "ML-DSA-65",
    kid: mlKid,
    publicJwk: () => ({
      kty: "AKP",
      alg: "ML-DSA-65",
      pub: bytesToB64url(mlKeys.publicKey),
      use: "sig",
      kid: mlKid,
    }),
    sign: (message: Uint8Array) =>
      ml_dsa65.sign(message, mlKeys.secretKey, { context: ML_DSA_CONTEXT }),
  };

  return {
    es256,
    mldsa65,
    keyset: (notBefore = "2020-01-01T00:00:00Z") => ({
      keys: [
        { ...es256.publicJwk(), status: "active", not_before: notBefore },
        { ...mldsa65.publicJwk(), status: "active", not_before: notBefore },
      ],
    }),
  };
}
