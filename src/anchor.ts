import { merkleLeafHash, verifyMerkleInclusion } from "./merkle.js";
import { allAttestations, bitcoinBlockHeight, parseOtsFile } from "./ots.js";
import { isProof, signedPayload, type Proof } from "./schema.js";

export interface AnchorResult {
  /** La preuve porte un champ anchor bien formé. */
  readonly present: boolean;
  /** Inclusion Merkle feuille → racine vérifiée hors ligne. */
  readonly inclusion: boolean;
  /** Le fichier .ots atteste bien la racine Merkle. */
  readonly otsMatchesRoot: boolean | undefined;
  /** Hauteur de bloc attestée par l'attestation Bitcoin du .ots. */
  readonly bitcoinBlockHeight: number | undefined;
  /** URIs des calendriers en attestation « pending ». */
  readonly pendingCalendars: readonly string[];
}

function b64ToBytes(b64: string): Uint8Array | undefined {
  try {
    return Uint8Array.from(Buffer.from(b64, "base64"));
  } catch {
    return undefined;
  }
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b.at(i));
}

/**
 * Vérifie hors ligne l'ancrage d'une preuve : inclusion Merkle de la
 * feuille (SHA-256(0x00‖SHA-256(signedPayload))) vers merkle_root, puis
 * lecture du fichier .ots embarqué : sa racine attestée doit égaler
 * merkle_root ; la hauteur de bloc en est extraite. Aucun réseau.
 */
export function verifyAnchor(proof: unknown): AnchorResult {
  const empty: AnchorResult = {
    present: false,
    inclusion: false,
    otsMatchesRoot: undefined,
    bitcoinBlockHeight: undefined,
    pendingCalendars: [],
  };
  if (!isProof(proof)) {
    return empty;
  }
  const p: Proof = proof;
  const anchor = p.anchor;
  if (anchor === undefined) {
    return empty;
  }
  const root = hexToBytes(anchor.merkle_root);
  const leaf = merkleLeafHash(signedPayload(p));
  const path = anchor.path.map(hexToBytes);

  // leaf_count n'est pas dans la preuve : on le recherche. Un chemin de
  // longueur L ne peut couvrir qu'un lot dont la taille est dans
  // ]index, index + 2^L] ; la vérification n'aboutit que pour la vraie.
  let inclusion = false;
  const maxCount = anchor.leaf_index + 2 ** path.length;
  for (let count = anchor.leaf_index + 1; count <= maxCount; count += 1) {
    if (verifyMerkleInclusion(leaf, anchor.leaf_index, count, path, root)) {
      inclusion = true;
      break;
    }
  }

  let otsMatchesRoot: boolean | undefined;
  let height: number | undefined;
  const pending: string[] = [];
  if (anchor.ots !== undefined) {
    const bytes = b64ToBytes(anchor.ots);
    try {
      if (bytes === undefined) throw new Error("bad base64");
      const ots = parseOtsFile(bytes);
      otsMatchesRoot = bytesEq(ots.fileDigest, root);
      height = bitcoinBlockHeight(ots.timestamp);
      for (const { attestation } of allAttestations(ots.timestamp)) {
        if (attestation.kind === "pending" && attestation.uri !== undefined) {
          pending.push(attestation.uri);
        }
      }
    } catch {
      otsMatchesRoot = false;
    }
  }

  return {
    present: true,
    inclusion,
    otsMatchesRoot,
    bitcoinBlockHeight: height,
    pendingCalendars: pending,
  };
}
