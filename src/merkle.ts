import { sha256 } from "./hash.js";

/**
 * Arbre de Merkle de type RFC 6962 (Certificate Transparency) avec
 * séparation de domaine :
 *   feuille = SHA-256(0x00 ‖ SHA-256(signedPayload))
 *   nœud    = SHA-256(0x01 ‖ gauche ‖ droite)
 * Nombre impair de feuilles : la dernière est promue (règle DTR, le
 * plus grand k = 2^m < n), jamais dupliquée.
 */

export function merkleLeafHash(signedPayload: Uint8Array): Uint8Array {
  return sha256(Uint8Array.from([0x00, ...sha256(signedPayload)]));
}

export function merkleNodeHash(
  left: Uint8Array,
  right: Uint8Array,
): Uint8Array {
  return sha256(Uint8Array.from([0x01, ...left, ...right]));
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b.at(i));
}

/** Plus grande puissance de 2 strictement inférieure à n (n > 1). */
function splitK(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/** Hash d'un sous-arbre DTR sur des feuilles déjà hachées. */
function subtreeHash(leaves: readonly Uint8Array[]): Uint8Array {
  const n = leaves.length;
  if (n === 0) {
    throw new Error("empty subtree");
  }
  if (n === 1) {
    const leaf = leaves[0];
    if (leaf === undefined) {
      throw new Error("missing leaf");
    }
    return leaf;
  }
  const k = splitK(n);
  return merkleNodeHash(
    subtreeHash(leaves.slice(0, k)),
    subtreeHash(leaves.slice(k)),
  );
}

/** Racine Merkle d'une liste de feuilles déjà hachées (merkleLeafHash). */
export function merkleRoot(leaves: readonly Uint8Array[]): Uint8Array {
  return subtreeHash(leaves);
}

/**
 * Chemin d'inclusion (audit path) de la feuille `index`, dans l'ordre
 * de remontée vers la racine : PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
 * pour m < k (RFC 6962 §2.1.1).
 */
export function merklePath(
  leaves: readonly Uint8Array[],
  index: number,
): Uint8Array[] {
  const n = leaves.length;
  if (index < 0 || index >= n) {
    throw new Error("leaf index out of range");
  }
  const path: Uint8Array[] = [];
  const walk = (lo: number, count: number, idx: number): void => {
    if (count === 1) {
      return;
    }
    const k = splitK(count);
    if (idx < k) {
      walk(lo, k, idx);
      path.push(subtreeHash(leaves.slice(lo + k, lo + count)));
    } else {
      walk(lo + k, count - k, idx - k);
      path.push(subtreeHash(leaves.slice(lo, lo + k)));
    }
  };
  walk(0, n, index);
  return path;
}

/**
 * Vérification hors ligne : la feuille `leaf` (déjà hachée par
 * merkleLeafHash) remonte-t-elle à `root` via `path` ? Miroir exact de
 * merklePath : chaque entrée du chemin est consommée une fois, dans
 * l'ordre.
 */
export function verifyMerkleInclusion(
  leaf: Uint8Array,
  index: number,
  leafCount: number,
  path: readonly Uint8Array[],
  root: Uint8Array,
): boolean {
  if (leafCount < 1 || index < 0 || index >= leafCount) {
    return false;
  }
  let consumed = 0;
  const walk = (count: number, idx: number): Uint8Array => {
    if (count === 1) {
      return leaf;
    }
    const k = splitK(count);
    // Miroir de merklePath : le sous-arbre porteur d'abord (il consomme
    // les entrées profondes), puis le sibling de CE niveau.
    let current: Uint8Array;
    let sibling: Uint8Array | undefined;
    if (idx < k) {
      current = walk(k, idx);
      sibling = path.at(consumed);
      if (sibling === undefined) {
        throw new Error("path too short");
      }
      consumed += 1;
      return merkleNodeHash(current, sibling);
    }
    current = walk(count - k, idx - k);
    sibling = path.at(consumed);
    if (sibling === undefined) {
      throw new Error("path too short");
    }
    consumed += 1;
    return merkleNodeHash(sibling, current);
  };
  let computed: Uint8Array;
  try {
    computed = walk(leafCount, index);
  } catch {
    return false;
  }
  return consumed === path.length && bytesEq(computed, root);
}
