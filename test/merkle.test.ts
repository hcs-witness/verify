import { createHash, randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  merkleLeafHash,
  merkleNodeHash,
  merklePath,
  merkleRoot,
  verifyMerkleInclusion,
} from "../src/index.js";

function leaf(i: number): Uint8Array {
  return merkleLeafHash(new Uint8Array([i]));
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

describe("merkle — RFC 6962 domain separation", () => {
  it("leaf = SHA-256(0x00‖SHA-256(payload)) and node = SHA-256(0x01‖l‖r)", () => {
    const payload = new Uint8Array([1, 2, 3]);
    const inner = createHash("sha256").update(payload).digest();
    const expectedLeaf = createHash("sha256")
      .update(Uint8Array.from([0x00, ...inner]))
      .digest("hex");
    expect(hex(merkleLeafHash(payload))).toBe(expectedLeaf);
    const a = leaf(0);
    const b = leaf(1);
    const expectedNode = createHash("sha256")
      .update(Uint8Array.from([0x01, ...a, ...b]))
      .digest("hex");
    expect(hex(merkleNodeHash(a, b))).toBe(expectedNode);
  });

  // Timeout justifié par mesure : merklePath recalcule les hachages de
  // sous-arbres à chaque appel (~O(n) par feuille, donc O(n²) ici) ;
  // le cas 1000 feuilles met ~2,6 s sans couverture et ~27,6 s sous
  // instrumentation v8 isolé (>30 s mesurés en charge parallèle :
  // 30,4 s et 32,5 s). 120 s = ~4x le pire cas observé.
  it.each([1, 2, 3, 7, 1000])(
    "round-trips inclusion for every leaf of a %i-leaf tree",
    { timeout: 120_000 },
    (n) => {
      const leaves = Array.from({ length: n }, (_, i) => leaf(i % 256));
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i += 1) {
        const path = merklePath(leaves, i);
        expect(
          verifyMerkleInclusion(
            leaves.at(i) ?? new Uint8Array(),
            i,
            n,
            path,
            root,
          ),
          `leaf ${String(i)}/${String(n)}`,
        ).toBe(true);
      }
    },
  );

  it("never duplicates an odd last leaf", () => {
    // 3 feuilles : root = node(node(d0,d1), d2) — pas node(node(d0,d1), node(d2,d2)).
    const leaves = [leaf(0), leaf(1), leaf(2)];
    const root = merkleRoot(leaves);
    const d2d2 = merkleNodeHash(
      leaves.at(2) ?? new Uint8Array(),
      leaves.at(2) ?? new Uint8Array(),
    );
    const wrong = merkleNodeHash(
      merkleNodeHash(
        leaves.at(0) ?? new Uint8Array(),
        leaves[1] ?? new Uint8Array(),
      ),
      d2d2,
    );
    expect(hex(root)).not.toBe(hex(wrong));
    const promoted = merkleNodeHash(
      merkleNodeHash(
        leaves.at(0) ?? new Uint8Array(),
        leaves[1] ?? new Uint8Array(),
      ),
      leaves.at(2) ?? new Uint8Array(),
    );
    expect(hex(root)).toBe(hex(promoted));
  });

  it("audit paths match the RFC 6962 §2.1.3 example structure", () => {
    // 7 feuilles : d0 → [b, h, l], d3 → [c, g, l], d4 → [f, j, k], d6 → [i, k].
    const leaves = Array.from({ length: 7 }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    for (let i = 0; i < 7; i += 1) {
      const path = merklePath(leaves, i);
      const expectedLen = [3, 3, 3, 3, 3, 3, 2].at(i);
      expect(path.length).toBe(expectedLen);
      expect(
        verifyMerkleInclusion(
          leaves.at(i) ?? new Uint8Array(),
          i,
          7,
          path,
          root,
        ),
      ).toBe(true);
    }
  });

  it("a modified leaf fails inclusion", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    const tampered = Uint8Array.from(randomBytes(32));
    for (let i = 0; i < 7; i += 1) {
      const path = merklePath(leaves, i);
      expect(verifyMerkleInclusion(tampered, i, 7, path, root)).toBe(false);
    }
  });

  it("a truncated or extended path fails", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    const path = merklePath(leaves, 4);
    expect(
      verifyMerkleInclusion(
        leaves[4] ?? new Uint8Array(),
        4,
        7,
        path.slice(0, -1),
        root,
      ),
    ).toBe(false);
    expect(
      verifyMerkleInclusion(
        leaves[4] ?? new Uint8Array(),
        4,
        7,
        [...path, leaf(9)],
        root,
      ),
    ).toBe(false);
  });

  it("single leaf: empty path, root = leaf", () => {
    const leaves = [leaf(42)];
    expect(hex(merkleRoot(leaves))).toBe(hex(leaves.at(0) ?? new Uint8Array()));
    expect(merklePath(leaves, 0)).toEqual([]);
    expect(
      verifyMerkleInclusion(
        leaves.at(0) ?? new Uint8Array(),
        0,
        1,
        [],
        merkleRoot(leaves),
      ),
    ).toBe(true);
  });
});
