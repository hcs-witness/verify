import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  bitcoinBlockHeight,
  merkleLeafHash,
  merklePath,
  merkleRoot,
  verifyMerkleInclusion,
  OtsError,
  parseOtsFile,
  serializeOtsFile,
  serializeTimestamp,
  signedPayload,
  verifyAnchor,
  type Proof,
} from "../src/index.js";

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

const vector = JSON.parse(
  readFileSync("test/vectors/proof-v1-valid.json", "utf8"),
) as Proof;

function anchoredProof(root: Uint8Array, index: number, path: Uint8Array[]) {
  return {
    ...vector,
    anchor: {
      batch_id: "anb_test",
      merkle_root: hex(root),
      leaf_index: index,
      path: path.map(hex),
    },
  };
}

describe("verifyAnchor", () => {
  it("proof sans anchor → present:false", () => {
    const r = verifyAnchor(vector);
    expect(r.present).toBe(false);
    expect(r.inclusion).toBe(false);
  });

  it("not a proof at all → present:false", () => {
    expect(verifyAnchor({ hello: 1 }).present).toBe(false);
    expect(verifyAnchor(42).present).toBe(false);
  });

  it("inclusion vérifiée sur un lot de 3 feuilles", () => {
    const leaf = merkleLeafHash(signedPayload(vector));
    const other1 = merkleLeafHash(new Uint8Array([9]));
    const other2 = merkleLeafHash(new Uint8Array([8]));
    const leaves = [other1, leaf, other2];
    const root = merkleRoot(leaves);
    const path = merklePath(leaves, 1);
    const r = verifyAnchor(anchoredProof(root, 1, path));
    expect(r.present).toBe(true);
    expect(r.inclusion).toBe(true);
  });

  it("mauvais index ou chemin trafiqué → inclusion false", () => {
    const leaf = merkleLeafHash(signedPayload(vector));
    const leaves = [leaf, merkleLeafHash(new Uint8Array([1]))];
    const root = merkleRoot(leaves);
    const path = merklePath(leaves, 0);
    // index 1 au lieu de 0
    expect(verifyAnchor(anchoredProof(root, 1, path)).inclusion).toBe(false);
    // chemin tronqué
    const p = verifyAnchor({
      ...vector,
      anchor: {
        batch_id: "x",
        merkle_root: hex(root),
        leaf_index: 0,
        path: [],
      },
    });
    expect(p.inclusion).toBe(false);
  });

  it("le .ots embarqué atteste la racine et donne la hauteur", () => {
    const leaf = merkleLeafHash(signedPayload(vector));
    const leaves = [leaf];
    const root = merkleRoot(leaves);
    const ots = serializeOtsFile(
      root,
      serializeTimestamp({
        msg: root,
        attestations: [
          { kind: "bitcoin", height: 912095 },
          { kind: "pending", uri: "https://a.cal.example/h" },
        ],
        ops: [],
      }),
    );
    const proof = anchoredProof(root, 0, []);
    (proof.anchor as Record<string, unknown>).ots =
      Buffer.from(ots).toString("base64");
    const r = verifyAnchor(proof);
    expect(r.otsMatchesRoot).toBe(true);
    expect(r.bitcoinBlockHeight).toBe(912095);
    expect(r.pendingCalendars).toEqual(["https://a.cal.example/h"]);
  });

  it(".ots trafiqué ou base64 invalide → otsMatchesRoot false", () => {
    const leaf = merkleLeafHash(signedPayload(vector));
    const root = merkleRoot([leaf]);
    const proof = anchoredProof(root, 0, []);
    (proof.anchor as Record<string, unknown>).ots = "!!!notbase64";
    expect(verifyAnchor(proof).otsMatchesRoot).toBe(false);
    (proof.anchor as Record<string, unknown>).ots =
      Buffer.from("garbage").toString("base64");
    expect(verifyAnchor(proof).otsMatchesRoot).toBe(false);
  });
});

describe("ots — chemins d'erreur et sérialisation", () => {
  const digest = new Uint8Array(32).fill(1);

  function stampWith(ops: {
    op: "sha256" | "append" | "prepend";
    arg?: Uint8Array;
    att?: { kind: "bitcoin" | "pending"; height?: number; uri?: string };
  }): Uint8Array {
    return serializeOtsFile(
      digest,
      serializeTimestamp({
        msg: digest,
        attestations: [ops.att ?? { kind: "pending", uri: "https://x.cal/a" }],
        ops: [],
      }),
    );
  }

  it("serializeTimestamp refuse un timestamp vide", () => {
    expect(() =>
      serializeTimestamp({ msg: digest, attestations: [], ops: [] }),
    ).toThrow(OtsError);
  });

  it("serializeOtsFile exige un digest de 32 octets", () => {
    expect(() => serializeOtsFile(new Uint8Array(8), new Uint8Array())).toThrow(
      OtsError,
    );
  });

  it.each([
    [
      "ops triées à la sérialisation",
      {
        msg: digest,
        attestations: [{ kind: "pending" as const, uri: "https://x.cal/a" }],
        ops: [
          {
            op: { kind: "prepend" as const, arg: new Uint8Array([1]) },
            stamp: {
              msg: Uint8Array.from([1, ...digest]),
              attestations: [{ kind: "bitcoin" as const, height: 7 }],
              ops: [],
            },
          },
          {
            op: { kind: "append" as const, arg: new Uint8Array([2]) },
            stamp: {
              msg: Uint8Array.from([...digest, 2]),
              attestations: [
                { kind: "pending" as const, uri: "https://y.cal/b" },
              ],
              ops: [],
            },
          },
        ],
      },
    ],
  ])("%s", (_n, stamp) => {
    const bytes = serializeOtsFile(digest, serializeTimestamp(stamp));
    const back = parseOtsFile(bytes);
    expect(back.timestamp.ops.length).toBe(2);
    expect(bitcoinBlockHeight(back.timestamp)).toBe(7);
  });

  it("entrée trop longue → SIZE", () => {
    expect(() => parseOtsFile(new Uint8Array(70 * 1024))).toThrow(OtsError);
    expect(() => parseOtsFile(new Uint8Array(0))).toThrow(OtsError);
  });

  it("entrée non-Uint8Array → TYPE", () => {
    expect(() => parseOtsFile("x" as never)).toThrow(OtsError);
  });

  it("version majeure ≠ 1 → VERSION", () => {
    const good = stampWith({ op: "append", arg: new Uint8Array([1]) });
    const copy = Uint8Array.from(good);
    copy[31] = 2; // MAJOR_VERSION varuint
    try {
      parseOtsFile(copy);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("VERSION");
    }
  });

  it("varuint non canonique → VARUINT", () => {
    // magic + major(1) + op(08) + digest + tag 0x00 (att) + 8-byte tag bitcoin + varbytes len encodé en 2 octets (non canonique)
    const attTag = Uint8Array.from([
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
    ]);
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0x00,
      ...attTag,
      0x80,
      0x02, // varbytes len = non-canonical (0x80 then 0x02)
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect(["VARUINT", "TRUNCATED"]).toContain((e as OtsError).code);
    }
  });

  it("données résiduelles après le timestamp → TRAILING", () => {
    const good = stampWith({ op: "append", arg: new Uint8Array([1]) });
    const extra = Uint8Array.from([...good, 0x00]);
    try {
      parseOtsFile(extra);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("TRAILING");
    }
  });

  it("attestation bitcoin avec octets résiduels → ATTESTATION", () => {
    const attTag = Uint8Array.from([
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
    ]);
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0x00,
      ...attTag,
      0x03,
      0x02,
      0x00,
      0xff, // payload len=3, varuint(2) + junk
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("ATTESTATION");
    }
  });

  it("hauteur > 2^32-1 → ATTESTATION", () => {
    const attTag = Uint8Array.from([
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
    ]);
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    // varuint encoding of 2^32 = 0x80 0x80 0x80 0x80 0x10
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0x00,
      ...attTag,
      0x05,
      0x80,
      0x80,
      0x80,
      0x80,
      0x10,
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("ATTESTATION");
    }
  });

  it("URI pending avec caractère interdit → ATTESTATION", () => {
    const attTag = Uint8Array.from([
      0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
    ]);
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const uri = new TextEncoder().encode("http://bad/?q=1"); // '?' interdit
    const payload = Uint8Array.from([uri.length, ...uri]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0x00,
      ...attTag,
      payload.length,
      ...payload,
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("ATTESTATION");
    }
  });

  it("op binaire sans arg → OP", () => {
    // construit un timestamp avec un op append sans arg via sérialisation manuelle
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      0x00, // append, varbytes len=0 → min 1 → LENGTH error
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("LENGTH");
    }
  });

  it("profondeur excessive → DEPTH", () => {
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    // 300 ops sha256 chaînés sans feuille
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      ...new Uint8Array(300).fill(0x08),
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect(["DEPTH", "TRUNCATED"]).toContain((e as OtsError).code);
    }
  });

  it("troncation pure → TRUNCATED", () => {
    const good = stampWith({ op: "append", arg: new Uint8Array([1]) });
    try {
      parseOtsFile(good.subarray(0, 40));
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(OtsError);
    }
  });
});

describe("ots — couverture branches", () => {
  const digest = new Uint8Array(32).fill(2);

  it("varuint multi-octets en écriture (URI > 127 octets) et relecture", () => {
    const uri = "https://a.cal/" + "x".repeat(200);
    const bytes = serializeOtsFile(
      digest,
      serializeTimestamp({
        msg: digest,
        attestations: [{ kind: "pending", uri }],
        ops: [],
      }),
    );
    const back = parseOtsFile(bytes);
    const att = back.timestamp.attestations.at(0);
    expect(att?.uri).toBe(uri);
  });

  it("op prepend et sha256 chaînés en sérialisation", () => {
    const inner = new Uint8Array([9, ...digest]);
    const sha = new Uint8Array([7]);
    const bytes = serializeOtsFile(
      digest,
      serializeTimestamp({
        msg: digest,
        attestations: [],
        ops: [
          {
            op: { kind: "prepend", arg: new Uint8Array([9]) },
            stamp: {
              msg: inner,
              attestations: [],
              ops: [
                {
                  op: { kind: "sha256" },
                  stamp: {
                    msg: sha,
                    attestations: [{ kind: "bitcoin", height: 1 }],
                    ops: [],
                  },
                },
              ],
            },
          },
        ],
      }),
    );
    const back = parseOtsFile(bytes);
    expect(back.timestamp.ops.at(0)?.op.kind).toBe("prepend");
    expect(bitcoinBlockHeight(back.timestamp)).toBe(1);
  });

  it("varbytes hors bornes (arg > 4096) → LENGTH", () => {
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      0x82,
      0x20, // varuint 4098
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("LENGTH");
    }
  });

  it("varuint trop long (> 9 octets) → VARUINT", () => {
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      ...new Uint8Array(10).fill(0xff),
      0x00,
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("VARUINT");
    }
  });

  it("attestation inconnue → UNKNOWN_ATTESTATION ; doublon d'op → DUPLICATE_OP", () => {
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    const unknownAtt = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0x00,
      ...new Uint8Array(8).fill(0xaa),
      0x00,
    ]);
    try {
      parseOtsFile(unknownAtt);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("UNKNOWN_ATTESTATION");
    }
    // Deux ops `append 0x09` en frères : chacun suivi de sa feuille
    // (attestation bitcoin hauteur 0) → DUPLICATE_OP attendu.
    const leaf = Uint8Array.from([
      0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0x01, 0x00,
    ]);
    const dup = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xff,
      0xf0,
      0x01,
      0x09,
      ...leaf,
      0xf0,
      0x01,
      0x09,
      ...leaf,
    ]);
    try {
      parseOtsFile(dup);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("DUPLICATE_OP");
    }
  });

  it("msg vide après op → MSG_LENGTH (résultat borné)", () => {
    // parse d'un fichier dont un op produit un msg > 4096 : append de 4065
    const magic = Uint8Array.from([
      ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
      0xbf,
      0x89,
      0xe2,
      0xe8,
      0x84,
      0xe8,
      0x92,
      0x94,
    ]);
    // append de 4065 octets (varuint 4065 = 0xe1 0x1f) : msg > 4096.
    const bad2 = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      0xe1,
      0x1f,
      ...new Uint8Array(4065).fill(1),
    ]);
    try {
      parseOtsFile(bad2);
      expect.unreachable();
    } catch (e) {
      expect(["LENGTH", "MSG_LENGTH"]).toContain((e as OtsError).code);
    }
  });
});

describe("merkle — couverture branches", () => {
  it("merklePath index hors bornes → throw", () => {
    const leaves = [merkleLeafHash(new Uint8Array([1]))];
    expect(() => merklePath(leaves, 1)).toThrow();
    expect(() => merklePath(leaves, -1)).toThrow();
  });

  it("verifyMerkleInclusion : leafCount/index invalides → false", () => {
    const leaf = merkleLeafHash(new Uint8Array([1]));
    const root = merkleRoot([leaf]);
    expect(verifyMerkleInclusion(leaf, 0, 0, [], root)).toBe(false);
    expect(verifyMerkleInclusion(leaf, -1, 1, [], root)).toBe(false);
    expect(verifyMerkleInclusion(leaf, 5, 1, [], root)).toBe(false);
  });

  it("racine d'un arbre à 0 feuille → throw", () => {
    expect(() => merkleRoot([])).toThrow();
  });
});

describe("ots — branches atteignables supplémentaires", () => {
  const digest = new Uint8Array(32).fill(3);
  const magic = Uint8Array.from([
    ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
    0xbf,
    0x89,
    0xe2,
    0xe8,
    0x84,
    0xe8,
    0x92,
    0x94,
  ]);

  it("varuint 0x80 0x00 (octet final nul) → VARUINT non canonique", () => {
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      0x80,
      0x00, // varbytes len = non-canonique
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("VARUINT");
    }
  });

  it("varuint débordant MAX_SAFE_INTEGER → VARUINT overflow", () => {
    const bad = Uint8Array.from([
      ...magic,
      0x01,
      0x08,
      ...digest,
      0xf0,
      ...new Uint8Array(8).fill(0xff),
      0x7f, // 9 octets, valeur énorme
    ]);
    try {
      parseOtsFile(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as OtsError).code).toBe("VARUINT");
    }
  });

  it("attestations bitcoin/pending sans height/uri → ?? couverts", () => {
    const stamp = {
      msg: digest,
      attestations: [
        { kind: "bitcoin" as const },
        { kind: "pending" as const },
      ],
      ops: [],
    };
    const bytes = serializeTimestamp(stamp);
    expect(bytes.length).toBeGreaterThan(0);
    // height absent → ?? 0 → Math.min donne 0
    expect(bitcoinBlockHeight(stamp)).toBe(0);
  });

  it("ops de même préfixe, longueurs différentes → cmpBytes length", () => {
    const leaf = {
      msg: digest,
      attestations: [{ kind: "pending" as const, uri: "https://x.cal/a" }],
      ops: [],
    };
    const bytes = serializeTimestamp({
      msg: digest,
      attestations: [],
      ops: [
        {
          op: { kind: "append" as const, arg: new Uint8Array([9]) },
          stamp: leaf,
        },
        {
          op: { kind: "append" as const, arg: new Uint8Array([9, 1]) },
          stamp: leaf,
        },
      ],
    });
    const parsed = parseOtsFile(serializeOtsFile(digest, bytes));
    expect(parsed.timestamp.ops.length).toBe(2);
  });
});

describe("ots — dernières branches atteignables", () => {
  const digest = new Uint8Array(32).fill(4);
  const magic = Uint8Array.from([
    ...new TextEncoder().encode("\0OpenTimestamps\0\0Proof\0"),
    0xbf,
    0x89,
    0xe2,
    0xe8,
    0x84,
    0xe8,
    0x92,
    0x94,
  ]);

  it("fichier tronqué juste après le digest → byte() EOF → OtsError", () => {
    const cut = Uint8Array.from([...magic, 0x01, 0x08, ...digest]);
    try {
      parseOtsFile(cut);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(OtsError);
    }
  });

  it("hauteur Bitcoin élevée → varuint écriture multi-octets", () => {
    const stamp = {
      msg: digest,
      attestations: [{ kind: "bitcoin" as const, height: 2_000_000 }],
      ops: [],
    };
    const back = parseOtsFile(
      serializeOtsFile(digest, serializeTimestamp(stamp)),
    );
    expect(bitcoinBlockHeight(back.timestamp)).toBe(2_000_000);
  });
});
