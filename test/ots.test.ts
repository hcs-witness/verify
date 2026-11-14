import { readFileSync } from "node:fs";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  allAttestations,
  bitcoinBlockHeight,
  OtsError,
  parseOtsFile,
  serializeOtsFile,
  serializeTimestamp,
} from "../src/index.js";

/**
 * Vecteurs officiels : github.com/opentimestamps/opentimestamps-client,
 * commit f3a9e92e4dcb89ed93396d71ec808b3290a438c4, dossier examples/.
 * (python-opentimestamps ne contient aucun fichier .ots — vérifié.)
 */

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

describe("ots reader — official vectors", () => {
  it("merkle2.txt.ots : digest, ops et attestations pending", () => {
    const f = parseOtsFile(
      Uint8Array.from(readFileSync("test/vectors/ots/merkle2.txt.ots")),
    );
    expect(hex(f.fileDigest)).toBe(
      "8bd5a5f07b4451c29756df5eb51d194fb5b20c7e89812d877bbad30d871c582f",
    );
    const uris = allAttestations(f.timestamp).map((a) => a.attestation.uri);
    expect(uris).toContain("https://alice.btc.calendar.opentimestamps.org");
    expect(uris).toContain("https://bob.btc.calendar.opentimestamps.org");
    expect(bitcoinBlockHeight(f.timestamp)).toBeUndefined();
  });

  it("gdp2q25-2nd.pdf.ots : attestation Bitcoin au bloc 912095", () => {
    const f = parseOtsFile(
      Uint8Array.from(readFileSync("test/vectors/ots/gdp2q25-2nd.pdf.ots")),
    );
    expect(hex(f.fileDigest)).toBe(
      "c70972a12908b73c2407d9cc6842ba2a02203a690f3090cd29f30c45f0cfd93d",
    );
    expect(bitcoinBlockHeight(f.timestamp)).toBe(912095);
  });

  it("incomplete.txt.ots : pending alice, pas de Bitcoin", () => {
    const f = parseOtsFile(
      Uint8Array.from(readFileSync("test/vectors/ots/incomplete.txt.ots")),
    );
    expect(hex(f.fileDigest)).toBe(
      "05c4f616a8e5310d19d938cfd769864d7f4ccdc2ca8b479b10af83564b097af9",
    );
    expect(bitcoinBlockHeight(f.timestamp)).toBeUndefined();
  });

  it("two-calendars.txt.ots : deux attestations pending", () => {
    const f = parseOtsFile(
      Uint8Array.from(readFileSync("test/vectors/ots/two-calendars.txt.ots")),
    );
    const pending = allAttestations(f.timestamp).filter(
      (a) => a.attestation.kind === "pending",
    );
    expect(pending.length).toBeGreaterThanOrEqual(2);
  });

  it.each([
    [
      "hello-world.txt.ots",
      "UNKNOWN_OP",
      () =>
        Uint8Array.from(readFileSync("test/vectors/ots/hello-world.txt.ots")),
    ],
    [
      "different-blockchains.txt.ots",
      "UNKNOWN_OP",
      () =>
        Uint8Array.from(
          readFileSync("test/vectors/ots/different-blockchains.txt.ots"),
        ),
    ],
    [
      "known-and-unknown-notary.txt.ots",
      "UNKNOWN_ATTESTATION",
      () =>
        Uint8Array.from(
          readFileSync("test/vectors/ots/known-and-unknown-notary.txt.ots"),
        ),
    ],
    [
      "bitcoin.pdf.ots",
      "FILE_HASH_OP",
      () => Uint8Array.from(readFileSync("test/vectors/ots/bitcoin.pdf.ots")),
    ],
    [
      "bad-major-version.ots",
      "VERSION",
      () =>
        Uint8Array.from(readFileSync("test/vectors/ots/bad-major-version.ots")),
    ],
  ])("%s → erreur explicite %s", (_name, code, read) => {
    try {
      parseOtsFile(read());
      expect.unreachable(`expected ${code}`);
    } catch (e) {
      expect(e).toBeInstanceOf(OtsError);
      expect((e as OtsError).code).toBe(code);
    }
  });
});

describe("ots round-trip", () => {
  it("serialize → parse reproduit digest, attestations et hauteur", () => {
    const digest = new Uint8Array(32).fill(7);
    const stamp = {
      msg: digest,
      attestations: [
        {
          kind: "pending" as const,
          uri: "https://a.btc.calendar.opentimestamps.org",
        },
        { kind: "bitcoin" as const, height: 912095 },
      ],
      ops: [
        {
          op: { kind: "append" as const, arg: new Uint8Array([1, 2]) },
          stamp: {
            msg: Uint8Array.from([...digest, 1, 2]),
            attestations: [
              {
                kind: "pending" as const,
                uri: "https://b.btc.calendar.opentimestamps.org",
              },
            ],
            ops: [],
          },
        },
      ],
    };
    const bytes = serializeOtsFile(digest, serializeTimestamp(stamp));
    const back = parseOtsFile(bytes);
    expect(hex(back.fileDigest)).toBe(hex(digest));
    expect(bitcoinBlockHeight(back.timestamp)).toBe(912095);
    const uris = allAttestations(back.timestamp)
      .filter((a) => a.attestation.kind === "pending")
      .map((a) => a.attestation.uri);
    expect(uris.sort()).toEqual([
      "https://a.btc.calendar.opentimestamps.org",
      "https://b.btc.calendar.opentimestamps.org",
    ]);
  });
});

describe("ots fuzzing", () => {
  it("never throws an unhandled error on arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 256 }), (bytes) => {
        try {
          parseOtsFile(bytes);
        } catch (e) {
          expect(e).toBeInstanceOf(OtsError);
          return;
        }
      }),
      { numRuns: 500 },
    );
  });

  it("never throws an unhandled error on mutated valid files", () => {
    const base = Uint8Array.from(
      readFileSync("test/vectors/ots/merkle2.txt.ots"),
    );
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.nat({ max: base.length - 1 }),
        (byte, pos) => {
          const copy = Uint8Array.from(base);
          copy.set([byte], pos);
          try {
            parseOtsFile(copy);
          } catch (e) {
            expect(e).toBeInstanceOf(OtsError);
            return;
          }
        },
      ),
      { numRuns: 300 },
    );
  });
});
