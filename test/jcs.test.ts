import fc from "fast-check";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { canonicalBytes, NonJsonValueError } from "../src/index.js";

interface JcsCase {
  readonly name: string;
  readonly input: unknown;
  readonly expected: string;
}

const vectors = JSON.parse(
  readFileSync("test/vectors/jcs-rfc8785.json", "utf8"),
) as { cases: JcsCase[] };

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

describe("canonicalBytes", () => {
  it.each(vectors.cases)(
    "matches RFC 8785 vector $name",
    ({ input, expected }) => {
      expect(decode(canonicalBytes(input))).toBe(expected);
    },
  );

  it.each([
    ["undefined", undefined],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["bigint", 1n],
    ["function", () => 1],
    ["symbol", Symbol("s")],
    ["class instance", new Date(0)],
    ["Map", new Map()],
  ])("rejects %s explicitly", (_name, value) => {
    expect(() => canonicalBytes(value)).toThrow(NonJsonValueError);
  });

  it("rejects non-JSON values nested in objects and arrays", () => {
    expect(() => canonicalBytes({ a: { b: [undefined] } })).toThrow(
      NonJsonValueError,
    );
    expect(() => canonicalBytes({ ok: 1, bad: { fn: () => 0 } })).toThrow(
      NonJsonValueError,
    );
  });

  it("rejects cyclic structures", () => {
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    expect(() => canonicalBytes(cyclic)).toThrow(NonJsonValueError);
  });

  it("is deterministic under JSON round-trip (property)", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const roundTripped: unknown = JSON.parse(JSON.stringify(value));
        expect(canonicalBytes(roundTripped)).toEqual(canonicalBytes(value));
      }),
      { numRuns: 200 },
    );
  });

  it("produces identical output for different key insertion orders (property)", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.tuple(fc.string(), fc.jsonValue()), {
          minLength: 1,
          maxLength: 20,
          selector: (entry) => entry[0],
        }),
        (entries) => {
          const forward = Object.fromEntries(entries);
          const backward = Object.fromEntries([...entries].reverse());
          expect(canonicalBytes(backward)).toEqual(canonicalBytes(forward));
        },
      ),
      { numRuns: 100 },
    );
  });
});
