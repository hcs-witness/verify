import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = "dist/cli.js";
const ENV = {
  NODE_ENV: "test",
  NODE_OPTIONS: "--require ./test/helpers/block-network.cjs",
};

function run(args: string[]): { code: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [CLI, ...args], {
      env: ENV,
      encoding: "utf8",
    });
    return { code: 0, out };
  } catch (error) {
    const e = error as { status?: number; stdout?: string };
    return { code: e.status ?? -1, out: e.stdout ?? "" };
  }
}

describe("hcs-witness-verify CLI (network blocked)", () => {
  it("exit 0 on the valid proof", () => {
    const r = run([
      "test/vectors/proof-v1-valid.json",
      "--keys",
      "test/vectors/keys-test.json",
    ]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("VALID");
  });

  it("exit 1 on a tampered proof", () => {
    const dir = mkdtempSync(join(tmpdir(), "ggv-"));
    const tampered = join(dir, "tampered.json");
    const proof = JSON.parse(
      execFileSync("cat", ["test/vectors/proof-v1-valid.json"], {
        encoding: "utf8",
      }),
    ) as { decision: string };
    proof.decision = "denied";
    writeFileSync(tampered, JSON.stringify(proof));
    const r = run([tampered, "--keys", "test/vectors/keys-test.json"]);
    expect(r.code).toBe(1);
  });

  it("exit 2 on a missing file", () => {
    const r = run([
      "does-not-exist.json",
      "--keys",
      "test/vectors/keys-test.json",
    ]);
    expect(r.code).toBe(2);
  });

  it("emits raw VerifyResult with --json", () => {
    const r = run([
      "test/vectors/proof-v1-valid.json",
      "--keys",
      "test/vectors/keys-test.json",
      "--json",
    ]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.out) as { valid: boolean };
    expect(parsed.valid).toBe(true);
  });
});
