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

/* ------------------------------------------------------------------ */
/* V1.3 : épinglage du jeu de clés + liaison preuve/action             */
/* ------------------------------------------------------------------ */

import { createHash } from "node:crypto";
import { canonicalBytes, keysetSha256 } from "../src/index.js";
import { makeTestSigners, signTestProof } from "./helpers/signer.js";
import type { UnsignedProof } from "../src/index.js";

const BOUND_ACTION = "armoury.firearm.release";
const BOUND_CONTEXT = { room: "vault-7", ticket: 42 };
const BOUND_DISPLAY = "Release firearm to operator-42";

function boundFixture(): {
  proofPath: string;
  keysPath: string;
  contextPath: string;
} {
  const dev = makeTestSigners();
  const sha = (b: Uint8Array) =>
    Buffer.from(createHash("sha256").update(b).digest()).toString("hex");
  const unsigned = {
    v: 1,
    proof_id: "ggp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    tenant_id: "tnt_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    approval_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAX",
    action: BOUND_ACTION,
    subject_ref: "operator-42",
    context_sha256: sha(canonicalBytes(BOUND_CONTEXT)),
    display_sha256: sha(
      new TextEncoder().encode(BOUND_DISPLAY.normalize("NFC")),
    ),
    decision: "approved",
    human_factor: {
      method: "webauthn",
      user_verified: true,
      credential_id_sha256: "b".repeat(64),
      authenticator_aaguid: "3f6b0f42-3d5a-4b8e-9c1d-2e4f5a6b7c8d",
    },
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2030-01-01T00:00:00Z",
  } as unknown as UnsignedProof;
  const signed = signTestProof(unsigned, dev);
  const dir = mkdtempSync(join(tmpdir(), "ggv-bound-"));
  const proofPath = join(dir, "proof.json");
  const keysPath = join(dir, "keys.json");
  const contextPath = join(dir, "context.json");
  writeFileSync(proofPath, JSON.stringify(signed));
  writeFileSync(keysPath, JSON.stringify(dev.keyset()));
  writeFileSync(contextPath, JSON.stringify(BOUND_CONTEXT));
  return { proofPath, keysPath, contextPath };
}

describe("hcs-witness-verify CLI — V1.3", () => {
  it("accepts a v:2 proof", () => {
    const r = run([
      "test/vectors/proof-v2-anchored.json",
      "--keys",
      "test/vectors/keys-local.json",
    ]);
    expect(r.code).toBe(0);
  });

  it("exit 0 when --expected-keyset-sha256 matches", () => {
    const { proofPath, keysPath } = boundFixture();
    const keysetJson: unknown = JSON.parse(
      execFileSync("cat", [keysPath], { encoding: "utf8" }),
    );
    const pin = keysetSha256(keysetJson);
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--expected-keyset-sha256",
      pin,
    ]);
    expect(r.code).toBe(0);
  });

  it("exit 1 with KEYSET_PIN_MISMATCH on a wrong pin", () => {
    const { proofPath, keysPath } = boundFixture();
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--expected-keyset-sha256",
      "0".repeat(64),
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("KEYSET_PIN_MISMATCH");
  });

  it("exit 2 when binding options are incomplete", () => {
    const { proofPath, keysPath } = boundFixture();
    const r = run([proofPath, "--keys", keysPath, "--action", BOUND_ACTION]);
    expect(r.code).toBe(2);
  });

  it("exit 0 when action/context/display all match", () => {
    const { proofPath, keysPath, contextPath } = boundFixture();
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--action",
      BOUND_ACTION,
      "--context",
      contextPath,
      "--display",
      BOUND_DISPLAY,
    ]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("binding: OK");
  });

  it("exit 1 with an explicit message on action mismatch", () => {
    const { proofPath, keysPath, contextPath } = boundFixture();
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--action",
      "armoury.firearm.seize",
      "--context",
      contextPath,
      "--display",
      BOUND_DISPLAY,
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("ACTION_MISMATCH");
  });

  it("exit 1 on context mismatch", () => {
    const { proofPath, keysPath } = boundFixture();
    const dir = mkdtempSync(join(tmpdir(), "ggv-ctx-"));
    const badContext = join(dir, "context.json");
    writeFileSync(badContext, JSON.stringify({ room: "vault-8" }));
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--action",
      BOUND_ACTION,
      "--context",
      badContext,
      "--display",
      BOUND_DISPLAY,
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("CONTEXT_MISMATCH");
  });

  it("exit 1 on display mismatch", () => {
    const { proofPath, keysPath, contextPath } = boundFixture();
    const r = run([
      proofPath,
      "--keys",
      keysPath,
      "--action",
      BOUND_ACTION,
      "--context",
      contextPath,
      "--display",
      "Release firearm to operator-99",
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("DISPLAY_MISMATCH");
  });
});

describe("hcs-witness-verify CLI — V1.6 assurance coherence", () => {
  it("exit 1 with the reason on an inconsistent v3 proof", () => {
    const dev = makeTestSigners();
    const raw = JSON.parse(
      execFileSync("cat", ["test/vectors/proof-v3-valid.json"], {
        encoding: "utf8",
      }),
    ) as Record<string, unknown>;
    delete raw.sig;
    const signed = signTestProof(
      {
        ...raw,
        human_factor: {
          ...(raw.human_factor as Record<string, unknown>),
          confirmed_at: null,
        },
      } as unknown as UnsignedProof,
      dev,
    );
    const dir = mkdtempSync(join(tmpdir(), "ggv-v16-"));
    const proofPath = join(dir, "proof.json");
    const keysPath = join(dir, "keys.json");
    writeFileSync(proofPath, JSON.stringify(signed));
    writeFileSync(keysPath, JSON.stringify(dev.keyset()));
    const r = run([proofPath, "--keys", keysPath]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("ASSURANCE_INCONSISTENT");
    expect(r.out).toContain("enrollment_confirmed_but_confirmed_at_null");
  });
});
