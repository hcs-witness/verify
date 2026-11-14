#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { verifyAnchor } from "./anchor.js";
import { verifyProof, type VerifyResult } from "./verify.js";

const USAGE =
  "Usage: hcs-witness-verify <proof.json> --keys <keys.json> [--now <rfc3339>] [--json]";

function parseArgs(args: string[]): {
  proof: string;
  keys: string;
  now?: Date;
  json: boolean;
} {
  let proof: string | undefined;
  let keys: string | undefined;
  let now: Date | undefined;
  let json = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args.at(i);
    if (a === "--keys") {
      keys = args.at(i + 1);
      i += 1;
    } else if (a === "--now") {
      const raw = args.at(i + 1) ?? "";
      const t = Date.parse(raw);
      if (Number.isNaN(t)) throw new Error("invalid --now value");
      now = new Date(t);
      i += 1;
    } else if (a === "--json") {
      json = true;
    } else if (a?.startsWith("-")) {
      throw new Error(`unknown option: ${a}`);
    } else if (proof === undefined) {
      proof = a;
    } else {
      throw new Error("unexpected extra argument");
    }
  }
  if (proof === undefined || keys === undefined) {
    throw new Error("missing arguments");
  }
  const out: { proof: string; keys: string; json: boolean; now?: Date } = {
    proof,
    keys,
    json,
  };
  if (now !== undefined) out.now = now;
  return out;
}

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

try {
  const opts = parseArgs(process.argv.slice(2));
  const proof = loadJson(opts.proof);
  const keys = loadJson(opts.keys);
  const result: VerifyResult = verifyProof(
    proof,
    keys,
    opts.now === undefined ? undefined : { now: opts.now },
  );
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else {
    const expired = result.errors.includes("PROOF_EXPIRED");
    const authErrors = result.errors.filter((e) => e !== "PROOF_EXPIRED");
    process.stdout.write(`proof_id: ${result.proof_id ?? "unknown"}\n`);
    if (result.valid) {
      process.stdout.write("status: VALID\n");
    } else {
      process.stdout.write(
        `status: INVALID (${authErrors.join(", ") || "see errors"})\n`,
      );
    }
    if (expired) {
      process.stdout.write(
        "note: proof is EXPIRED (signature authenticity intact)\n",
      );
    }
    // Bloc presence (étape 5) : affiché pour information, JAMAIS
    // utilisé pour la validité cryptographique.
    const presence = (proof as { presence?: unknown }).presence;
    if (presence !== undefined && presence !== null) {
      const p = presence as {
        challenge?: { kind?: string; completed?: boolean };
        flags?: string[];
      };
      const synced = (p.flags ?? []).includes("synced_passkey");
      process.stdout.write(
        `presence: measured, not yet rated (challenge: ${
          p.challenge?.kind ?? "unknown"
        }${synced ? ", synced passkey" : ""})
`,
      );
    }
    const anchor = verifyAnchor(proof);
    if (anchor.present) {
      process.stdout.write(
        `anchor: merkle inclusion ${anchor.inclusion ? "OK" : "KO"}\n`,
      );
      if (anchor.otsMatchesRoot === false) {
        process.stdout.write("anchor: ots file does NOT attest this root\n");
      }
      if (anchor.bitcoinBlockHeight !== undefined) {
        process.stdout.write(
          `anchor: bitcoin block ${String(anchor.bitcoinBlockHeight)} (attested by the .ots file)\n`,
        );
      } else if (anchor.pendingCalendars.length > 0) {
        process.stdout.write(
          `anchor: pending (${anchor.pendingCalendars.join(", ")})\n`,
        );
      }
      process.stdout.write(
        "note: block confirmation is to be done with a node or an explorer\n",
      );
    }
  }
  process.exit(result.valid ? 0 : 1);
} catch (error) {
  process.stdout.write(
    `${error instanceof Error ? error.message : String(error)}\n${USAGE}\n`,
  );
  process.exit(2);
}
