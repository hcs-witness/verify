#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { verifyAnchor } from "./anchor.js";
import { checkActionBinding } from "./binding.js";
import {
  verifyProof,
  type VerifyOptions,
  type VerifyResult,
} from "./verify.js";

const USAGE =
  "Usage: hcs-witness-verify <proof.json> --keys <keys.json> [--now <rfc3339>] " +
  "[--expected-keyset-sha256 <hex>] " +
  "[--action <text> --context <context.json> --display <text>] [--json]";

interface CliArgs {
  proof: string;
  keys: string;
  now?: Date;
  expectedKeysetSha256?: string;
  action?: string;
  context?: string;
  display?: string;
  json: boolean;
}

function parseArgs(args: string[]): CliArgs {
  const out: CliArgs = { proof: "", keys: "", json: false };
  let proof: string | undefined;
  const next = (i: number, flag: string): string => {
    const v = args.at(i + 1);
    if (v === undefined) throw new Error(`missing value for ${flag}`);
    return v;
  };
  for (let i = 0; i < args.length; i += 1) {
    const a = args.at(i);
    if (a === "--keys") {
      out.keys = next(i, a);
      i += 1;
    } else if (a === "--now") {
      const t = Date.parse(next(i, a));
      if (Number.isNaN(t)) throw new Error("invalid --now value");
      out.now = new Date(t);
      i += 1;
    } else if (a === "--expected-keyset-sha256") {
      out.expectedKeysetSha256 = next(i, a);
      i += 1;
    } else if (a === "--action") {
      out.action = next(i, a);
      i += 1;
    } else if (a === "--context") {
      out.context = next(i, a);
      i += 1;
    } else if (a === "--display") {
      out.display = next(i, a);
      i += 1;
    } else if (a === "--json") {
      out.json = true;
    } else if (a?.startsWith("-")) {
      throw new Error(`unknown option: ${a}`);
    } else if (proof === undefined) {
      proof = a;
    } else {
      throw new Error("unexpected extra argument");
    }
  }
  if (proof === undefined || out.keys === "") {
    throw new Error("missing arguments");
  }
  out.proof = proof;
  const bindingCount =
    Number(out.action !== undefined) +
    Number(out.context !== undefined) +
    Number(out.display !== undefined);
  if (bindingCount !== 0 && bindingCount !== 3) {
    throw new Error(
      "--action, --context and --display must be given together or not at all",
    );
  }
  return out;
}

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

try {
  const opts = parseArgs(process.argv.slice(2));
  const proof = loadJson(opts.proof);
  const keys = loadJson(opts.keys);
  const verifyOpts: VerifyOptions = {
    ...(opts.now === undefined ? {} : { now: opts.now }),
    ...(opts.expectedKeysetSha256 === undefined
      ? {}
      : { expectedKeysetSha256: opts.expectedKeysetSha256 }),
  };
  const result: VerifyResult = verifyProof(proof, keys, verifyOpts);

  // Liaison preuve/action : les trois options ou aucune (vérifié par
  // parseArgs). Le contexte est lu depuis un fichier JSON.
  const binding =
    opts.action === undefined
      ? undefined
      : checkActionBinding(proof, {
          action: opts.action,
          context: loadJson(opts.context ?? "") as Record<string, unknown>,
          displayText: opts.display ?? "",
        });

  if (opts.json) {
    const payload = binding === undefined ? result : { ...result, binding };
    process.stdout.write(`${JSON.stringify(payload)}\n`);
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
    if (result.reasons !== undefined && result.reasons.length > 0) {
      process.stdout.write(`reasons: ${result.reasons.join(", ")}\n`);
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
  if (binding !== undefined && !opts.json) {
    process.stdout.write(
      binding.valid
        ? "binding: OK\n"
        : `binding: MISMATCH (${binding.errors.join(", ")})\n`,
    );
  }
  process.exit(result.valid && (binding?.valid ?? true) ? 0 : 1);
} catch (error) {
  process.stdout.write(
    `${error instanceof Error ? error.message : String(error)}\n${USAGE}\n`,
  );
  process.exit(2);
}
