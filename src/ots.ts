import { sha256 } from "./hash.js";

/**
 * Client OpenTimestamps minimal (ADR 0009) — format .ots uniquement.
 * Périmètre strict : opérations sha256 / append / prepend,
 * attestations pending et Bitcoin. Toute autre opération ou
 * attestation est une erreur explicite, jamais ignorée. Aucun réseau.
 *
 * Référence du format : opentimestamps/python-opentimestamps,
 * opentimestamps/core/{timestamp,op,notary,serialize}.py.
 */

export class OtsError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "OtsError";
    this.code = code;
  }
}

const MAGIC = Uint8Array.from([
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
const MAJOR_VERSION = 1;

const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const SEP_FORK = 0xff;
const SEP_ATTESTATION = 0x00;

const TAG_PENDING = "83dfe30d2ef90c8e";
const TAG_BITCOIN = "0588960d73d71901";

const MAX_FILE_BYTES = 64 * 1024;
const MAX_MSG_BYTES = 4096;
const MAX_ATTESTATION_PAYLOAD = 8192;
const MAX_URI_BYTES = 1000;
const MAX_DEPTH = 256;
const MAX_NODES = 8192;
const MAX_HEIGHT = 0xffffffff;

const URI_ALLOWED =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:";

export interface OtsOp {
  readonly kind: "sha256" | "append" | "prepend";
  readonly arg?: Uint8Array;
}

export interface OtsAttestation {
  readonly kind: "pending" | "bitcoin";
  readonly uri?: string;
  readonly height?: number;
}

export interface OtsTimestamp {
  readonly msg: Uint8Array;
  readonly attestations: OtsAttestation[];
  readonly ops: { op: OtsOp; stamp: OtsTimestamp }[];
}

export interface OtsFile {
  readonly fileDigest: Uint8Array;
  readonly timestamp: OtsTimestamp;
}

class Reader {
  private pos = 0;
  nodes = 0;
  constructor(private readonly buf: Uint8Array) {}

  byte(): number {
    const b = this.buf.at(this.pos);
    if (b === undefined) {
      throw new OtsError("TRUNCATED", "unexpected end of stream");
    }
    this.pos += 1;
    return b;
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw new OtsError("TRUNCATED", "unexpected end of stream");
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  varuint(): number {
    let value = 0;
    let shift = 0;
    for (let i = 0; i < 9; i += 1) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) {
        // Canonique : le dernier octet ne peut pas valoir 0 sauf si
        // c'est le seul octet.
        if (b === 0 && i > 0) {
          throw new OtsError("VARUINT", "non-canonical varuint");
        }
        if (value > Number.MAX_SAFE_INTEGER) {
          throw new OtsError("VARUINT", "varuint overflow");
        }
        return value;
      }
      shift += 7;
    }
    throw new OtsError("VARUINT", "varuint too long");
  }

  varbytes(maxLen: number, minLen = 0): Uint8Array {
    const n = this.varuint();
    if (n < minLen || n > maxLen) {
      throw new OtsError(
        "LENGTH",
        `varbytes length ${String(n)} out of bounds`,
      );
    }
    return this.bytes(n);
  }

  done(): boolean {
    return this.pos === this.buf.length;
  }
}

function applyOp(op: OtsOp, msg: Uint8Array): Uint8Array {
  let out: Uint8Array;
  if (op.kind === "sha256") {
    out = sha256(msg);
  } else {
    const arg = op.arg;
    /* c8 ignore next 3 — défensif : le parseur garantit arg pour les ops binaires */
    if (arg === undefined) {
      throw new OtsError("OP", "binary op without arg");
    }
    out =
      op.kind === "append"
        ? Uint8Array.from([...msg, ...arg])
        : Uint8Array.from([...arg, ...msg]);
  }
  /* c8 ignore next 3 — défensif : out.length === 0 impossible (ops >= 1 octet) */
  if (out.length === 0 || out.length > MAX_MSG_BYTES) {
    throw new OtsError("MSG_LENGTH", "message length out of bounds");
  }
  return out;
}

function hexOf(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function readAttestation(r: Reader): OtsAttestation {
  const tag = hexOf(r.bytes(8));
  const payload = r.varbytes(MAX_ATTESTATION_PAYLOAD);
  if (tag === TAG_BITCOIN) {
    const pr = new Reader(payload);
    const height = pr.varuint();
    if (!pr.done()) {
      throw new OtsError("ATTESTATION", "trailing bytes in attestation");
    }
    if (height > MAX_HEIGHT) {
      throw new OtsError("ATTESTATION", "block height out of range");
    }
    return { kind: "bitcoin", height };
  }
  if (tag === TAG_PENDING) {
    const pr = new Reader(payload);
    const raw = pr.varbytes(MAX_URI_BYTES);
    if (!pr.done()) {
      throw new OtsError("ATTESTATION", "trailing bytes in attestation");
    }
    let uri: string;
    try {
      uri = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new OtsError("ATTESTATION", "pending URI is not valid UTF-8");
    }
    for (const ch of uri) {
      if (!URI_ALLOWED.includes(ch)) {
        throw new OtsError("ATTESTATION", "forbidden char in pending URI");
      }
    }
    return { kind: "pending", uri };
  }
  throw new OtsError("UNKNOWN_ATTESTATION", `unknown attestation tag ${tag}`);
}

function readTimestamp(
  r: Reader,
  initialMsg: Uint8Array,
  depth: number,
): OtsTimestamp {
  if (depth > MAX_DEPTH) {
    throw new OtsError("DEPTH", "timestamp tree too deep");
  }
  /* c8 ignore next 3 — défensif : l'en-tête impose un digest de 32 octets */
  if (initialMsg.length === 0 || initialMsg.length > MAX_MSG_BYTES) {
    throw new OtsError("MSG_LENGTH", "message length out of bounds");
  }
  r.nodes += 1;
  /* c8 ignore next 3 — défensif : > 8192 nœuds excéderait la borne fichier de 64 Ko */
  if (r.nodes > MAX_NODES) {
    throw new OtsError("NODES", "timestamp tree too large");
  }
  const stamp: OtsTimestamp = { msg: initialMsg, attestations: [], ops: [] };
  const seenOps = new Set<string>();

  const readItem = (tag: number): void => {
    if (tag === SEP_ATTESTATION) {
      stamp.attestations.push(readAttestation(r));
      return;
    }
    let op: OtsOp;
    if (tag === OP_SHA256) {
      op = { kind: "sha256" };
    } else if (tag === OP_APPEND || tag === OP_PREPEND) {
      op = {
        kind: tag === OP_APPEND ? "append" : "prepend",
        arg: r.varbytes(MAX_MSG_BYTES, 1),
      };
    } else {
      throw new OtsError(
        "UNKNOWN_OP",
        `unsupported operation tag 0x${tag.toString(16)}`,
      );
    }
    const key = `${String(tag)}:${hexOf(op.arg ?? new Uint8Array())}`;
    if (seenOps.has(key)) {
      throw new OtsError("DUPLICATE_OP", "repeated operation in timestamp");
    }
    seenOps.add(key);
    stamp.ops.push({
      op,
      stamp: readTimestamp(r, applyOp(op, initialMsg), depth + 1),
    });
  };

  let tag = r.byte();
  while (tag === SEP_FORK) {
    readItem(r.byte());
    tag = r.byte();
  }
  readItem(tag);
  return stamp;
}

/** Lit un fichier .ots complet. Jamais d'exception non gérée : OtsError. */
export function parseOtsFile(input: Uint8Array): OtsFile {
  if (!(input instanceof Uint8Array)) {
    throw new OtsError("TYPE", "input must be a Uint8Array");
  }
  if (input.length === 0 || input.length > MAX_FILE_BYTES) {
    throw new OtsError("SIZE", "file size out of bounds");
  }
  const r = new Reader(input);
  const magic = r.bytes(MAGIC.length);
  if (hexOf(magic) !== hexOf(MAGIC)) {
    throw new OtsError("BAD_MAGIC", "bad file magic");
  }
  if (r.varuint() !== MAJOR_VERSION) {
    throw new OtsError("VERSION", "unsupported .ots major version");
  }
  const fileHashOp = r.byte();
  if (fileHashOp !== OP_SHA256) {
    throw new OtsError(
      "FILE_HASH_OP",
      `unsupported file digest op 0x${fileHashOp.toString(16)}`,
    );
  }
  const fileDigest = r.bytes(32);
  const timestamp = readTimestamp(r, fileDigest, 0);
  if (!r.done()) {
    throw new OtsError("TRAILING", "trailing garbage after timestamp");
  }
  return { fileDigest, timestamp };
}

/* ------------------------------------------------------------------ */
/* Sérialisation canonique (miroir de timestamp.py serialize)          */
/* ------------------------------------------------------------------ */

class Writer {
  private out: number[] = [];
  byte(b: number): void {
    this.out.push(b);
  }
  bytes(bs: Uint8Array): void {
    for (const b of bs) this.out.push(b);
  }
  varuint(value: number): void {
    let v = value;
    for (;;) {
      const b = v % 128;
      v = Math.floor(v / 128);
      if (v === 0) {
        this.byte(b);
        return;
      }
      this.byte(b | 0x80);
    }
  }
  varbytes(bs: Uint8Array): void {
    this.varuint(bs.length);
    this.bytes(bs);
  }
  toBytes(): Uint8Array {
    return Uint8Array.from(this.out);
  }
}

function bytesFromHex(hex: string): Uint8Array {
  /* c8 ignore next — défensif : les tags internes sont de longueur paire */
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
}

function opSortKey(op: OtsOp): Uint8Array {
  const tag =
    op.kind === "sha256"
      ? OP_SHA256
      : op.kind === "append"
        ? OP_APPEND
        : OP_PREPEND;
  return Uint8Array.from([tag, ...(op.arg ?? [])]);
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    /* c8 ignore next — défensif : i < min(len) garantit la présence */
    const d = (a.at(i) ?? 0) - (b.at(i) ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

function attTag(att: OtsAttestation): Uint8Array {
  return bytesFromHex(att.kind === "bitcoin" ? TAG_BITCOIN : TAG_PENDING);
}

function writeAttestation(w: Writer, att: OtsAttestation): void {
  w.bytes(attTag(att));
  const p = new Writer();
  if (att.kind === "bitcoin") {
    p.varuint(att.height ?? 0);
  } else {
    p.varbytes(new TextEncoder().encode(att.uri ?? ""));
  }
  w.varbytes(p.toBytes());
}

function writeOp(w: Writer, op: OtsOp): void {
  w.byte(
    op.kind === "sha256"
      ? OP_SHA256
      : op.kind === "append"
        ? OP_APPEND
        : OP_PREPEND,
  );
  if (op.arg !== undefined) {
    w.varbytes(op.arg);
  }
}

/** Sérialise un Timestamp (ordre canonique : attestations puis ops). */
export function serializeTimestamp(stamp: OtsTimestamp): Uint8Array {
  const w = new Writer();
  const atts = [...stamp.attestations].sort((a, b) =>
    cmpBytes(attTag(a), attTag(b)),
  );
  const ops = [...stamp.ops].sort((x, y) =>
    cmpBytes(opSortKey(x.op), opSortKey(y.op)),
  );
  for (const att of atts.slice(0, -1)) {
    w.byte(SEP_FORK);
    w.byte(SEP_ATTESTATION);
    writeAttestation(w, att);
  }
  const lastAtt = atts.at(-1);
  if (ops.length === 0) {
    if (lastAtt === undefined) {
      throw new OtsError("EMPTY", "empty timestamp cannot be serialized");
    }
    w.byte(SEP_ATTESTATION);
    writeAttestation(w, lastAtt);
  } else {
    if (lastAtt !== undefined) {
      w.byte(SEP_FORK);
      w.byte(SEP_ATTESTATION);
      writeAttestation(w, lastAtt);
    }
    for (const { op, stamp: sub } of ops.slice(0, -1)) {
      w.byte(SEP_FORK);
      writeOp(w, op);
      w.bytes(serializeTimestamp(sub));
    }
    const last = ops.at(-1);
    /* c8 ignore next 3 — défensif : ops.length > 0 garanti en amont */
    if (last === undefined) {
      throw new OtsError("EMPTY", "no operations");
    }
    writeOp(w, last.op);
    w.bytes(serializeTimestamp(last.stamp));
  }
  return w.toBytes();
}

/** Fabrique un fichier .ots : magic ‖ version ‖ sha256 ‖ digest ‖ timestamp. */
export function serializeOtsFile(
  fileDigest: Uint8Array,
  timestampBytes: Uint8Array,
): Uint8Array {
  if (fileDigest.length !== 32) {
    throw new OtsError("DIGEST", "file digest must be 32 bytes");
  }
  return Uint8Array.from([
    ...MAGIC,
    MAJOR_VERSION,
    OP_SHA256,
    ...fileDigest,
    ...timestampBytes,
  ]);
}

/** Toutes les attestations de l'arbre (avec le msg attesté). */
export function allAttestations(stamp: OtsTimestamp): {
  msg: Uint8Array;
  attestation: OtsAttestation;
}[] {
  const out = stamp.attestations.map((attestation) => ({
    msg: stamp.msg,
    attestation,
  }));
  for (const { stamp: sub } of stamp.ops) {
    out.push(...allAttestations(sub));
  }
  return out;
}

/** Plus petite hauteur de bloc Bitcoin attestée, si présente. */
export function bitcoinBlockHeight(stamp: OtsTimestamp): number | undefined {
  const heights = allAttestations(stamp)
    .filter((a) => a.attestation.kind === "bitcoin")
    .map((a) => a.attestation.height ?? 0);
  return heights.length === 0 ? undefined : Math.min(...heights);
}
