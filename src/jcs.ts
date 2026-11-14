import canonicalize from "canonicalize";

export class NonJsonValueError extends Error {
  constructor(path: string, reason: string) {
    super(`non-JSON value at ${path}: ${reason}`);
    this.name = "NonJsonValueError";
  }
}

function assertJsonValue(
  value: unknown,
  path: string,
  seen: Set<object>,
): void {
  if (value === undefined) {
    throw new NonJsonValueError(path, "undefined");
  }
  if (value === null) {
    return;
  }
  switch (typeof value) {
    case "boolean":
    case "string":
      return;
    case "number":
      if (!Number.isFinite(value)) {
        throw new NonJsonValueError(path, "non-finite number");
      }
      return;
    case "object":
      break;
    default:
      throw new NonJsonValueError(path, typeof value);
  }
  const obj = value;
  if (seen.has(obj)) {
    throw new NonJsonValueError(path, "cyclic reference");
  }
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      obj.forEach((item, index) => {
        assertJsonValue(item, `${path}[${String(index)}]`, seen);
      });
      return;
    }
    const proto: unknown = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      throw new NonJsonValueError(path, "non-plain object");
    }
    for (const [key, member] of Object.entries(obj)) {
      assertJsonValue(member, `${path}.${key}`, seen);
    }
  } finally {
    seen.delete(obj);
  }
}

export function canonicalBytes(value: unknown): Uint8Array {
  assertJsonValue(value, "$", new Set());
  const out = canonicalize(value);
  if (out === undefined) {
    throw new NonJsonValueError("$", "canonicalize returned undefined");
  }
  return new TextEncoder().encode(out);
}
