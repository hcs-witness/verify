const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function rev(ch: string): number {
  // Callers guarantee input matches /^[A-Za-z0-9_-]*$/ first.
  return B64.indexOf(ch);
}

export function bytesToB64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes.at(i) ?? 0;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    const b1 = bytes.at(i + 1) ?? 0;
    const b2 = bytes.at(i + 2) ?? 0;
    out += B64.charAt(b0 >> 2);
    out += B64.charAt(((b0 & 3) << 4) | (b1 >> 4));
    if (has1) {
      out += B64.charAt(((b1 & 0x0f) << 2) | (b2 >> 6));
    }
    if (has2) {
      out += B64.charAt(b2 & 0x3f);
    }
  }
  return out;
}

export function b64urlToBytes(input: string): Uint8Array | null {
  if (input.length % 4 === 1 || !/^[A-Za-z0-9_-]*$/.test(input)) {
    return null;
  }
  const quad = (a: string, b: string, c: string, d: string): number =>
    (rev(a) << 18) | (rev(b) << 12) | (rev(c) << 6) | rev(d);
  const bytes: number[] = [];
  const fullGroups = Math.floor(input.length / 4);
  for (let i = 0; i < fullGroups; i += 1) {
    const n = quad(
      input.charAt(i * 4),
      input.charAt(i * 4 + 1),
      input.charAt(i * 4 + 2),
      input.charAt(i * 4 + 3),
    );
    bytes.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const tail = input.slice(fullGroups * 4);
  if (tail.length === 2) {
    const n = quad(tail.charAt(0), tail.charAt(1), "A", "A");
    bytes.push((n >> 16) & 0xff);
  } else if (tail.length === 3) {
    const n = quad(tail.charAt(0), tail.charAt(1), tail.charAt(2), "A");
    bytes.push((n >> 16) & 0xff, (n >> 8) & 0xff);
  }
  return Uint8Array.from(bytes);
}
