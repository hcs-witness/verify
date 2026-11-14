// Loaded via NODE_OPTIONS=--require to prove the CLI does zero network I/O.
"use strict";

const BLOCKED = new Set([
  "net",
  "node:net",
  "tls",
  "node:tls",
  "http",
  "node:http",
  "https",
  "node:https",
  "dns",
  "node:dns",
  "dgram",
  "node:dgram",
]);

const Module = require("node:module");
const originalLoad = Module._load;

Module._load = function (request, ...rest) {
  if (BLOCKED.has(request)) {
    throw new Error(`network module blocked in test: ${request}`);
  }
  return originalLoad.call(this, request, ...rest);
};

globalThis.fetch = () => {
  throw new Error("fetch blocked in test");
};
