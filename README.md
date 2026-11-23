# @hcs-witness/verify

Offline verification library and CLI for **HCS Witness** proofs —
vérificateur hors ligne des preuves HCS Witness.

A proof is a signed document attesting that a human approved (or
refused) a critical action. This package verifies such proofs **without
any network access**: signatures (ES256 + ML-DSA-65), key validity
windows, Merkle inclusion, and embedded OpenTimestamps anchors.

Runtime dependencies: two — `@noble/post-quantum` and `canonicalize`,
pinned to exact versions. ES256 and SHA-256 go through `node:crypto`.

## Installation

```bash
npm install --global @hcs-witness/verify   # CLI
npm install @hcs-witness/verify            # library
```

Requires Node.js **≥ 22** — no Node-24-only API is used at runtime
(tested in CI on Node 22 and 24; releases are built on Node 24).

## Verify a proof (CLI)

```bash
hcs-witness-verify <proof.json> --keys <keys.json> [--now <rfc3339>]
                   [--expected-keyset-sha256 <hex>]
                   [--action <text> --context <context.json> --display <text>]
                   [--json]
```

- `<proof.json>`: a proof document (`proofs/<proof_id>.json` in an audit
  export, or `GET /v1/proofs/<id>` output). Proof versions v1, v2 and v3
  are accepted.
- `--keys`: the public keyset (`keys.json` in an export, or
  `/.well-known/hcs-keys.json` on the issuing service).
- `--now`: reference time for expiry checks (default: none).
- `--expected-keyset-sha256 <hex>`: pin the keyset — SHA-256 of its
  canonical JCS form, i.e. the value of the `ETag` served with
  `/.well-known/hcs-keys.json`. Obtain it out of band; a mismatch makes
  the proof `INVALID` with `KEYSET_PIN_MISMATCH`.
- `--action`, `--context`, `--display`: action binding check — must be
  given all three together or not at all. `--context` points to a JSON
  file with the same object sent with the approval request, `--display`
  is the exact text shown to the human. The check runs
  `checkActionBinding`; any `*_MISMATCH` makes the run invalid.
- Exit code: `0` — proof valid and binding (when requested) OK;
  `1` — proof invalid or binding mismatch; `2` — usage or I/O error.

```console
$ hcs-witness-verify proofs/ggp_01JZ….json --keys keys.json
proof_id: ggp_01JZFXANCH0REDPR00FV2TEST9
status: VALID
presence: measured, not yet rated (challenge: numeric, synced passkey)
anchor: merkle inclusion OK
anchor: bitcoin block 915042 (attested by the .ots file)
note: block confirmation is to be done with a node or an explorer
```

## Library usage

```ts
import {
  verifyProof,
  verifyAnchor,
  checkActionBinding,
} from "@hcs-witness/verify";

const result = verifyProof(proofJson, keysetJson, { now: new Date() });
// → { valid: boolean, errors: VerifyErrorCode[], proof_id? }

const anchor = verifyAnchor(proofJson);
// → { present, inclusion, otsMatchesRoot, bitcoinBlockHeight, pendingCalendars }

// Before executing the attested action — mandatory binding check:
const binding = checkActionBinding(proofJson, {
  action: "armoury.firearm.release",
  context, // same object sent with the approval request
  displayText, // exact text shown to the human (NFC applied)
});
```

The exported JSON Schemas (`proofSchema`, `unsignedProofSchema`,
`keysetSchema`) are plain JSON Schema documents — usable with any
validator (e.g. ajv) — and `isProof` / `isUnsignedProof` / `isKeyset`
are dependency-free type guards.

## Publishing a release

The real publication process (described, not run from a working copy):

1. The maintainer signs an annotated tag `v<version>` exactly matching
   `package.json` `version` and pushes it.
2. `.github/workflows/release.yml` triggers on the tag: `npm ci`,
   `lint`, `typecheck`, `build`, `test`, then a guard step that fails
   if the tag does not equal the package version.
3. `npm publish --provenance` runs with **npm trusted publishing
   (OIDC)** — the `id-token: write` permission mints a short-lived
   OIDC token in the `npm-release` environment; no npm access token
   exists anywhere.
4. The published tarball carries a **Sigstore provenance** statement
   linking it to the GitHub Actions run and commit; verifiable with
   `npm audit signatures`.

## Verify the package provenance

Every release is published from GitHub Actions via **npm trusted
publishing (OIDC)** with Sigstore provenance — no access token exists
anywhere.

```bash
npm audit signatures   # in a project that depends on @hcs-witness/verify
```

The package page on [npmjs.com/package/@hcs-witness/verify](https://www.npmjs.com/package/@hcs-witness/verify)
shows the provenance badge linking back to the exact GitHub Actions run
and commit in [hcs-witness/verify](https://github.com/hcs-witness/verify).

## Verify a Bitcoin anchor

If the proof carries `anchor.ots` (base64 OpenTimestamps file attesting
the Merkle root), offline parsing is included; confirming the block on
the blockchain is done with the public OpenTimestamps tooling:

```bash
# save anchors/<batch_id>.ots from the audit export, then:
ots verify anchors/<batch_id>.ots
```

`verifyAnchor` reports `bitcoinBlockHeight` when the .ots embeds a
Bitcoin attestation, and `pendingCalendars` when it is still awaiting
confirmation.

## Proof format and compatibility

- Format versions `v: 1`, `v: 2` and `v: 3` are supported. The
  `presence` block appeared in v2; v3 adds a mandatory enrollment
  history under `human_factor` and a mandatory `assurance` object
  (`{ level: "N1" | "N2", controls }`). The package version is
  **independent** of the proof-format version.
- Schema selection is driven by the `v` field; an unknown version is
  rejected with `UNSUPPORTED_VERSION`. `proofV1Schema`/`proofV2Schema`
  are byte-for-byte identical to the schemas emitted proofs were
  validated against (full non-regression).
- A new verifier release always keeps verifying all previously
  published format versions; dropping a format version requires a
  major release announced ≥ 12 months in advance.
- The ML-DSA context string `gateguard:proof:v1` and the JCS (RFC 8785)
  canonicalization are part of the signed format — they are immutable
  and retained verbatim for compatibility.
- The `presence` block is signed but **never** used for cryptographic
  validity; it is reported for information only.

## Security

Vulnerability reports: **contact@ia-solution.fr** — see
[SECURITY.md](SECURITY.md). This package performs **zero network
access**: any network I/O is a security defect.

---

## Français

`@hcs-witness/verify` nécessite Node.js **≥ 22** et vérifie hors ligne les preuves HCS Witness :
signatures ES256 (P-256, low-S) et ML-DSA-65, fenêtre de validité des
clés, inclusion Merkle et ancrage OpenTimestamps — **sans aucun accès
réseau**.

```bash
npm install --global @hcs-witness/verify
hcs-witness-verify proofs/<proof_id>.json --keys keys.json
```

- Codes de sortie : `0` valide, `1` invalide ou liaison non conforme,
  `2` erreur d'usage.
- Provenance : `npm audit signatures` + badge de provenance sur la page
  npm ; publication par trusted publishing OIDC depuis GitHub Actions,
  sans aucun jeton.
- Ancrage Bitcoin : `verifyAnchor` vérifie l'inclusion Merkle et lit le
  fichier `.ots` embarqué ; la confirmation du bloc se fait avec les
  outils publics OpenTimestamps (`ots verify anchors/<batch_id>.ots`).
- Compatibilité : les formats `v:1`, `v:2` et `v:3` restent
  vérifiables (v3 ajoute l'historique d'enrôlement et l'objet
  `assurance`, tous deux obligatoires) ; le contexte signé
  `gateguard:proof:v1` et la canonicalisation JCS sont immuables.
- Épinglage : `--expected-keyset-sha256 <hex>` refuse explicitement un
  jeu de clés différent de celui épinglé hors bande (empreinte = ETag
  de `/.well-known/hcs-witness-keys.json`).
- Liaison : `--action` / `--context` / `--display` vérifient que la
  preuve porte bien sur l'action, le contexte et le texte affiché —
  codes de sortie `0` valide, `1` invalide ou liaison non conforme,
  `2` erreur d'usage.
- Sécurité : signalement à **contact@ia-solution.fr** (cf. SECURITY.md).
