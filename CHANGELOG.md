# Changelog

Toutes les modifications notables de ce projet sont consignées ici.
Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [1.0.0] - 2026-XX-XX

Première publication publique. Succède au paquet interne privé
`@gateguard/verify` (0.2.0) — même format de preuve, mêmes vérifications.

### Ajouté

- Vérification hors ligne de preuves HCS Witness v1 et v2 :
  signatures ES256 (P-256, low-S) et ML-DSA-65 (contexte
  `gateguard:proof:v1`), fenêtre de validité des clés, plafond
  `signals`, horodatages cohérents.
- Vérification d'ancrage : inclusion Merkle RFC 6962 (DTR),
  lecture des fichiers OpenTimestamps embarqués (attestation Bitcoin,
  calendriers en attente) — aucun accès réseau.
- `checkActionBinding` : lie la preuve à l'action, au contexte (JCS)
  et au texte affiché (NFC) avant exécution.
- CLI `hcs-witness-verify <proof.json> --keys <keys.json>
[--now <rfc3339>] [--json]`.
- Schémas JSON exportés (`proofSchema`, `unsignedProofSchema`,
  `keysetSchema`) et gardes de type (`isProof`, `isUnsignedProof`,
  `isKeyset`) — sans dépendance de validation.

### Sécurité / dépendances

- Dépendances d'exécution réduites à deux : `@noble/post-quantum` et
  `canonicalize` (épinglées en version exacte).
- ES256 et SHA-256 passent par `node:crypto` ; le validateur TypeBox
  interne est remplacé par un évaluateur JSON Schema dédié.

[1.0.0]: https://github.com/hcs-witness/verify/releases/tag/v1.0.0
