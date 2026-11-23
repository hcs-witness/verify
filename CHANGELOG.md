# Changelog

Toutes les modifications notables de ce projet sont consignées ici.
Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet respecte [Semantic Versioning](https://semver.org/lang/fr/).

## [1.1.0] - 2026-XX-XX

Ajout compatible : format de preuve `v:3`, épinglage du jeu de clés et
liaison preuve/action dans la CLI. Aucun changement de comportement
pour les preuves `v:1` et `v:2` déjà émises — leurs schémas sont
inchangés octet pour octet (non-régression testée).

### Ajouté

- Schémas par version : `proofV1Schema` / `proofV2Schema` /
  `proofV3Schema` (et `unsignedProof*`), sélection sur le champ `v` ;
  version inconnue → erreur explicite `UNSUPPORTED_VERSION`.
- `v:3` = v2 plus, sous `human_factor`, l'historique d'enrôlement
  OBLIGATOIRE (`enrolled_at`, `confirmed_at`, `invited_by_ref`,
  `confirmed_by_ref`, `self_confirmed`, `enrollment_code_verified`)
  et l'objet `assurance` OBLIGATOIRE `{ level: "N1" | "N2",
controls }` (contrôles énumérés, sans doublon).
  `additionalProperties: false` à tous les niveaux, comme v1/v2.
- `keysetSha256(keyset)` : SHA-256 du JCS canonique du jeu de clés —
  la même valeur que l'ETag servi par
  `/.well-known/hcs-witness-keys.json`. L'empreinte se publie hors
  bande ; le document du jeu de clés est inchangé.
- `verifyProof` : option `expectedKeysetSha256` → erreur dédiée
  `KEYSET_PIN_MISMATCH` en cas de différence.
- CLI : `--expected-keyset-sha256 <hex>` (refus + sortie non nulle
  en cas de différence) et `--action` / `--context` / `--display`
  (les trois ensemble ou aucun ; contrôle via `checkActionBinding`,
  mismatch → sortie non nulle et message explicite). Codes de sortie
  documentés dans le README.
- Vecteur fixe signé `test/vectors/proof-v3-valid.json` +
  `keys-v3-test.json`, régénérable via
  `tools/gen-proof-v3-vector.ts` (clés seedées de test, présentes
  uniquement dans les tests), empreintes SHA-256 épinglées.
- Gardes et types : `isProofV1/V2/V3`, `isUnsignedProofV1/V2/V3`,
  `ProofV1/V2/V3`, `UnsignedProofV1/V2/V3`, `ProofAssurance`,
  `AssuranceControl`, `HumanFactorV3`.
- Évaluateur de schéma interne : support de `uniqueItems`.

### Notes

- Les émetteurs n'activent `v:3` que derrière un réglage de version
  de schéma côté serveur, après publication de ce vérificateur — une
  preuve v3 émise avant serait refusée `UNSUPPORTED_VERSION` par les
  vérificateurs publiés antérieurs.
- Voir la section « Publishing a release » du README pour le
  processus de publication réel (tag signé, trusted publishing OIDC,
  provenance Sigstore) — non exécuté dans ce commit.

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

[1.1.0]: https://github.com/hcs-witness/verify/releases/tag/v1.1.0
[1.0.0]: https://github.com/hcs-witness/verify/releases/tag/v1.0.0
