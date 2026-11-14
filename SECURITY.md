# Politique de sécurité / Security Policy

## Versions supportées / Supported Versions

| Version | Supportée          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Signaler une vulnérabilité / Reporting a Vulnerability

**FR** — Merci de signaler toute vulnérabilité par courriel à
**contact@ia-solution.fr**. N'ouvrez pas de ticket public avant que le
problème soit corrigé.

- Accusé de réception sous **72 heures**.
- Première évaluation sous **7 jours** ; correctif ou plan d'action
  communiqué sous **30 jours** selon la sévérité.
- Divulgation coordonnée : nous publions un avis après la sortie du
  correctif et nous créditons le chercheur si souhaité.

**EN** — Please report any vulnerability by email to
**contact@ia-solution.fr**. Do not open a public issue before the
problem is fixed.

- Acknowledgement within **72 hours**.
- First assessment within **7 days**; a fix or action plan is
  communicated within **30 days** depending on severity.
- Coordinated disclosure: we publish an advisory once the fix is out
  and credit the reporter if desired.

### Périmètre / Scope

Ce paquet ne fait **aucun accès réseau** : toute entrée/sortie réseau
constitue un défaut de sécurité à signaler. Sont également dans le
périmètre : divergence de vérification entre implémentations,
acceptation d'une signature invalide, rejet abusif d'une signature
valide, et toute faiblesse dans la chaîne de publication (provenance,
trusted publishing).
