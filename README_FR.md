# GitRecon

[English](README.md) | [Français](README_FR.md)

GitRecon est un outil en ligne de commande dédié à l'analyse de dépôts GitHub et à l'identification d'indicateurs de sécurité.

Il collecte les métadonnées publiques d'un dépôt, inspecte les workflows GitHub Actions, analyse leurs permissions et dépendances, détecte certains comportements pertinents pour la sécurité et peut exporter les résultats au format JSON.

GitRecon est conçu pour l'analyse défensive, l'audit de dépôts, l'étude des workflows GitHub Actions et l'évaluation de la sécurité des chaînes CI/CD.

## Fonctionnalités

GitRecon permet actuellement :

- La collecte des métadonnées d'un dépôt GitHub
- L'analyse des langages de programmation
- L'analyse du nombre de contributeurs, branches et releases
- La détection de fichiers liés à la sécurité
- La détection des workflows GitHub Actions
- Le parsing des fichiers YAML
- L'extraction des dépendances GitHub Actions
- L'analyse des permissions des workflows
- La génération de findings de sécurité
- La détection d'automatisations liées à la sécurité
- L'export des rapports au format JSON
- Une couverture automatisée avec pytest

## Analyse du dépôt

GitRecon collecte plusieurs informations générales sur un dépôt :

- Nom du dépôt
- Propriétaire
- Description
- Branche par défaut
- Langage principal
- Nombre d'étoiles
- Nombre de forks
- Nombre d'issues ouvertes
- Date de création
- Date de dernière mise à jour
- Date du dernier push
- Langages utilisés et leur proportion
- Contributeurs
- Branches
- Releases

## Fichiers de sécurité

GitRecon recherche plusieurs fichiers couramment utilisés pour la sécurité et la gouvernance d'un projet :

- `SECURITY.md`
- Les fichiers de licence
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- La configuration Dependabot

L'objectif est d'obtenir rapidement une vue d'ensemble de la posture de sécurité et de maintenance du dépôt.

## Analyse de GitHub Actions

GitRecon détecte les workflows GitHub Actions et analyse leur contenu lorsque leur fichier YAML est accessible.

Pour chaque workflow, GitRecon peut extraire :

- Le nom du workflow
- Son chemin
- Son état
- Les actions externes utilisées
- Les références complètes `uses:`
- Les permissions explicites au niveau du workflow
- Les permissions explicites au niveau des jobs
- Les findings de sécurité

Exemple de référence d'action :

```text
actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
```

GitRecon distingue les actions officielles GitHub des dépendances tierces et vérifie la manière dont les références sont épinglées.

## Règles de sécurité GitHub Actions

GitRecon implémente actuellement les règles suivantes :

| Règle | Sévérité | Description |
|---|---|---|
| `GH-ACTIONS-001` | HIGH | Utilisation d'une référence `@main` ou `@master` |
| `GH-ACTIONS-002` | MEDIUM | Action non épinglée sur un SHA de commit complet |
| `GH-ACTIONS-003` | INFO | Dépendance GitHub Actions tierce |
| `GH-ACTIONS-004` | HIGH | Permission `write-all` détectée |
| `GH-ACTIONS-005` | MEDIUM | Déclencheur `pull_request_target` détecté |
| `GH-ACTIONS-006` | MEDIUM | Permission `contents: write` détectée |
| `GH-ACTIONS-007` | LOW | Permission `pull-requests: write` détectée |
| `GH-ACTIONS-008` | LOW | Permission `issues: write` détectée |
| `GH-ACTIONS-009` | MEDIUM | Permission `id-token: write` détectée |
| `GH-ACTIONS-010` | LOW | Permission `packages: write` détectée |
| `GH-ACTIONS-011` | HIGH | Combinaison de `pull_request_target` avec des permissions en écriture |

Ces résultats sont des indicateurs de sécurité et doivent être interprétés selon le contexte du workflow.

Par exemple, `contents: write` peut être légitime dans un workflow de release et `id-token: write` est couramment utilisé pour l'authentification OpenID Connect.

Un finding ne signifie donc pas automatiquement qu'un workflow contient une vulnérabilité.

## Détection des automatisations de sécurité

GitRecon peut identifier des automatisations liées à :

- CodeQL
- Zizmor
- Dependency Review
- Des outils de gestion des dépendances
- Des tests
- Des workflows de release

Cela permet d'obtenir rapidement une vue d'ensemble des mécanismes CI/CD et de sécurité déjà présents dans le dépôt.

## Installation

Clone le dépôt :

```bash
git clone https://github.com/PotateBulle/GitRecon.git
cd GitRecon
```

Crée un environnement virtuel Python :

```bash
python -m venv .venv
```

Active-le.

### Bash / Zsh

```bash
source .venv/bin/activate
```

### Fish

```fish
source .venv/bin/activate.fish
```

Installe GitRecon en mode éditable :

```bash
pip install -e .
```

Vérifie l'installation :

```bash
gitrecon --help
```

## Token GitHub

GitRecon utilise l'API GitHub.

L'utilisation d'un token GitHub est recommandée afin de bénéficier de limites d'API plus élevées et d'accéder aux endpoints nécessaires à l'analyse.

Crée un fichier `.env` à la racine du projet :

```env
GITHUB_TOKEN=your_github_token
```

Ne publie jamais ton fichier `.env` ou ton token GitHub.

## Utilisation

Pour analyser un dépôt :

```bash
gitrecon scan owner/repository
```

Une URL GitHub complète peut également être utilisée :

```bash
gitrecon scan https://github.com/owner/repository
```

Les URL terminant par `.git` sont également prises en charge :

```bash
gitrecon scan https://github.com/owner/repository.git
```

## Export JSON

Depuis GitRecon v0.3.6, les résultats d'analyse peuvent être exportés au format JSON.

Exécute :

```bash
gitrecon scan owner/repository --json
```

GitRecon crée automatiquement le dossier :

```text
reports/
```

et génère un rapport nommé à partir du propriétaire et du dépôt :

```text
reports/owner-repository.json
```

Il est également possible de choisir un nom de rapport personnalisé :

```bash
gitrecon scan owner/repository --json -o audit
```

Résultat :

```text
reports/audit.json
```

L'extension `.json` est ajoutée automatiquement si nécessaire.

Les rapports générés sont ignorés par Git et ne sont pas destinés à être ajoutés au dépôt.

## Structure JSON

Un rapport JSON GitRecon contient trois sections principales :

```json
{
  "repository": {},
  "analysis": {},
  "security": {}
}
```

La section de sécurité contient notamment :

```text
security
├── security_policy
├── license
├── code_of_conduct
├── contributing_guide
├── dependabot
├── github_actions
│   └── workflows
│       ├── actions
│       ├── uses
│       ├── permissions
│       └── findings
├── automation
├── workflow_security
└── warnings
```

Ce format permet d'utiliser les rapports GitRecon dans :

- Des outils de sécurité
- Des pipelines CI/CD
- Des scripts de traitement
- Des inventaires de dépôts
- Des tableaux de bord
- D'autres outils d'analyse automatisée

## Exemple de finding

```json
{
  "rule_id": "GH-ACTIONS-006",
  "title": "Permission contents en écriture",
  "description": "Le workflow dispose d'un accès en écriture au contenu du dépôt.",
  "severity": "MEDIUM",
  "workflow": "Publish",
  "path": ".github/workflows/publish.yaml",
  "evidence": "contents: write (job: create-release)",
  "recommendation": "Limiter contents: write aux workflows et aux jobs qui doivent réellement modifier le contenu du dépôt."
}
```

## Développement

Pour vérifier le code avec Ruff :

```bash
ruff check tests gitrecon
```

Pour formater le projet :

```bash
ruff format tests gitrecon
```

Pour lancer les tests :

```bash
pytest -q
```

GitRecon v0.3.6 contient actuellement :

```text
76 passed
```

## Structure du projet

```text
GitRecon/
├── gitrecon/
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── repository.py
│   │   └── security.py
│   ├── github/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── repositories.py
│   │   └── security.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── analysis.py
│   │   ├── repository.py
│   │   └── security.py
│   ├── output/
│   │   ├── __init__.py
│   │   ├── json.py
│   │   └── terminal.py
│   ├── __init__.py
│   ├── cli.py
│   └── config.py
├── tests/
│   ├── __init__.py
│   ├── test_json_output.py
│   └── test_security_analysis.py
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── README_FR.md
└── pyproject.toml
```

## Version actuelle

Version stable actuelle :

```text
v0.3.6
```

Principales nouveautés de la v0.3.6 :

- Export des rapports au format JSON
- Création automatique du dossier `reports/`
- Génération automatique du nom de rapport
- Nom personnalisé avec `--output`
- Sérialisation des workflows
- Sérialisation des permissions
- Sérialisation des findings de sécurité
- Tests de validation JSON
- 76 tests automatisés
- Renforcement de la robustesse de la CLI

## Limitations

GitRecon dépend des informations exposées par l'API GitHub.

Certains workflows présentés par GitHub ne correspondent pas nécessairement à des fichiers YAML classiques stockés directement dans `.github/workflows/`.

GitHub peut notamment exposer des workflows internes ou générés dynamiquement dont le contenu ne peut pas être récupéré via l'API de contenu du dépôt.

Lorsque le contenu d'un workflow n'est pas disponible, GitRecon conserve les métadonnées accessibles et indique que le contenu du workflow est indisponible au lieu de considérer la situation comme une erreur globale d'analyse.

Les findings doivent également être interprétés en fonction de l'architecture CI/CD réelle du dépôt.

L'absence de findings ne garantit pas qu'un dépôt ou qu'un workflow est sécurisé.

## Sécurité

GitRecon est destiné à l'analyse défensive de dépôts, aux audits de sécurité et à la recherche en sécurité.

Ne publie jamais de token GitHub dans :

- Le code source
- Les commits
- Les issues
- Les captures d'écran
- Les rapports
- Les logs de debug

Si tu découvres une vulnérabilité affectant GitRecon lui-même, évite de publier immédiatement des détails d'exploitation sensibles avant que le problème puisse être examiné.

## Contribution

Les contributions sont les bienvenues.

Cela comprend notamment :

- Les rapports de bugs
- Les nouvelles règles de sécurité
- Les améliorations de détection
- Les améliorations de documentation
- Les tests
- Les améliorations de qualité du code

Avant de proposer une modification :

```bash
ruff check tests gitrecon
pytest -q
```

Toute nouvelle règle de détection de sécurité devrait idéalement être accompagnée de tests automatisés dédiés.

## Licence

GitRecon est distribué selon les conditions décrites dans le fichier [`LICENSE`](LICENSE).

## Avertissement

GitRecon fournit des informations automatisées sur les dépôts et des indicateurs liés à la sécurité.

Les résultats sont destinés à faciliter l'analyse défensive et ne remplacent pas une revue de sécurité manuelle.

La présence d'un finding ne signifie pas nécessairement qu'une vulnérabilité existe.

L'absence de findings ne garantit pas qu'un dépôt, un workflow ou une chaîne CI/CD est sécurisé.