# leakline

Scanner de secrets en **un seul fichier PHP**, zéro dépendance. Il attrape les clés API, tokens, clés privées et vrais fichiers `.env` **avant** qu'ils partent sur Git.

```bash
php leakline.php .
```

Code de sortie `1` dès qu'il y a un finding. Rien n'est envoyé sur le réseau : lecture locale, secret masqué dans le rapport.

## Le problème

Un `.env` poussé par erreur, une clé Stripe live collée dans un test, un token GitHub dans un snippet. Les bots scannent les dépôts publics en continu. `gitleaks` est très bien — leakline est le contrôle que tu lances avec le PHP déjà installé sur la machine, un serveur mutualisé, ou une CI Laravel, sans binaire à télécharger.

## Usage

```bash
php leakline.php
php leakline.php --json src/
php leakline.php --ignore=storage,legacy --disable=stripe_test_key .
```

| Option | Effet |
| --- | --- |
| `--json` | Rapport JSON (extraits masqués uniquement) |
| `--quiet`, `-q` | Findings seulement, sans bannière |
| `--no-color` | Texte brut |
| `--max-size=BYTES` | Ignore les fichiers plus gros (défaut 1 Mio) |
| `--ignore=A,B` | Dossiers ou préfixes en plus |
| `--disable=RULE` | Coupe une règle |

Codes de sortie : `0` rien à signaler, `1` au moins un finding, `2` mauvaise utilisation.

Exemple de rapport :

```text
.env:1  [high]  dotenv_committed
  Real dotenv file (keep it out of git)

app/config.php:3  [critical]  aws_access_key
  AWS access key id
  AKIA••••••••789

docs/db.md:1  [high]  database_url
  Database URL with a password
  mysql://app:****@db.internal:3306/app
```

## Ce qui est détecté

| Règle | Niveau | Quoi |
| --- | --- | --- |
| `private_key` | critical | Bloc de clé privée |
| `aws_access_key`, `aws_secret_key` | critical | Identifiants AWS |
| `stripe_live_key` | critical | Clé secrète Stripe live |
| `github_token` | critical | Token GitHub (`ghp_`, `github_pat_`, …) |
| `slack_token`, `slack_webhook` | high | Token ou webhook Slack |
| `google_api_key` | high | Clé API Google |
| `ai_provider_key` | high | Clé `sk-`, `sk-proj-`, `sk-ant-` |
| `sendgrid_key`, `shopify_token`, `npm_token` | high | SendGrid, Shopify, npm |
| `database_url` | high | URL `mysql://` / `postgres://` / `mongodb://` / `redis://` avec mot de passe |
| `dotenv_committed` | high | `.env`, `.env.local`, `.env.production`, `.env.staging`, … |
| `dotenv_secret` | high | Affectation secrète dans un fichier `.env*` |
| `stripe_test_key` | medium | Clé Stripe de test (à ne pas committer non plus) |
| `generic_secret` | medium | Valeur à forte entropie assignée à `api_key`, `password`, `token`, … |

Ne sont **pas** traités comme un vrai `.env` : `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.testing`, `.env.ci`. Leur contenu est quand même scanné : une vraie clé dedans est signalée.

Ignorés par défaut : `vendor/`, `node_modules/`, `.git/`, `storage/framework/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`.

## Faux positifs

Sur la ligne concernée :

```php
$api_key = 'not-really-secret'; // leakline:ignore
```

Ou la ligne juste au-dessus, seule :

```php
// leakline:ignore
$token = $loadedFromTheEnvironment;
```

Fichier `.leaklineignore` à la racine scannée :

```text
# chemins (préfixe, segment, ou glob)
legacy/fixtures/
*.pdf

# règles
rule:generic_secret
```

Les valeurs évidentes (`changeme`, `your-api-key`, `password`, `secret`, `xxxx`, vides) ne remontent pas.

## CI

```yaml
- uses: shivammathur/setup-php@v2
  with:
    php-version: '8.2'
- run: php leakline.php .
```

PHP **8.1+**. Pas de Composer requis. Le dépôt embarque `tests/selftest.php` :

```bash
php tests/selftest.php
```

## Installer le fichier seul

```bash
curl -fsSL -o leakline.php \
  https://raw.githubusercontent.com/Nguemoue/project2026_20261126_leakline/main/leakline.php
php leakline.php .
```

## English

leakline is a single-file PHP secret scanner. It flags API keys, tokens, private keys and real `.env` files before they are committed. Output is masked, nothing is uploaded, and the process exits `1` when it finds something so CI can fail the build.

```bash
php leakline.php .
```

It is not a replacement for GitHub secret scanning or gitleaks. It is the check you can run anywhere PHP 8.1+ already exists.

## Licence

MIT.
