# Veille technologique — BTS SIO SISR

Architecture : **RSS / Atom → GitHub Actions → Python → Gemini API → JSON → GitHub Pages → Framer /veille**.

## Règles de conservation et performance

| Période | Fichier | Politique |
|---|---|---|
| Actualités récentes | `site/data/recent.json` | Articles des **60 derniers jours** |
| Archives | `site/data/archives.json` | Articles de **plus de 60 jours et jusqu’à 365 jours** |
| Plafond | Les deux fichiers | **1 000 articles maximum** au total |
| Compatibilité | `site/data/articles.json` | Copie temporaire des seuls articles récents pour les anciens composants |

Chaque synchronisation classe les publications par date, élimine les URL en doublon et retire des fichiers courants les articles âgés de plus de 365 jours ou dépassant les 1 000 plus récents. La date de publication est utilisée ; si elle est absente, la date de collecte sert de repli. Ces règles ne suppriment pas les anciens objets de l’historique Git.

Le portfolio Framer télécharge **uniquement recent.json au démarrage**. Il récupère archives.json seulement lorsque le lecteur choisit l’onglet Archives. Recherche, filtres, tri et pagination fonctionnent sur chaque vue.

## Collecte et intelligence artificielle

- Sources : CERT-FR alertes et avis, Ubuntu Security, Docker, Kubernetes, Cloudflare, Linux Kernel, **Microsoft Windows IT Pro Blog** (Windows, Windows Server, administration et sécurité).
- Jusqu’à **8 nouveaux articles par exécution** et **3 par source** ; sélection **équilibrée par rotation entre les sources (round-robin)** afin que les flux moins fréquents, notamment Windows IT Pro, ne soient pas masqués par les autres ; classification SISR (dont une catégorie **Windows** dédiée) et déduplication.
- Gemini produit un résumé factuel en français si disponible. Sinon la description RSS est conservée et indiquée comme `summary_kind: extrait`.
- Aucun secret dans les données publiques : la clé `GEMINI_API_KEY` reste dans les GitHub Actions Secrets.
- En cas d’échec de tous les flux RSS, le script échoue sans écraser les données existantes. Les erreurs partielles sont consignées.
- Migration automatique des données historiques de `articles.json` lors de la première exécution de la nouvelle version.

## Programmation

Le workflow [Veille technologique quotidienne](https://github.com/Berberin-2k/bts-sio-veille/actions/workflows/veille.yml) s’exécute chaque jour à **06:17 Europe/Paris** (retard possible côté GitHub) et manuellement avec `workflow_dispatch`.

Avant publication : tests offline, validation des JSON, vérification des dates, des doublons et du plafond de conservation.

## URLs des données

- Actualités : https://berberin-2k.github.io/bts-sio-veille/data/recent.json
- Archives : https://berberin-2k.github.io/bts-sio-veille/data/archives.json
- Compatibilité : https://berberin-2k.github.io/bts-sio-veille/data/articles.json

## Configuration

1. Repository public ; ajouter le secret **GEMINI_API_KEY** dans Settings → Secrets and variables → Actions.
2. Activer GitHub Pages avec **Source: GitHub Actions**.
3. Lancer le workflow manuellement pour vérifier la première synchronisation.

## Tests

```bash
python -m unittest discover -s tests -v
python scripts/collect.py
```

Le second appel nécessite un accès réseau. La clé Gemini est facultative.

## Exploitation et limites

- Les articles ne sont pas reproduits intégralement : seuls titre, URL, source, date, catégorie et court résumé sont publics.
- Un JSON manquant ou corrompu provoque une erreur plutôt que d’effacer silencieusement les données.
- Les anciens commits Git ne sont pas purgés par les règles de conservation des données courantes.
- GitHub peut désactiver les scheduled workflows des repositories publics après 60 jours d’inactivité : vérifier périodiquement les exécutions.
- Les résumés automatiques ne constituent pas une vérification humaine. Toujours consulter les sources officielles avant toute décision technique.
