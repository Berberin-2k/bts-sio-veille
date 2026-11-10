# Veille technologique — BTS SIO SISR

Architecture : **RSS / Atom → GitHub Actions / Python → collecte des bulletins officiels → API NVD (CVE/CVSS avec cache) + Gemini → JSON → GitHub Pages → Framer /veille**.

## Règles de conservation et performance

| Période | Fichier | Politique |
|---|---|---|
| Actualités récentes | `site/data/recent.json` | Articles des **60 derniers jours** |
| Archives | `site/data/archives.json` | Articles de **plus de 60 jours et jusqu’à 365 jours** |
| Plafond | Les deux fichiers | **1 000 articles maximum** au total |
| Compatibilité | `site/data/articles.json` | Copie temporaire des seuls articles récents pour les anciens composants |

Chaque synchronisation classe les publications par date, élimine les URL en doublon et retire des fichiers courants les articles âgés de plus de 365 jours ou dépassant les 1 000 plus récents. La date de publication est utilisée ; si elle est absente, la date de collecte sert de repli. Ces règles ne suppriment pas les anciens objets de l’historique Git.

Le portfolio Framer télécharge **uniquement recent.json au démarrage**. Il récupère archives.json seulement lorsque le lecteur choisit l’onglet Archives. Recherche, filtres, tri et pagination fonctionnent sur chaque vue.

## Gravité des bulletins de sécurité

Le tableau de veille présente un **tag Gravité** et un filtre sur les actualités récentes et les archives. Il distingue l'évaluation technique d'une vulnérabilité des informations générales et ne présente jamais une estimation IA comme un score officiel.

- **Critique :** CVSS 9,0–10,0
- **Élevée :** CVSS 7,0–8,9
- **Modérée :** CVSS 4,0–6,9
- **Faible :** CVSS 0,1–3,9
- **Aucune :** CVSS 0,0
- **Non évaluée :** bulletin de sécurité sans score fiable déjà récupéré (données manquantes, CVE en attente de consultation ou absence de métrique disponible). Ce statut n'indique pas un faible risque.
- **Information :** actualité technologique sans bulletin de sécurité identifié.

Référence : [FIRST CVSS v4.0](https://www.first.org/cvss/specification-document) (bornes qualitatives également utilisées pour CVSS v3.x).

**Règles de sécurité et traçabilité :** la gravité n'est jamais inventée par Gemini. Le système cherche des CVE dans le flux RSS et dans les **bulletins officiels Debian/CERT-FR**, puis interroge l'API **NVD 2.0** pour les scores CVSS v3.x/v4.0. Chaque score utilisé est associé à **une CVE identifiée, sa source NVD/CVSS et un lien de vérification**. Lorsqu'un avis contient plusieurs CVE, le badge correspond au **plus haut score parmi les CVE effectivement consultées** et affiche sa couverture (CVE consultées / identifiées). Une couverture partielle ne représente pas la gravité officielle de tout l'avis. À défaut de métrique, « Non évaluée » n'implique pas un faible risque.

La consultation NVD est limitée à **14 requêtes par workflow**, espacées d'au moins **7 secondes** sans clé (quota prudent), et les résultats sont conservés dans `site/data/cvss-cache.json` pour réduire les appels. Les résultats positifs sont revérifiés au bout de 14 jours, les CVE sans métrique au bout de deux jours. Le script évite les requêtes vers des domaines externes non approuvés. Une panne NVD n'interrompt pas le flux RSS : les scores déjà sourcés restent affichés avec leur date de vérification.

Champs publiés : `severity`, `severity_basis`, `cvss_score`, `cvss_version`, `severity_cve`, `severity_source`, `severity_source_url`, `cve_ids`, `cve_checked_count`, `cve_identified_count`, `severity_coverage`. Le score CVSS est une caractéristique de la vulnérabilité : il ne mesure pas le risque réel pour une infrastructure donnée.

## Collecte et intelligence artificielle

- Sources : CERT-FR alertes et avis, **Debian Security Advisories (DSA)**, Docker, Kubernetes, Cloudflare, Linux Kernel, **Microsoft Windows IT Pro Blog** (Windows, Windows Server, administration et sécurité). Le flux Debian officiel est `https://www.debian.org/security/dsa-long`.
- Jusqu’à **8 nouveaux articles par exécution** et **3 par source** ; sélection **équilibrée par rotation entre les sources (round-robin)** afin que les flux moins fréquents, notamment Windows IT Pro, ne soient pas masqués par les autres ; classification SISR (dont une catégorie **Windows** dédiée) et déduplication.
- Gemini produit un résumé factuel en français si disponible. Sinon la description RSS est conservée et indiquée comme `summary_kind: extrait`.
- Aucun secret dans les données publiques : la clé `GEMINI_API_KEY` reste dans les GitHub Actions Secrets. `NVD_API_KEY` est facultative, **non nécessaire** pour le fonctionnement à cadence limitée.
- En cas d’échec de tous les flux RSS, le script échoue sans écraser les données existantes. Les erreurs partielles sont consignées.
- Migration automatique des données historiques de `articles.json` lors de la première exécution de la nouvelle version.

## Retrait de la source Ubuntu Security (novembre 2026)

La source Ubuntu Security a été désactivée, remplacée par les **Debian Security Advisories** publiées par l'équipe sécurité de Debian. Le système refuse désormais les anciens enregistrements dont `source = Ubuntu Security` ou dont l'URL correspond à un avis `ubuntu.com/security/notices/`. Cette règle s'applique aussi aux articles déjà présents dans `recent.json` et `archives.json`. Les JSON publics sont régénérés lors de l'exécution GitHub Actions, sans intervention dans Framer.

La source Debian publie les bulletins de sécurité dans un **flux RDF/RSS 1.0**. Les liens des articles renvoient vers les annonces officielles `lists.debian.org`, avec possibilité de vérifier les CVE/NVD lorsque les preuves sont disponibles. Un score CVSS absent reste **Non évaluée**, jamais une estimation IA.

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
4. Aucune nouvelle clé API n'est nécessaire. En option : créer `NVD_API_KEY` dans les Secrets si un quota supérieur devient utile.

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
