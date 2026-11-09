# Veille technologique — BTS SIO SISR

RSS officiels → GitHub Actions (quotidien) → Python → Gemini API (optionnel) → JSON → GitHub Pages → Framer /veille.

## Configuration

1. Créer le secret Actions **GEMINI_API_KEY** dans Settings → Secrets and variables → Actions.
2. Dans Settings → Pages → Build and deployment, choisir **GitHub Actions**.
3. Lancer **Actions → Veille technologique quotidienne → Run workflow** pour une première synchronisation.
4. Flux public : https://berberin-2k.github.io/bts-sio-veille/data/articles.json

## Fonctionnement

- Jusqu'à 8 nouveaux articles par exécution, 3 maximum par source, 180 conservés.
- Sources : CERT-FR (avis, alertes), Ubuntu Security, Docker, Kubernetes, Cloudflare, Linux Kernel.
- Titre, source, date, résumé court, catégorie et lien original.
- Clé Gemini absente ou quota épuisé : extrait RSS utilisé avec `summary_kind: extrait`.
- Aucun flux disponible : l'exécution échoue sans écraser les données précédentes.
- Schedule : **06:17 Europe/Paris** (exécution susceptible de retard côté GitHub).
- GitHub peut désactiver les schedules des repos publics après 60 jours d'inactivité.
- Le fichier JSON est public. Aucun secret ne doit y être stocké.

## Tests

`python -m unittest discover -s tests -v`

`python scripts/collect.py` (accès réseau requis ; Gemini optionnel).

## Méthodologie

Veille automatisée via liste fixe de flux officiels, déduplication par URL, sélection chronologique, classification et synthèses neutres en français. Les résumés produits par IA ne constituent ni une analyse personnelle ni une validation des informations. Toujours consulter les publications originales.
