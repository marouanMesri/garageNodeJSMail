# Vérifications locales — 24 octobre 2026

La suite finale comprend 58 tests : 31 payloads/Git/fixtures, 8 décisions de revue, 8 statuts HEAD/test-merge et 11 intégrations Gitleaks. Résultats détaillés et logs expurgés : `../reports/guardrails-review/` dans la préparation locale. Ces tests ne contactent ni ne modifient GitHub.

- Dépôts Git synthétiques jetables : historique intermédiaire, fichier supprimé, merge, altération puis restauration des contrôles, liens, sous-modules, noms et modes, limites de couverture et export sans exécution.
- Assets opaques : fixture JavaScript inerte en .llf, en-tête de police invalide et vérification du mécanisme de hash connu avec un spécimen factice. Aucun vrai payload de malware.
- Gitleaks 8.30.1 installé localement : stdin de textes, secrets factices sous dossiers cachés/vendor/lockfiles, ignores/configs PR inopérants, marqueur ajouté puis supprimé, ligne longue, redaction, exception de hash exact et refus d'une exception couvrant deux blobs.
- Le kit et ses propres fixtures restent dans le périmètre des scans, sans exception globale. La règle Bedrock reste détectante après sa réécriture équivalente.
- Statuts API simulés : bon HEAD, base distincte, annulation/échec, HEAD/base déplacés, propriétaire solo, approbation, dismissal, revue obsolète, mauvais relais et arbre de test-merge différent.
- Syntaxe des trois YAML vérifiée par le parseur système. Les arguments, permissions et références de confiance sont relus ; cela ne remplace pas l'exécution réelle du workflow GitHub.

Aucun npm/pip, code de cible, configuration de PR, conteneur, stage réseau, artifact ou script de package exécuté. Les commandes Git font seulement fonctionner des fixtures écrites par ces tests avec hooks désactivés. Aucun vrai secret dans les fixtures.

Le binaire Linux destiné à CI reste épinglé par version et SHA-256 dans le workflow ; les tests locaux utilisent le binaire macOS installé et son empreinte est enregistrée séparément. Ils ne prouvent pas l'authenticité de ce binaire par une nouvelle vérification de l'archive Linux.

À faire dans le dépôt privé éphémère : permissions réelles GITHUB_TOKEN, exécution du relais review et workflow_run, statuts sur HEAD et test-merge, fork et nouveau push. Sur GitHub Free ce dépôt privé n'a pas de protection native prétendue. Les contrôles obligatoires et leur source attendue doivent ensuite être validés sur un dépôt public avant généralisation.

Pas de garantie d'invalidation instantanée, d'absence de malware inconnu, de secret encodé/binaire, de dépendance compromise ou d'immunité à un writer hostile.
