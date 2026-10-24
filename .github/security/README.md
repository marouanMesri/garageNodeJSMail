# Kit de contrôles GitHub — revue locale du 24 octobre 2026

Aucune installation distante ni mutation GitHub effectuée. Ce kit vise une nouvelle base dont le seul writer est le propriétaire. Il n'est pas une frontière absolue contre un writer ou un administrateur hostile.

## GitHub Free et statuts à utiliser

- Dépôts privés sur Free : CI **informative** ; aucune protection de branche privée prétendue disponible. Les minutes Actions incluses et leurs limites continuent de s'appliquer.
- Dépôts publics sur Free : protections possibles après test. Exiger les contextes REST **`security/payloads`** et **`security/owner-review`**, une PR et une branche à jour. Ne pas exiger le job `guardrails` en pensant qu'il est automatiquement lié au HEAD de la PR.
- PR de `marouanMesri` : contrôles automatiques, sans auto-approbation impossible. PR d'un autre auteur : dernière revue formelle de marouanMesri APPROVED pour le HEAD actuel. Pas de review universelle native obligatoire qui bloquerait le propriétaire solo.
- Aucun PAT supplémentaire, secret métier, App indépendante ou abonnement payant requis. Le jeton automatique reçoit uniquement contents/read, pull-requests/read et statuses/write ; le rafraîchissement ajoute actions/read pour vérifier le relais.

## Fichiers à installer après validation

Les trois `security*.yml` vont dans `.github/workflows/`. Les scripts `.py`, `policy_exceptions.json`, `gitleaks.toml` et les fichiers de licence/provenance vont dans `.github/security/`. Les tests sont eux aussi issus de la base fiable. Tous ces emplacements de contrôle et les trois emplacements CODEOWNERS sont protégés contre des changements dans une PR ordinaire.

## Flux de confiance

1. `security.yml` utilise `pull_request_target`. Depuis la modification GitHub de décembre 2025, ce workflow et GITHUB_SHA viennent de la branche par défaut. Le checkout explicite utilise ce SHA fiable, pas un ancien workflow de la branche ciblée. Les PR vers une autre branche sont refusées par ce kit.
2. Le publisher met les deux contextes en attente sur **`pull_request.head.sha`**. Il relit les métadonnées GitHub et vérifie auteur, HEAD, base et branche par défaut.
3. Les objets PR sont récupérés par Git sans checkout, sous-module, LFS, hooks ou filtre de conversion. Le HEAD récupéré et la base fiable doivent correspondre aux SHA attendus. Aucun code/configuration/dépendance de PR n'est importé, testé comme application ou exécuté.
4. Le scanner fiable examine le HEAD complet et les arbres intermédiaires nouveaux de la PR, merges inclus. Il ne suit ni `.gitignore`, répertoire caché, `vendor`, `node_modules`, fichier d'ignore Gitleaks ou configuration de PR. Les modes et chemins sont vérifiés ; liens et gitlinks bloquent. Les fichiers de contrôle modifiés puis restaurés restent signalés.
5. Tous les textes UTF-8 et UTF-16 avec BOM analysés sont concaténés dans un fichier temporaire privé, avec un index chemin/commit/hash/lignes. Les fichiers ajoutés puis supprimés sont donc aussi transmis à Gitleaks. Pas de limite silencieuse à dix Mo dans son mode répertoire : il reçoit **stdin**, sa configuration de base et un ignore vide.
6. Gitleaks 8.30.1 est téléchargé depuis la release officielle et vérifié par le SHA-256 épinglé. Le wrapper ne publie que règle, chemin, ligne et commit ; aucun Match, Secret, corps de réponse ou extrait de PR. Les commentaires de bypass sont désactivés.
7. Le publisher final associe le résultat au HEAD exact, après relecture des métadonnées. Il ne transforme pas un échec, une annulation ou un changement de base en succès.
8. Si GitHub a créé un commit de test de fusion, le publisher y reporte aussi les contextes **uniquement si son arbre est identique à celui du HEAD scanné et ses parents correspondent aux HEAD/base attendus**. Un arbre différent reçoit un échec demandant une mise à jour de branche. Cela couvre la sélection HEAD/test-merge des contrôles obligatoires sans déclarer scanné un arbre différent.

## Recalcul après une revue

`security-review-signal.yml` écoute les revues soumises, éditées et révoquées. Son job ne fait qu'émettre un signal fixe : aucun checkout, action externe, secret, artifact ou permission d'écriture. Sa définition peut provenir de la PR, aussi aucune décision de sécurité n'en est acceptée.

`security-review-refresh.yml` est déclenché sur requested/completed de ce relais, via `workflow_run`, et s'exécute depuis la branche par défaut. Il vérifie via l'API le type d'événement et le chemin exact du workflow relais, ne télécharge aucun artifact/cache, et relit les PR/revues courantes. Il remet les contextes review en attente, puis recalcule l'approbation. Un déclenchement manuel depuis la branche par défaut est disponible pour réparer un événement manqué.

Le rafraîchissement parcourt les PR ouvertes (moins de 100), sans se fier à un artifact ou à un tableau `pull_requests` qui peut manquer pour certains forks. Les décisions de plusieurs PR partageant le même HEAD sont agrégées de façon conservatrice : une PR externe non approuvée empêche le succès de ce HEAD. Un nouveau push nécessite une revue sur le nouveau HEAD. Le dernier état formel révoqué ou CHANGES_REQUESTED échoue ; un simple commentaire n'efface pas une approbation.

## Exceptions exactes et protégées

`policy_exceptions.json` est initialement **vide**. Il est lu depuis le dossier du scanner fiable. Toute modification de ce fichier dans une PR ordinaire est bloquée. Chaque entrée exige `kind` (`payload` ou `secret`), `rule`, `path`, SHA-256 des **octets originaux complets**, et `reason` documentant la revue.

Une exception de cycle de vie exige aussi `command`, identique à la valeur du script package. Par exemple, un prebuild Material-UI ou un prepare légitime peut être accepté pour son manifeste exact ; un seul octet changé, un autre chemin, une autre règle ou commande annule l'exception. Une exception de secret s'applique au fichier exact et à une règle fournisseur précise : auditer **tout le fichier** pour cette règle, pas uniquement le premier résultat public. Aucune valeur secrète ne doit être copiée dans cette politique.

Seules les règles génériques de maintenance prévues peuvent recevoir une exception payload. Les hashes malveillants connus, faux assets exécutables, liens/sous-modules et changements des contrôles ne sont pas dérogeables. Pas d'exclusion globale d'un vendor ou d'une extension, pas d'allowlist chargée depuis la PR. Les décisions approuvées pour les vingt-huit autres candidats doivent être ajoutées par la coordination à la base contrôlée, pas inventées ici.

Un faux positif lexical existe dans certains scanners défensifs déjà présents dans les candidats. Ne pas ignorer leur chemin globalement : réécrire de façon équivalente la regex défensive ou auditer une exception règle/chemin/hash exact. Les candidats externes ne sont pas modifiés par cette revue.

## Faux assets et fixtures

Les octets sont vérifiés avant décodage : hash connu du `.llf` de 14 871 octets, en-têtes WOFF/WOFF2/TTF/OTF/EOT et primitives JavaScript dans les extensions de police ou `.llf`. Les artefacts de propagation et tâches folder-open sont signalés. Les fixtures sont des marqueurs inertes assemblés en mémoire ; aucune charge réelle n'est stockée dans les tests.

Le kit entier, tests compris, est scanné dans un dépôt synthétique sans exception. La règle Bedrock officielle contenant littéralement son propre préfixe a été réécrite avec un groupe non capturant équivalent. Le préfixe reste détecté par un test ; le fichier de configuration reste dans le périmètre.

## Limites à conserver visibles

- Revue réévaluée **après événement**, pas transaction atomique au moment de fusionner. Délais de file, événements/permissions manquants, dépassement de quota, panne API ou courses entre lecture et publication peuvent laisser temporairement un statut ancien. Aucun polling permanent ni promesse d'invalidation instantanée.
- Moins de 100 PR ouvertes, au plus 1 000 revues par PR, 200 commits PR, 200 000 entrées et 1 Go cumulé. Un fichier de plus de **50 000 000 octets bloque**, quelle que soit son extension. Une commande Git dure au plus 90 s ; Gitleaks 300 s ; job principal 20 min. Les limites ne sont pas transformées en succès.
- Les binaires/encodages non pris en charge ont un gap explicite, même si leur format/hash est vérifié ; ils ne deviennent pas des textes analysés exhaustivement pour les secrets. Archives non décompressées, LFS non téléchargé. Aucun audit exhaustif des dépendances ou antivirus promis.
- Les statuts partagent l'origine GitHub Actions avec d'autres workflows. Un writer doté de droits Actions/statuts, une App autorisée ou un administrateur peut affaiblir ce modèle. Le propriétaire seul comme writer, des permissions minimales et l'audit des autres workflows sont des préconditions importantes.
- La maintenance légitime des contrôles est bloquée aussi. Prévoir une procédure propriétaire temporaire, ciblée et tracée, testée séparément ; pas de bypass permanent donné aux bots.
- Aucun historique distant, cache, backup, poste développeur ou secret déjà exposé n'est purgé ou révoqué par ce kit.

## Avant installation

Tester d'abord dans le dépôt privé éphémère prévu : statuts sur le HEAD et sur un test-merge de même arbre, fixture rejetée, secret ajouté puis supprimé, modification d'ignore/config PR, contrôle altéré, fork, approbation, révocation et nouveau push. Vérifier les permissions exactes de l'API et les chemins de workflows.

Ce test privé ne prouve pas une protection native indisponible sur Free. Avant d'exiger ces contextes sur les dépôts publics, vérifier leur source et le comportement réel des contrôles obligatoires (HEAD/test-merge), sans confondre un job vert attaché à la base et les statuts publiés explicitement. Consulter `REVIEW_POLICY.md` et `TEST_RESULTS.md`.

## Documentation primaire relue

- [Événements et contexte de confiance](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).
- [Usage sûr de pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
- [Statuts de commit REST](https://docs.github.com/en/rest/commits/statuses).
- [HEAD et test-merge pour les contrôles obligatoires](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).
- [Protections disponibles sur GitHub Free](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
- [Politique d'exécution des workflows](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/administer/control-workflow-execution).

La dernière page annonce actuellement l'application d'une politique publique bloquant par défaut pull_request_target le **2 décembre 2026**, et non le 2 novembre figurant dans la version précédente de ce kit. Vérifier les règles effectivement applicables au compte avant installation ; aucune exception distante n'est activée ici.
