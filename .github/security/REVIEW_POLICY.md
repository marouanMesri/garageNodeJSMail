# Politique conditionnelle — GitHub Free, propriétaire solo

PR de marouanMesri : scans automatiques. Autre auteur : approbation de marouanMesri sur le HEAD courant, en plus des scans. Une review universelle native bloquerait le propriétaire qui ne peut pas approuver sa propre PR ; elle n'est pas proposée.

Les protections sont prévues uniquement pour les dépôts publics sur Free. Dans les privés, ces mêmes résultats sont informatifs et ne sont pas présentés comme une interdiction de fusion.

Deux contextes REST sont publiés explicitement : `security/payloads` et `security/owner-review`. Le job pull_request_target ne suffit pas à attester le HEAD, car son SHA est celui de la branche par défaut. Le publisher vérifie les métadonnées, publie sur le HEAD et, si nécessaire, sur le commit de test-merge seulement lorsque son arbre est identique au HEAD scanné et ses parents correspondent. Autrement, le test-merge reçoit un échec.

Le recalcul de revue est déclenché après submitted/edited/dismissed par un relais sans checkout ni privilège, puis workflow_run lit les contrôles de la branche par défaut. Aucun artifact de la PR n'est consommé. L'API confirme le type et le chemin du relais ; ses conclusions ne sont jamais considérées comme une approbation. Le rafraîchissement manuel permet de réparer un événement manqué. Les contextes en attente précèdent la nouvelle évaluation.

Ce mécanisme réduit la période de statut périmé ; il ne fournit pas de transaction atomique avec la fusion. Une panne API, un événement non exécuté ou une course peut laisser temporairement un ancien état. Vérifier l'approbation courante dans l'interface au moment de fusionner une PR externe. Pour une vraie barrière contre un writer hostile, il faudrait un contrôle indépendant ou une protection native compatible ; aucune App payante ou garantie de ce type n'est ajoutée.

Préconditions : nouvelle racine contrôlée, propriétaire seul comme writer, autres workflows audités, tokens de fork non promus en écriture, contrôles `.github/security` et `.github/workflows` protégés, pas de bypass permanent des bots. Les changements ordinaires de contrôles sont refusés, même annulés plus tard. Une maintenance propriétaire exceptionnelle doit être temporaire, revue et tracée.

Les tests locaux vérifient états de revue, HEAD/base obsolètes, auteur propriétaire, rejet des autres approbateurs, publication au bon SHA, test-merge différent et intégrité des contrôles. Ils n'émettent aucun statut ni revue GitHub. Le test réel dans le dépôt privé éphémère reste à exécuter, puis le comportement des protections publiques à valider.

Sources : [événements](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [API statuts](https://docs.github.com/en/rest/commits/statuses), [contrôles requis](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks), [GitHub Free](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
