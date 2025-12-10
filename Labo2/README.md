<!--
vim: spelllang=fr
-->
# SLH 2025 - Lab #2

- Laboratoire noté.
- Veuillez rendre **votre code** et le **README.md** répondant aux questions du
  chapitre `Question`.
- La qualité du code est notée.
- Le code doit obligatoirement être écrit en Rust.
- La **validation des entrées** est primordiale.
- Nous nous attendons à ce que vous testiez votre code.
- Vous trouverez dans le code fourni les fichiers à remplir. La partie frontend
  est déjà fournie dans son entièreté.
- La crate `openssl` nécessite d'avoir `openssl-dev` d'installé.
- **Ne pas modifier la version des dépendances de `cargo.toml`**. Vous pouvez
  cependant ajouter des crates si nécessaire.

## Description

Le but de ce laboratoire est de gérer l'authentification d'un site web.
L'authentification doit être gérée à travers le protocole OAuth2[^1] avec GitHub[^2]
et la crate `rocket_oauth2`[^3].
Les fonctionnalités du site sont les suivantes :

- Connexion avec un nouveau compte.
- Connexion à un compte existant.
- Publier une image et une courte description.

[^1]: <https://oauth.net/2/>
[^2]: <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app>
[^3]: <https://lib.rs/crates/rocket_oauth2>

## Rendu

Le `README.md` contenant les réponses aux questions et le code source dans une archive `.crate`.

Pour générer l'archive avec le code source, la commande :

```sh
cargo package
```

Génère l'archive dans le répertoire `target/package/`.

## Questions

> Répondez aux questions directement dans ce fichier là.

1. Quel serait l'impact si on se fait voler notre secret client (et client id) ?

   **Réponse:** Si un attaquant obtient le client_id et le client_secret, il peut :
   - Créer une application malveillante qui se fait passer pour notre application légitime
   - Demander des autorisations OAuth2 au nom de notre application aux utilisateurs
   - Potentiellement obtenir des tokens d'accès pour les utilisateurs qui autorisent l'application malveillante
   - Compromettre la réputation de notre application
   - Voler des données utilisateurs si les utilisateurs accordent les permissions à l'application malveillante
   - GitHub pourrait révoquer les credentials si un usage abusif est détecté, ce qui bloquerait notre application légitime

2. Comment peut-on protéger notre secret client, afin d'éviter qu'il soit publier ou voler ?

   **Réponse:** Plusieurs mesures de protection :
   - **Variables d'environnement:** Stocker le secret dans des variables d'environnement plutôt que dans le code source
   - **Fichiers de configuration exclus:** Ajouter les fichiers de configuration contenant les secrets au `.gitignore`
   - **Gestionnaires de secrets:** Utiliser des solutions comme HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
   - **Rotation régulière:** Changer périodiquement le client_secret
   - **Accès restreint:** Limiter l'accès aux secrets uniquement aux personnes et systèmes qui en ont besoin
   - **Chiffrement au repos:** Stocker les secrets chiffrés dans les bases de données ou fichiers
   - **Audit et monitoring:** Surveiller l'utilisation des secrets pour détecter des comportements anormaux
   - **Ne jamais commiter:** Vérifier avec des outils comme git-secrets ou pre-commit hooks qu'aucun secret n'est commité
   - **Utiliser HTTPS:** Toujours transmettre les secrets via des connexions sécurisées

3. Quels est la différences entre OAuth2 et LDAP ?

   **Réponse:** OAuth2 et LDAP ont des objectifs différents :

   **OAuth2:**
   - **Protocole d'autorisation déléguée:** Permet à une application d'accéder aux ressources d'un utilisateur sans connaître son mot de passe
   - **Délégation d'accès:** L'utilisateur autorise une application tierce à accéder à ses données
   - **Basé sur des tokens:** Utilise des access tokens temporaires avec des scopes limités
   - **Stateless:** Les tokens peuvent être validés sans interroger constamment le serveur d'autorisation
   - **Cas d'usage:** Intégrations avec des services tiers, Single Sign-On (SSO), APIs REST

   **LDAP:**
   - **Protocole d'authentification et d'annuaire:** Permet de stocker et interroger des informations d'utilisateurs dans un annuaire centralisé
   - **Authentification directe:** Le serveur vérifie directement les credentials (username/password)
   - **Annuaire hiérarchique:** Organise les données sous forme d'arbre (DN, OU, etc.)
   - **Stateful:** Nécessite une connexion au serveur LDAP pour chaque authentification
   - **Cas d'usage:** Gestion d'annuaire d'entreprise, authentification interne, gestion centralisée des utilisateurs

4. Est-ce que le mot de passe transite par votre serveur ? Est-ce qu'on peut le voler ?

   **Réponse:** **Non**, le mot de passe GitHub ne transite **jamais** par notre serveur. Voici le flux OAuth2 :

   1. L'utilisateur clique sur "Se connecter avec GitHub" sur notre site
   2. Notre serveur redirige l'utilisateur vers GitHub (avec client_id et scopes)
   3. **L'utilisateur entre son mot de passe directement sur le site de GitHub** (pas sur notre serveur)
   4. GitHub authentifie l'utilisateur et lui demande d'autoriser notre application
   5. GitHub redirige l'utilisateur vers notre serveur avec un code d'autorisation temporaire
   6. Notre serveur échange ce code contre un access token en communiquant directement avec GitHub
   7. Notre serveur utilise l'access token pour récupérer les informations de l'utilisateur

   **Sécurité:** C'est un des avantages majeurs d'OAuth2. Même si notre serveur est compromis, l'attaquant ne peut pas voler les mots de passe GitHub des utilisateurs car ils ne transitent jamais par notre infrastructure. Seul l'access token est présent sur notre serveur, et celui-ci a une portée limitée (scopes) et peut être révoqué.

5. Si vous êtes mal intentionné et que vous administrez un serveur utilisant l'OAuth2 Github. Comment ferriez-vous pour obtenir plus d'accès au nom de vos utilisateur ? Et donnez des exemples.

   **Réponse:** Un administrateur malveillant pourrait :

   **1. Demander des scopes excessifs:**
   - Au lieu de demander uniquement `user:read`, demander `repo`, `delete_repo`, `admin:org`, etc.
   - Exemple: Modifier le code pour demander `["user:read", "repo", "delete_repo"]` lors de l'authentification
   - Les utilisateurs peu attentifs pourraient accepter sans lire les permissions demandées

   **2. Modifier l'application après autorisation:**
   - Initialement demander des scopes minimaux pour gagner la confiance
   - Plus tard, demander aux utilisateurs de se reconnecter en demandant plus de scopes
   - Les utilisateurs habitués à l'application feront moins attention

   **3. Utiliser les tokens pour des actions non légitimes:**
   - Voler les access tokens stockés sur le serveur
   - Utiliser ces tokens pour accéder aux repos privés, modifier du code, créer des issues, etc.
   - Exemple: Accéder à `https://api.github.com/user/repos` pour lister tous les repos privés

   **4. Phishing via la redirection:**
   - Créer une fausse page de consentement qui ressemble à GitHub
   - Voler directement les credentials au lieu d'utiliser OAuth2

   **5. Stocker et exploiter les données:**
   - Garder les access tokens même après que l'utilisateur se déconnecte
   - Continuer à accéder aux ressources GitHub de l'utilisateur en arrière-plan

6. Pour les 2 captures d'écran d'écran de consentement de google, indiqué quels
   scopes on probablement été demander par le site web.

   - [image 1](scope-01.png) ![](scope-01.png) ![](../../../scope-01.png)
   - [image 2](scope-01.png) ![](../../../scope-02.png) ![](scope-02.png)

   Scopes possible (dans l'ordre alphabétique):
   - `email`
   - `https://example.com/all`
   - `https://www.googleapis.com/auth/documents`
   - `https://www.googleapis.com/auth/drive.file`
   - `https://www.googleapis.com/auth/drive.photos.readonly`
   - `https://www.googleapis.com/auth/drive.readonly`
   - `https://www.googleapis.com/auth/drive`
   - `https://www.googleapis.com/auth/gmail`
   - `openid`
   - `profile`

   **Réponse:**

   **Image 1 (scope-01.png):** L'écran montre deux permissions demandées :
   - "Se connecter à votre Google Drive" → `https://www.googleapis.com/auth/drive`
   - "Consulter, modifier, créer et supprimer uniquement les fichiers Google Drive spécifiques que vous utilisez avec cette application" → `https://www.googleapis.com/auth/drive.file`

   **Scopes demandés pour l'image 1:**
   - `https://www.googleapis.com/auth/drive`
   - `https://www.googleapis.com/auth/drive.file`
   - `openid` (implicite pour l'authentification OAuth2)
   - `profile` (implicite, car affiche "Name and profile picture" dans image 2)

   **Image 2 (scope-02.png):** L'écran montre uniquement :
   - "Name and profile picture" → Informations de profil basiques

   **Scopes demandés pour l'image 2:**
   - `openid` (requis pour l'authentification OpenID Connect)
   - `profile` (pour obtenir le nom et la photo de profil)

## Tâches principales

Pour lancer l'application vous devez être dans le même répertoire que `Cargo.toml` :

```sh
…$ ls -A
Cargo.lock  Cargo.toml  data  image  README.md  Rocket.toml  scope-01.png  scope-02.png  src  target  templates  tests
…$ cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running `target/debug/lab02-2025`
🔧 Configured for debug.
   >> address: 127.0.0.1
…
```

Compléter toutes les parties marquées dans le code. La commande `cargo test` affiche la liste des fichiers contenant encore des éléments à compléter.

## Fournisseur OAuth2

Le fournisseur OAuth2 pour ce labo est Github; La création des token se passe sur la page : <https://github.com/settings/developers>.
