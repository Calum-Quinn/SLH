# Q1: Lesquelles des affirmations suivantes sont vraies ou fausses ? 

## Q1.1: L'*Autorité* peut *accéder* à *toutes les informations* médicales si elle le désire

**FAUX** L'Autorité ne stocke aucune donnée médicale et n'a pas accès aux serveurs de stockage. Elle ne fait que délivrer des biscuits signés lors de l'enregistrement des utilisateurs. Les données médicales sont stockées uniquement chez les fournisseurs et l'Autorité n'interagit pas avec eux pour accéder aux données.


## Q1.2: L'*Autorité* peut *déterminer* avec *quel médecins* un patient *partage* ses données

**FAUX** Selon l'architecture (Fig. 1, étape 3), le patient peut atténuer son biscuit et le transmettre directement à son médecin, sans interaction avec l'Autorité. L'atténuation se fait localement côté patient et l'Autorité n'est jamais informée de ces partages.


## Q1.3: Un *fournisseur* peut *déterminer* tous les *médecins* avec lesquels un patient *partage ses données*

**FAUX** Le fournisseur ne peut voir que les accès effectivement réalisés (lorsqu'un médecin utilise son biscuit atténué pour accéder aux données). Il ne peut pas savoir combien de biscuits atténués le patient a créés ni à qui il les a distribués, seulement qui a effectivement accédé à ses données.


## Q1.4: Un *médecin* peut *partager des données* auquelles il a accès *autre médecin*, *sans* le *consentement* du patient.

**VRAI** Les biscuits peuvent être atténués par n'importe quel détenteur. Un médecin qui possède un biscuit atténué peut le partager ou l'atténuer davantage pour le transmettre à un autre médecin, sans que le patient n'en soit informé ou ne donne son consentement. C'est une propriété inhérente au système des biscuits.


# Q2: *Quelle URL* pouvez-vous utiliser pour enregistrer un médecin ? Sous *quelle CWE* pourrait-t-on classer cette vulnérabilité ?

URL: `POST /register?doctor=true`

En examinant le code dans `bin/directory.rs` ligne 95-103, la route `/register` accepte un paramètre optionnel `doctor` qui, s'il est fourni à `true`, permet de s'enregistrer directement en tant que médecin sans validation manuelle.

CWE-862 (Missing Authorization) - L'endpoint ne vérifie pas l'autorisation pour créer un compte médecin, permettant à n'importe qui de s'auto-attribuer ce rôle privilégié.


# Q3: *que contient le message* envoyé par le serveur au client, *que contient la réponse* en cas de succès, et *que fait le client* avec la réponse ?

Message envoyé au serveur (karamel.rs:156-157): Un objet `Login` contenant le nom d'utilisateur (`user`) et le mot de passe (`password`) en clair.

Réponse en cas de succès (directory.rs:92): Un objet `LoginResponse` contenant:
- `uid`: l'identifiant unique de l'utilisateur
- `token`: un biscuit signé encodé en base64, contenant les faits datalog `user({uid})` et `is_doctor({uid}, {is_doctor})`

Traitement par le client (karamel.rs:168): Le client sauvegarde le token (biscuit) dans un fichier local (par défaut `.karamel-token`) pour l'utiliser lors des futures requêtes aux services de stockage.


# Q4: Pour assurer la *confidentialité* des *mots de passe* pendant le processus de login, quelle *fonctionnalité essentielle* devrait absolument être *ajoutée* avant de déployer ce code en *production* ?

TLS/HTTPS (chiffrement de la couche transport). Actuellement, le mot de passe est envoyé en clair dans la requête HTTP. Sans TLS, n'importe qui interceptant le trafic réseau peut lire le mot de passe. Il est essentiel d'utiliser HTTPS pour chiffrer toutes les communications entre le client et le serveur d'autorité.


# Q5: Comment la *clé publique* de l'*autorité* est-elle *passée* au processus du serveur de *stockage* ?

La clé publique est passée via un fichier (out-of-band). Le serveur d'autorité exporte sa clé publique dans le fichier `./pubkey.bin` au démarrage (directory.rs:137-141). Le serveur de stockage lit ensuite cette clé publique depuis ce même fichier au démarrage (store.rs:126-131). Il s'agit d'un échange hors-bande via le système de fichiers, correspondant à l'étape 0 de l'architecture (Fig. 1).


# Q6: `read_report` dans `bin/store.rs` renvoie une erreur 404 si l'ID du rapport demandé n'existe pas, *avant* de procéder à la décision d'autorisation. *Est-ce un problème ?* *Justifier*.

Oui, c'est un problème. Cela crée une vulnérabilité de divulgation d'information (information disclosure). Un attaquant peut distinguer:
- 404 → le rapport n'existe pas
- 403 (Forbidden) → le rapport existe mais l'attaquant n'a pas accès

Cela permet d'énumérer les rapports existants dans le système, même sans y avoir accès. La bonne pratique serait de toujours effectuer la vérification d'autorisation d'abord, puis de retourner la même erreur (typiquement 403 ou 404) que le rapport n'existe pas ou que l'utilisateur n'y a pas accès, pour éviter cette fuite d'information.


# Q7: Le serveur d'autorité implémente un mécanisme de *défense* contre un *canal auxiliaire* pour empêcher l'énumération des utilisateurs. *Est-ce pertinent ?* *Justifier*.

Partiellement pertinent; le mécanisme (password.rs:57-66) utilise un hash vide (`EMPTY_HASH`) pour les utilisateurs inexistants, assurant que la vérification du mot de passe prend le même temps qu'un utilisateur existe ou non. Cela empêche les attaques par timing.

Cependant, cette défense est largement inutile car l'endpoint `/users` (directory.rs:53-64) expose publiquement la liste complète de tous les utilisateurs enregistrés. Un attaquant peut simplement appeler cet endpoint pour énumérer tous les comptes sans recourir à une attaque par canal auxiliaire. La défense serait pertinente si `/users` était protégé ou supprimé.


# Q8: *Listez* les noms des *faits datalog* disponibles pour effectuer l'autorisation, en *indiquant* ceux provenant du *biscuit* et ceux provenant du *contexte* de la requête

Faits provenant du biscuit (directory.rs:87):
- `user($uid)` - identifiant de l'utilisateur
- `is_doctor($uid, $boolean)` - indique si l'utilisateur est médecin

Faits provenant du contexte de la requête:

Pour les opérations sur les rapports (authorization.rs:55-77):
- `id($report_id)` - identifiant du rapport
- `author($user_id)` - auteur du rapport
- `patient($user_id)` - patient concerné par le rapport
- `report_time($date)` - date du rapport
- `keyword($set)` - ensemble de mots-clés du rapport

Pour les opérations sur les données patient (authorization.rs:79-91):
- `patient($user_id)` - identifiant du patient
- `blood_type($string)` - groupe sanguin
- `gender($string)` - genre

De plus, l'opération demandée est ajoutée via `operation($op_name)` (ex: "read-report", "write-patient", etc.)


# Q9: Par rapport à un système d'*ABAC*, y a-t-il des *limitations* sur la manière dont les *règles* d'accès peuvent dépendre du *contenu* d'un rapport ?

Oui, il y a des limitations. Dans l'implémentation actuelle, seules les métadonnées du rapport sont exposées comme faits datalog (authorization.rs:55-77): id, author, patient, report_time, et keywords. Le contenu textuel du rapport (`contents`) n'est pas ajouté aux faits.

Cela signifie qu'on peut créer des règles basées sur qui a écrit le rapport, pour quel patient, quand, et avec quels mots-clés, mais on ne peut pas créer de règles qui analysent ou dépendent du contenu textuel du rapport lui-même. Un système ABAC plus sophistiqué pourrait potentiellement extraire et analyser des informations du contenu pour prendre des décisions d'accès plus fines.


# Q11: Dans le système tel qu'il est implémenté, *que se passe-t-il* si un utilisateur *perd* ses *droits* de *médecin* ? Que proposez-vous pour *limiter le problème*, *sans modifier* la structure des *communications* entre les différentes parties ?

**Problème**: Si un utilisateur perd ses droits de médecin, les biscuits déjà émis avec `is_doctor($uid, true)` restent valides indéfiniment. L'utilisateur peut continuer à utiliser son ancien biscuit pour accéder aux données avec les privilèges de médecin, même après la révocation de ses droits dans la base de données de l'Autorité.

**Solution proposée**: Ajouter des dates d'expiration (TTL) aux biscuits lors de leur émission par l'Autorité. On pourrait ajouter un check dans le biscuit: `check if time($t), $t < {expiration_date}`. Cela force les utilisateurs à renouveler régulièrement leur biscuit. Lors du renouvellement, l'Autorité vérifie le statut actuel et émet un nouveau biscuit avec les droits à jour. Des biscuits de courte durée (ex: 24h) limitent la fenêtre d'exploitation après révocation.


# Q12: *Proposez* une *commande* pour créer un token attenué permettant l'accès à *chacun de ces cas*:


# Q12.1: *un seul rapport* en particulier

```bash
cargo run -- lock 'check if id($id), $id == hex:AABBCCDD...'
```
(Remplacer `AABBCCDD...` par l'UUID du rapport en hexadécimal)

# Q12.2:  *tous les rapports* concernant les problèmes de coeur (*keyword* "heart"), et *postérieurs* au *1er janvier 2010*

```bash
cargo run -- lock 'check if keyword($kw), $kw.contains("heart"), report_time($t), $t >= 2010-01-01T00:00:00Z'
```

# Q12.3: *tous les rapports* par un *médecin* particulier

```bash
cargo run -- lock 'check if author($a), $a == hex:11223344...'
```
(Remplacer `11223344...` par l'UUID du médecin en hexadécimal)

