# Sécurité web Challenges

## 1. File path traversal, validation of file extension with null byte bypass

Lien:
https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

Le titre indique une faille liée au null byte, et le contenu montre que la vulnérabilité est aussi au niveau du chemin des images.

Donc j'intercepte le chargement des images avec Burp.

Requête de base :

```
GET /image?filename=38.jpg
```

En testant, je remarque que je peux modifier le paramètre filename et ajouter un path traversal.
Je tente :

```
../../../../../../../etc/passwd%00.jpg
```

Le %00 correspond au null byte, ce qui permet de stopper la lecture réelle du nom de fichier après /etc/passwd, tout en gardant .jpg pour passer la validation.

Payload :

```
GET /image?filename=../../../../../../../etc/passwd%00.jpg
```
Pour sécurisé :
- Éviter d'utiliser directement la valeur fournie par l'utilisateur dans une fonction
- 