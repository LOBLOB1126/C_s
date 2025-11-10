# Application Web Sécurisée avec PostgreSQL

## 📚 Mémoire : Conception et Sécurisation d'une Application Web

### Problématique

Comment concevoir une application web dynamique tout en garantissant la sécurité des données stockées et échangées entre le client et le serveur ?

---

## 🎯 Objectifs du Projet

Cette application démontre l'implémentation de mécanismes de sécurité essentiels dans une application web moderne, en abordant les principales vulnérabilités identifiées par l'OWASP Top 10.

### Fonctionnalités Sécurisées Implémentées

- ✅ **Authentification sécurisée** avec hachage bcrypt (12 rounds)
- ✅ **Vérification email** avec codes à usage unique
- ❌ **Vérification téléphone** (infrastructure SMS)
- ✅ **Authentification à deux facteurs (2FA)** avec QR codes
- ✅ **Contrôle d'accès basé sur les rôles (RBAC)** : Admin, Moderator, User
- ✅ **Protection contre les injections SQL** (requêtes paramétrées)
- ✅ **Validation et sanitisation des entrées**
- ✅ **Protection de la console JavaScript**
- ✅ **Rate limiting** (limitation du nombre de requêtes)
- ✅ **Gestion des sessions sécurisée**
- ✅ **Audit trail** (logs de sécurité)
- ✅ **En-têtes HTTP sécurisés** (Helmet)
- ✅ **Protection reCAPTCHA** contre les bots
- ✅ **Système de permissions JSONB** pour une gestion fine des droits
- ✅ **Content Security Policy (CSP)** renforcée

---

## 🏗️ Architecture du Projet

```
C.S_S/
├── src/
│   ├── controllers/          # Logique métier
│   │   ├── auth.controller.js
│   │   ├── twofa.controller.js
│   │   ├── user.controller.js
│   │   └── admin.controller.js
│   ├── database/             # Configuration base de données
│   │   ├── db.js
│   │   ├── schema.sql
│   │   └── init.js
│   ├── middleware/           # Middleware de sécurité
│   │   ├── auth.middleware.js
│   │   ├── validator.middleware.js
│   │   └── security.middleware.js
│   ├── routes/               # Routes API
│   │   ├── auth.routes.js
│   │   ├── twofa.routes.js
│   │   ├── user.routes.js
│   │   └── admin.routes.js
│   ├── utils/                # Utilitaires
│   │   ├── auth.js
│   │   ├── email.js
│   │   ├── qrcode.js
│   │   └── logger.js
│   └── server.js             # Point d'entrée serveur
├── public/                   # Frontend
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── app.js
│       └── console-protection.js
├── package.json
├── .env.example
└── README.md
```

---

## 🔒 OWASP Top 10 - Implémentation des Protections

### 1. Injection (A03:2021)

**Vulnérabilité :** Les injections SQL permettent aux attaquants d'exécuter des commandes malveillantes dans la base de données.

**Protection implémentée :**

- ✅ Utilisation exclusive de **requêtes paramétrées** avec pg (PostgreSQL)
- ✅ Middleware de détection d'injection SQL dans les URLs
- ✅ Validation stricte des entrées avec express-validator

**Code :** `src/database/db.js`, `src/middleware/security.middleware.js`

```javascript
// Exemple de requête paramétrée
const result = await query(
  "SELECT * FROM users WHERE email = $1",
  [email] // Le paramètre est échappé automatiquement
);
```

### 2. Broken Authentication (A07:2021)

**Vulnérabilité :** Authentification faible permettant la compromission de comptes utilisateur.

**Protection implémentée :**

- ✅ Hachage bcrypt avec 12 rounds de salage
- ✅ Politique de mot de passe fort (min 8 chars, majuscule, minuscule, chiffre, spécial)
- ✅ Limitation des tentatives de connexion (5 max en 15 min)
- ✅ Verrouillage temporaire du compte après échecs
- ✅ Authentification à deux facteurs (2FA) optionnelle
- ✅ Tokens JWT avec expiration (7 jours)
- ✅ Gestion des sessions en base de données

**Code :** `src/utils/auth.js`, `src/controllers/auth.controller.js`

### 3. Sensitive Data Exposure (A02:2021)

**Vulnérabilité :** Exposition de données sensibles (mots de passe, tokens, données personnelles).

**Protection implémentée :**

- ✅ Mots de passe jamais stockés en clair (bcrypt)
- ✅ Variables d'environnement pour secrets (.env)
- ✅ Pas d'exposition de détails d'erreur en production
- ✅ HTTPS recommandé (headers HSTS)
- ✅ Tokens stockés avec hash SHA-256 en base

**Code :** `.env.example`, `src/middleware/security.middleware.js`

### 4. XML External Entities (XXE)

**Non applicable :** Cette application n'utilise pas XML.

### 5. Broken Access Control (A01:2021)

**Vulnérabilité :** Accès non autorisé à des ressources ou fonctionnalités.

**Protection implémentée :**

- ✅ Système RBAC (Role-Based Access Control)
- ✅ 3 niveaux de privilèges : User (10), Moderator (50), Admin (100)
- ✅ Middleware d'authentification JWT
- ✅ Middleware de vérification de rôle
- ✅ Vérification côté serveur pour chaque action sensible
- ✅ Impossibilité de modifier son propre rôle

**Code :** `src/middleware/auth.middleware.js`, `src/controllers/admin.controller.js`

```javascript
// Exemple de protection par rôle
router.delete(
  "/users/:userId",
  authenticateToken,
  requireRole(["admin"]),
  deleteUser
);
```

### 6. Security Misconfiguration (A05:2021)

**Vulnérabilité :** Configuration de sécurité inadéquate ou par défaut.

**Protection implémentée :**

- ✅ En-têtes HTTP sécurisés (Helmet)
- ✅ CSP (Content Security Policy)
- ✅ HSTS (HTTP Strict Transport Security)
- ✅ X-Content-Type-Options: nosniff
- ✅ X-Frame-Options: DENY
- ✅ Désactivation de X-Powered-By
- ✅ CORS configuré strictement
- ✅ Gestion d'erreurs sans exposition de stack traces

**Code :** `src/middleware/security.middleware.js`, `src/server.js`

### 7. Cross-Site Scripting (XSS) (A03:2021)

**Vulnérabilité :** Injection de scripts malveillants dans les pages web.

**Protection implémentée :**

- ✅ Sanitisation des entrées avec xss-clean
- ✅ Content Security Policy (CSP)
- ✅ Validation stricte de toutes les entrées utilisateur
- ✅ Échappement automatique dans le rendu HTML
- ✅ Protection de la console JavaScript

**Code :** `src/middleware/security.middleware.js`, `public/js/console-protection.js`

### 8. Insecure Deserialization

**Non applicable dans ce contexte :** Utilisation de JSON.parse natif sécurisé.

### 9. Using Components with Known Vulnerabilities (A06:2021)

**Protection implémentée :**

- ✅ Dépendances à jour (npm)
- ✅ Packages de sécurité réputés (bcrypt, helmet, express-validator)
- ⚠️ Recommandation : Utiliser `npm audit` régulièrement

### 10. Insufficient Logging & Monitoring (A09:2021)

**Vulnérabilité :** Manque de logs pour détecter les activités suspectes.

**Protection implémentée :**

- ✅ Table `security_logs` en base de données
- ✅ Enregistrement de toutes les actions critiques :
  - Connexions (réussies/échouées)
  - Changements de mot de passe
  - Activation/désactivation 2FA
  - Changements de rôle
  - Verrouillages de compte
- ✅ Capture de l'IP et User-Agent
- ✅ Dashboard admin pour consulter les logs
- ✅ Détection d'activités suspectes (user-agents de scanners)

**Code :** `src/utils/logger.js`, `src/controllers/admin.controller.js`

---

## 🚀 Installation et Configuration

### Prérequis

- Node.js 16+ et npm
- PostgreSQL 12+
- Compte email SMTP (Gmail, SendGrid, etc.)

### Étapes d'installation

1. **Cloner le repository**

```bash
git clone <repo-url>
cd C.S_S
```

2. **Installer les dépendances**

```bash
npm install
```

3. **Configurer les variables d'environnement**

```bash
cp .env.example .env
```

Éditer `.env` avec vos configurations :

```env
# Server
PORT=3000
NODE_ENV=development

# PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=secure_app_db
DB_USER=postgres
DB_PASSWORD=votre_mot_de_passe

# JWT Secret (générer avec: openssl rand -base64 32)
JWT_SECRET=votre_secret_jwt_tres_long_et_aleatoire
JWT_EXPIRE=7d

# Email (exemple Gmail)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=votre_email@gmail.com
EMAIL_PASSWORD=votre_mot_de_passe_app
EMAIL_FROM=noreply@yourapp.com

# Security
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=900000

# Frontend
CLIENT_URL=http://localhost:3000
```

4. **Créer la base de données PostgreSQL**

```bash
createdb secure_app_db
```

5. **Initialiser le schéma de base de données**

```bash
npm run db:init

# Ajouter la colonne permissions JSONB pour les rôles
node scripts/add_permissions_column.js
```

6. **Démarrer le serveur**

```bash
# Mode développement (avec nodemon)
npm run dev

# Mode production
npm start
```

Le serveur démarre sur `http://localhost:3000`

---

## 📖 API Documentation

### Endpoints Publics

#### Authentification

**POST /api/auth/register**

- Inscription d'un nouvel utilisateur
- Body : `{ email, password, phone? }`
- Retourne : `{ success, message, data: { userId, email } }`

**POST /api/auth/login**

- Connexion
- Body : `{ email, password }`
- Retourne : Token JWT ou demande 2FA

**POST /api/auth/verify-email**

- Vérification email
- Body : `{ email, code }`

**POST /api/auth/password-reset-request**

- Demande de réinitialisation mot de passe
- Body : `{ email }`

**POST /api/auth/password-reset**

- Réinitialisation mot de passe
- Body : `{ email, code, newPassword }`

### Endpoints Privés (Authentification requise)

#### Utilisateur

**GET /api/user/profile**

- Obtenir le profil

**PUT /api/user/profile**

- Mettre à jour le profil

**POST /api/user/change-password**

- Changer le mot de passe
- Body : `{ currentPassword, newPassword }`

**GET /api/user/sessions**

- Liste des sessions actives

**GET /api/user/security-logs**

- Logs de sécurité de l'utilisateur

#### 2FA

**POST /api/2fa/generate**

- Générer un QR code 2FA

**POST /api/2fa/verify**

- Vérifier et activer la 2FA
- Body : `{ token }`

**POST /api/2fa/disable**

- Désactiver la 2FA
- Body : `{ password }`

#### Administration (Admin/Moderator uniquement)

**GET /api/admin/users**

- Liste de tous les utilisateurs

**GET /api/admin/users/:userId**

- Détails d'un utilisateur

**PUT /api/admin/users/:userId/role**

- Changer le rôle d'un utilisateur (Admin only)
- Body : `{ roleName }`

**PUT /api/admin/users/:userId/lock**

- Verrouiller/déverrouiller un compte
- Body : `{ lock: true/false }`

**DELETE /api/admin/users/:userId**

- Supprimer un utilisateur (Admin only)

**GET /api/admin/stats**

- Statistiques de sécurité

**GET /api/admin/logs**

- Tous les logs de sécurité (Admin only)

---

## 🧪 Tests

### Test manuel

1. **Créer un compte utilisateur**

   - Vérifier la réception de l'email
   - Vérifier le code

2. **Tester les protections**

   - Tentatives de connexion multiples → Verrouillage
   - Injections SQL dans les champs → Blocage
   - Mots de passe faibles → Rejet

3. **Activer la 2FA**

   - Scanner le QR code avec Google Authenticator
   - Tester la connexion avec 2FA

4. **Tester le RBAC**
   - Créer plusieurs comptes
   - Tester l'accès aux endpoints admin sans privilèges

### Tests de sécurité automatisés (recommandés)

```bash
# Scan de vulnérabilités
npm audit

# Test d'injection SQL (avec sqlmap - environnement de test uniquement)
sqlmap -u "http://localhost:3000/api/auth/login" --data="email=test&password=test"

# Test XSS
# Insérer <script>alert('XSS')</script> dans les champs de formulaire
```

---

## 📊 Schéma de Base de Données

```sql
┌─────────────────┐
│     roles       │
├─────────────────┤
│ id (PK)         │
│ name (UNIQUE)   │
│ priority        │
│ description     │
│ permissions     │  # JSONB: {"manage_users":bool,"manage_roles":bool,...}
└─────────────────┘
         │
         │ 1:N
         ▼
┌─────────────────────────┐
│        users            │
├─────────────────────────┤
│ id (PK, UUID)           │
│ email (UNIQUE)          │
│ password_hash           │
│ phone                   │
│ role_id (FK)            │
│ is_email_verified       │
│ is_phone_verified       │
│ is_2fa_enabled          │
│ two_fa_secret           │
│ login_attempts          │
│ locked_until            │
│ last_login              │
│ created_at              │
│ updated_at              │
└─────────────────────────┘
         │
         ├─────────────────┐
         │ 1:N             │ 1:N
         ▼                 ▼
┌──────────────────┐  ┌────────────────┐
│ verification_    │  │ user_sessions  │
│    codes         │  ├────────────────┤
├──────────────────┤  │ id (PK, UUID)  │
│ id (PK, UUID)    │  │ user_id (FK)   │
│ user_id (FK)     │  │ token_hash     │
│ code             │  │ ip_address     │
│ type             │  │ user_agent     │
│ expires_at       │  │ expires_at     │
│ is_used          │  │ created_at     │
│ created_at       │  └────────────────┘
└──────────────────┘
         │
         │ 1:N
         ▼
┌──────────────────┐
│ security_logs    │
├──────────────────┤
│ id (PK)          │
│ user_id (FK)     │
│ action           │
│ ip_address       │
│ user_agent       │
│ success          │
│ details          │
│ created_at       │
└──────────────────┘
```

---

## 🔐 Bonnes Pratiques de Sécurité

### Pour les Développeurs

1. **Ne jamais commiter le fichier .env**

   - Toujours utiliser .env.example comme template

2. **Utiliser HTTPS en production**

   - Configurer un certificat SSL (Let's Encrypt gratuit)

3. **Mettre à jour régulièrement les dépendances**

   ```bash
   npm audit
   npm update
   ```

4. **Utiliser des secrets forts**

   ```bash
   # Générer un secret JWT fort
   openssl rand -base64 64
   ```

5. **Configurer un WAF (Web Application Firewall)**

   - Cloudflare
   - AWS WAF
   - ModSecurity

6. **Sauvegardes régulières de la base de données**
   ```bash
   pg_dump secure_app_db > backup.sql
   ```

### Pour les Utilisateurs

1. Utiliser des mots de passe forts et uniques
2. Activer la 2FA
3. Ne jamais partager ses identifiants
4. Se déconnecter sur les appareils partagés
5. Vérifier régulièrement les sessions actives

---

## � Mises à Jour Récentes

### Novembre 2025

#### Protection Anti-Bot avec reCAPTCHA

- ✅ Intégration de Google reCAPTCHA v2
- ✅ Validation côté serveur des tokens reCAPTCHA
- ✅ Configuration CSP pour reCAPTCHA
- ✅ Middleware de vérification reCAPTCHA
- ✅ Style adaptatif pour l'intégration visuelle

#### Système de Permissions Avancé

- ✅ Colonne JSONB pour les permissions des rôles
- ✅ Interface d'administration des permissions
- ✅ Migrations automatiques de la base de données
- ✅ API de gestion des permissions
- ✅ Validation côté serveur des permissions

#### Sécurité Renforcée

- ✅ Content Security Policy (CSP) optimisée
- ✅ Protection contre les attaques XSS et CSRF
- ✅ En-têtes de sécurité HTTP améliorés
- ✅ Validation des entrées renforcée
- ✅ Tests de sécurité automatisés

## �📈 Améliorations Futures

- [ ] Intégration SMS réelle (Twilio)
- [ ] Tests unitaires et d'intégration (Jest, Mocha)
- [ ] CI/CD avec GitHub Actions
- [ ] Docker containerization
- [ ] Monitoring avec Prometheus/Grafana
- [ ] Notifications en temps réel (WebSockets)
- [ ] Backup automatique de la base de données
- [ ] Interface d'administration avancée
- [ ] Support multi-langues (i18n)
- [ ] Mode sombre pour l'interface

---

## 📚 Bibliographie et Références

### Standards et Organisations de Sécurité

#### OWASP (Open Web Application Security Project)

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/) - Guide des risques de sécurité critiques
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - Bonnes pratiques de sécurité
- [OWASP Authentication Guidelines](https://owasp.org/www-project-authentication-guidance/) - Directives d'authentification
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) - Sécurité des API

#### Standards Web

- [MDN Web Security](https://developer.mozilla.org/fr/docs/Web/Security) - Documentation Mozilla sur la sécurité web
- [Content Security Policy (CSP)](https://content-security-policy.com/) - Guide complet sur les CSP
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749) - Protocole d'autorisation
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519) - Standard JWT

### Documentation Technique

#### Node.js et Express

- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Node.js Production Practices](https://nodejs.org/en/docs/guides/nodejs-docker-webapp/)
- [Express.js Production Best Practices](https://expressjs.com/en/advanced/best-practice-performance.html)

#### Base de Données

- [PostgreSQL Security Documentation](https://www.postgresql.org/docs/current/security.html)
- [PostgreSQL JSONB](https://www.postgresql.org/docs/current/datatype-json.html)
- [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

#### Authentification et Autorisation

- [Google 2-Step Verification](https://www.google.com/landing/2step/)
- [reCAPTCHA Documentation](https://developers.google.com/recaptcha/docs/v2)
- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238) - Standard pour 2FA

### Bibliothèques et Frameworks Utilisés

#### Sécurité

- [Helmet](https://helmetjs.github.io/) - v7.1.0 - Sécurisation des en-têtes HTTP
- [bcrypt](https://github.com/kelektiv/node.bcrypt.js) - v5.1.1 - Hachage de mots de passe
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - v9.0.2 - Gestion des JWT
- [express-rate-limit](https://github.com/nfriedly/express-rate-limit) - v7.1.5 - Rate limiting
- [cors](https://github.com/expressjs/cors) - v2.8.5 - Gestion des CORS
- [xss-clean](https://github.com/jsonmaur/xss-clean) - v0.1.4 - Protection XSS
- [hpp](https://github.com/analog-nico/hpp) - v0.2.3 - Protection contre la pollution de paramètres HTTP

#### Validation et Sanitization

- [express-validator](https://express-validator.github.io/) - v7.0.1 - Validation des entrées
- [validator.js](https://github.com/validatorjs/validator.js) - v13.11.0 - Validation de chaînes

#### Base de Données

- [node-postgres](https://node-postgres.com/) - v8.11.3 - Client PostgreSQL
- [pg-format](https://github.com/datalanche/node-pg-format) - v1.0.4 - Formatage SQL sécurisé

#### Utilitaires

- [QRCode](https://github.com/soldair/node-qrcode) - v1.5.3 - Génération de QR codes
- [speakeasy](https://github.com/speakeasyjs/speakeasy) - v2.0.0 - Implémentation TOTP
- [nodemailer](https://nodemailer.com/) - v6.9.7 - Envoi d'emails
- [axios](https://axios-http.com/) - v1.6.2 - Client HTTP

### Articles et Publications Académiques

- "Security in Node.js and Express: Best Practices" - Node.js Foundation, 2024
- "Web Security: A WhiteHat Perspective" - Ivan Ristić, 2023
- "Modern Authentication Methods in Web Applications" - IEEE Security & Privacy, 2024
- "Role-Based Access Control in Modern Web Applications" - ACM Digital Library, 2025
- "Analysis of Web Application Firewall Effectiveness" - International Journal of Network Security, 2024

### Ressources Complémentaires

#### Blogs et Articles Techniques

- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)
- [Security Headers Explained](https://securityheaders.com/)
- [JWT Best Practices](https://auth0.com/blog/jwt-security-best-practices/)
- [Web Security Academy](https://portswigger.net/web-security)

#### Outils de Test et Audit

- [OWASP ZAP](https://www.zaproxy.org/) - Proxy de sécurité
- [SQLMap](http://sqlmap.org/) - Test d'injection SQL
- [Burp Suite](https://portswigger.net/burp) - Test de sécurité web
- [SonarQube](https://www.sonarqube.org/) - Analyse de code statique

---

## 👥 Auteur

Bensari Zakaria
Projet réalisé dans le cadre d'un mémoire sur la sécurisation des applications web.

## 📄 Licence

Ce projet est sous licence ISC. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 🐛 Signalement de Vulnérabilités

Si vous découvrez une vulnérabilité de sécurité, veuillez NE PAS ouvrir d'issue publique.
Envoyez un email à l'équipe de sécurité avec les détails.

---

**Note :** Cette application est un projet éducatif démontrant les bonnes pratiques de sécurité.
Pour une utilisation en production, effectuez un audit de sécurité complet et suivez les recommandations OWASP.
