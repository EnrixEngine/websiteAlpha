# AlphaMouv

Site web portfolio et boutique en ligne pour AlphaMouv (B.A.B - Artiste Createur).

## Stack technique

- **Backend** : Node.js, Express
- **Base de donnees** : SQLite (sql.js)
- **Paiement** : Stripe Checkout
- **Stockage images** : Cloudinary
- **Emails** : Resend
- **Securite** : Helmet, bcryptjs, JWT, AES-256-GCM

## Installation

```bash
npm install
```

## Configuration

Creer un fichier `.env` a la racine :

```env
PORT=3000
NODE_ENV=development
JWT_SECRET=votre_secret_jwt
ADMIN_EMAIL=admin@alphamouv.com
ADMIN_PASSWORD=votre_mot_de_passe

# Cloudinary
CLOUDINARY_CLOUD_NAME=votre_cloud
CLOUDINARY_API_KEY=votre_cle
CLOUDINARY_API_SECRET=votre_secret

# Stripe (optionnel)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...

# Resend (optionnel)
RESEND_API_KEY=re_...
```

## Demarrage

```bash
# Developpement
npm run dev

# Production
npm start
```

Le serveur demarre sur `http://localhost:3000`.

## Structure

```
index.html      - Page d'accueil (split portfolio/boutique)
blog.html       - Portfolio / sections artiste
boutique.html   - Boutique en ligne
server.js       - API backend Express
```

## Licence

ISC
