/**
 * Serveur AlphaMouv - Backend Node.js
 * Portfolio et Boutique en ligne
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fsPromises = require('fs').promises;
const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

// ==================== LOGGER ====================
const isProduction = process.env.NODE_ENV === 'production';
/* eslint-disable no-console */
const logger = {
    info: (...args) => { if (!isProduction) console.log(...args); },
    warn: (...args) => { if (!isProduction) console.warn(...args); },
    error: (...args) => { console.error(...args); },
    debug: (...args) => { if (!isProduction) console.log(...args); },
};
/* eslint-enable no-console */

// ==================== SECURITE ====================
const helmet = require('helmet');

// ==================== CHIFFREMENT DES DONNEES (AES-256-GCM) ====================
let ENCRYPTION_KEY;
if (process.env.ENCRYPTION_KEY) {
    // Cle fournie en env var (doit etre une chaine hex de 64 caracteres = 32 bytes)
    const hexKey = process.env.ENCRYPTION_KEY;
    ENCRYPTION_KEY = Buffer.from(hexKey, 'hex');
    if (ENCRYPTION_KEY.length !== 32) {
        logger.warn('ENCRYPTION_KEY invalide (' + ENCRYPTION_KEY.length + ' bytes au lieu de 32). Utilisation de la cle derivee.');
        ENCRYPTION_KEY = crypto.createHash('sha256')
            .update(process.env.JWT_SECRET || 'alphamouv_default_key_2024')
            .digest();
    }
} else {
    // Pas de cle fournie → deriver depuis JWT_SECRET
    ENCRYPTION_KEY = crypto.createHash('sha256')
        .update(process.env.JWT_SECRET || 'alphamouv_default_key_2024')
        .digest();
}
const GCM_IV_LENGTH = 12;

// Chiffrer une donnee sensible (AES-256-GCM - chiffrement authentifie)
function encryptData(text) {
    if (!text) return text;
    try {
        const iv = crypto.randomBytes(GCM_IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return 'gcm:' + iv.toString('hex') + ':' + authTag + ':' + encrypted;
    } catch (error) {
        logger.error('Erreur chiffrement:', error);
        return text;
    }
}

// Dechiffrer une donnee sensible (AES-256-GCM uniquement)
function decryptData(encryptedText) {
    if (!encryptedText || typeof encryptedText !== 'string') {
        return encryptedText;
    }
    try {
        if (encryptedText.startsWith('gcm:')) {
            const [, ivHex, authTagHex, encrypted] = encryptedText.split(':');
            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');
            const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        }
        return encryptedText;
    } catch {
        return encryptedText;
    }
}

// Verifier si une donnee est chiffree (format GCM)
function isEncrypted(text) {
    if (!text || typeof text !== 'string') return false;
    return text.startsWith('gcm:');
}
const rateLimit = require('express-rate-limit');

// Rate limiters pour differentes routes
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 2000, // 2000 requetes par IP (supporte haut trafic)
    message: { error: 'Trop de requetes, reessayez dans 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 tentatives de login par IP
    message: { error: 'Trop de tentatives de connexion, reessayez dans 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Configuration Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configuration Stripe (optionnel - le serveur demarre meme sans cles)
let stripe = null;
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || '';
if (process.env.STRIPE_SECRET_KEY) {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    logger.info('Stripe configure en mode', STRIPE_PUBLISHABLE_KEY.includes('test') ? 'TEST' : 'PRODUCTION');
} else {
    logger.info('Stripe non configure - ajoutez STRIPE_SECRET_KEY pour activer les paiements');
}

// Configuration Resend (emails)
let resend = null;
if (process.env.RESEND_API_KEY) {
    const { Resend } = require('resend');
    resend = new Resend(process.env.RESEND_API_KEY);
    logger.info('Resend configure pour les emails');
} else {
    logger.info('Resend non configure - ajoutez RESEND_API_KEY pour activer les emails');
}

// Fonction d'envoi d'email de confirmation de commande
async function sendOrderConfirmationEmail(order, customerEmail, customerName) {
    if (!resend) {
        logger.info('Email non envoye - Resend non configure');
        return false;
    }

    try {
        const items = JSON.parse(order.items || '[]');
        const itemsList = items.map(item =>
            `<tr>
                <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.name}</td>
                <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: center;">${item.quantity || 1}</td>
                <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">${item.price.toFixed(2)} €</td>
            </tr>`
        ).join('');

        const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #ddac0b, #b8900a); padding: 30px; text-align: center; }
                .header h1 { color: #000; margin: 0; font-size: 28px; }
                .content { padding: 30px; background: #f9f9f9; }
                .order-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                .order-table th { background: #333; color: #fff; padding: 12px; text-align: left; }
                .total { font-size: 20px; font-weight: bold; color: #ddac0b; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>AlphaMouv</h1>
                </div>
                <div class="content">
                    <h2>Merci pour votre commande !</h2>
                    <p>Bonjour ${customerName || 'cher client'},</p>
                    <p>Nous avons bien recu votre commande et nous vous en remercions.</p>

                    <h3>Recapitulatif de votre commande #${order.id}</h3>
                    <table class="order-table">
                        <thead>
                            <tr>
                                <th>Produit</th>
                                <th style="text-align: center;">Quantite</th>
                                <th style="text-align: right;">Prix</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${itemsList}
                        </tbody>
                    </table>

                    <p class="total">Total: ${order.total.toFixed(2)} €</p>

                    <p>Vous recevrez un email de suivi des que votre commande sera expediee.</p>
                    <p>Si vous avez des questions, n'hesitez pas a nous contacter.</p>

                    <p>A bientot !<br>L'equipe AlphaMouv</p>
                </div>
                <div class="footer">
                    <p>© ${new Date().getFullYear()} AlphaMouv - Tous droits reserves</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const { data, error } = await resend.emails.send({
            from: 'AlphaMouv <onboarding@resend.dev>',
            to: [customerEmail],
            subject: `Confirmation de commande #${order.id} - AlphaMouv`,
            html: emailHtml,
        });

        if (error) {
            logger.error('Erreur envoi email:', error);
            return false;
        }

        logger.info('Email de confirmation envoye:', data?.id);
        return true;
    } catch (error) {
        logger.error('Erreur envoi email:', error);
        return false;
    }
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'alphamouv_secret_2024';

// ==================== CONFIGURATION ====================

// Middleware pour forcer HTTPS en production (Render)
app.use((req, res, next) => {
    // Render utilise le header x-forwarded-proto pour indiquer HTTPS
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
});

// Middleware de securite
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://accounts.google.com", "https://cdn.tailwindcss.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://accounts.google.com", "https://www.instagram.com", "https://js.stripe.com", "https://www.paypal.com", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:", "https:", "http:"],
            connectSrc: ["'self'", "https://accounts.google.com", "https://www.instagram.com", "https://res.cloudinary.com", "https://api.stripe.com", "https://www.paypal.com", "https://cdnjs.cloudflare.com"],
            frameSrc: ["'self'", "https://accounts.google.com", "https://www.instagram.com", "https://js.stripe.com", "https://hooks.stripe.com", "https://www.paypal.com"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

// Rate limiting global
app.use(generalLimiter);

// Middleware CORS
const corsOptions = {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' })); // Reduit de 50mb a 10mb pour securite
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname)));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Creer le dossier uploads s'il n'existe pas (async IIFE)
(async () => {
    try {
        await fsPromises.access(path.join(__dirname, 'uploads'));
    } catch {
        await fsPromises.mkdir(path.join(__dirname, 'uploads'), { recursive: true });
    }
})();

// Configuration Multer pour upload d'images (stockage en memoire pour Cloudinary)
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Type de fichier non autorise. Utilisez JPG, PNG, GIF ou WebP.'), false);
    }
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: fileFilter
});

// ==================== BASE DE DONNEES TURSO ====================

let db;

// Creer toutes les tables de la base de donnees
async function createTables() {
    const tables = [
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            nom TEXT, prenom TEXT, adresse TEXT, code_postal TEXT,
            ville TEXT, telephone TEXT, role TEXT DEFAULT 'user',
            two_factor_secret TEXT, two_factor_enabled INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL, description TEXT, prix REAL NOT NULL,
            prix_promo REAL, image TEXT, images TEXT, tailles TEXT,
            categorie TEXT, stock INTEGER DEFAULT 0, actif INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS newsletter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, actif INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT NOT NULL, description TEXT, date TEXT,
            lieu TEXT, image TEXT, statut TEXT DEFAULT 'a_venir',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT, description TEXT, image TEXT NOT NULL,
            categorie TEXT, ordre INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS carousel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT, description TEXT, image TEXT NOT NULL,
            ordre INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, stripe_session_id TEXT,
            total REAL NOT NULL, status TEXT DEFAULT 'pending',
            items TEXT, shipping_address TEXT, paid_at TEXT,
            promo_code TEXT, discount_amount REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )`,
        `CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id),
            UNIQUE(user_id, product_id)
        )`,
        `CREATE TABLE IF NOT EXISTS promo_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL, discount_percent INTEGER NOT NULL,
            max_uses INTEGER DEFAULT NULL, used_count INTEGER DEFAULT 0,
            min_order_amount REAL DEFAULT 0, active INTEGER DEFAULT 1,
            expires_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS instagram_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instagram_url TEXT NOT NULL, image TEXT NOT NULL,
            caption TEXT DEFAULT '', position INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`,
    ];
    for (const sql of tables) {
        await db.execute(sql);
    }
}

// Tables valides pour les migrations (whitelist contre injection SQL)
const VALID_TABLES = ['users', 'products', 'orders', 'newsletter', 'events', 'gallery', 'carousel', 'instagram_posts', 'promo_codes'];
const VALID_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

// Ajouter une colonne si elle n'existe pas
async function addColumnIfMissing(table, column, definition) {
    if (!VALID_TABLES.includes(table) || !VALID_IDENTIFIER.test(column)) {
        logger.error(`Migration: identifiant invalide (table=${table}, column=${column})`);
        return;
    }
    try {
        const info = await db.execute(`PRAGMA table_info(${table})`);
        const columns = info.rows.map(row => row.name);
        if (!columns.includes(column)) {
            await db.execute(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
            logger.info(`Migration: colonne ${column} ajoutee a ${table}`);
        }
    } catch (err) {
        logger.info(`Migration ${table}: `, err.message);
    }
}

// Executer toutes les migrations de schema
async function runMigrations() {
    await addColumnIfMissing('orders', 'stripe_session_id', 'TEXT');
    await addColumnIfMissing('orders', 'status', 'TEXT DEFAULT "pending"');
    await addColumnIfMissing('orders', 'shipping_address', 'TEXT');
    await addColumnIfMissing('orders', 'paid_at', 'TEXT');
    await addColumnIfMissing('orders', 'promo_code', 'TEXT');
    await addColumnIfMissing('orders', 'discount_amount', 'REAL DEFAULT 0');
    await addColumnIfMissing('products', 'stock', 'INTEGER DEFAULT 0');
    await addColumnIfMissing('users', 'auth_provider', 'TEXT DEFAULT "email"');
    await addColumnIfMissing('instagram_posts', 'video', 'TEXT DEFAULT ""');
    await addColumnIfMissing('products', 'type', 'TEXT');
}

// Creer ou mettre a jour le compte admin
async function setupAdmin() {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@alphamouv.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const BCRYPT_ROUNDS = 10;
    const hashedPassword = bcrypt.hashSync(adminPassword, BCRYPT_ROUNDS);
    const encryptedAdminEmail = encryptData(adminEmail);

    const admin = await dbGet("SELECT id FROM users WHERE role = 'admin'");
    if (!admin) {
        await dbRun(
            'INSERT INTO users (email, password, nom, prenom, role) VALUES (?, ?, ?, ?, ?)',
            [encryptedAdminEmail, hashedPassword, 'Admin', 'AlphaMouv', 'admin']
        );
        logger.info('Admin cree');
    } else {
        await dbRun(
            'UPDATE users SET email = ?, password = ? WHERE role = ?',
            [encryptedAdminEmail, hashedPassword, 'admin']
        );
        logger.info('Admin mis a jour');
    }
}

async function initDatabase() {
    db = createClient({
        url: process.env.TURSO_DATABASE_URL,
        authToken: process.env.TURSO_AUTH_TOKEN,
    });

    await createTables();
    await runMigrations();
    await setupAdmin();
    await migrateEncryption();
    logger.info('Base de donnees Turso connectee');
}

// Migration pour chiffrer les donnees existantes et migrer CBC vers GCM
async function migrateEncryption() {
    logger.info('Verification du chiffrement des donnees...');

    // Detecter le format legacy CBC (iv hex 32 chars : encrypted hex)
    const isCbcFormat = (text) => {
        if (!text || typeof text !== 'string') return false;
        return !text.startsWith('gcm:') && /^[a-f0-9]{32}:[a-f0-9]+$/.test(text);
    };

    // Dechiffrer le format legacy CBC (utilise uniquement pour la migration)
    const decryptLegacyCbc = (encryptedText) => {
        const [ivHex, encrypted] = encryptedText.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    };

    // Migrer un champ : plaintext→GCM, CBC→GCM, ou null si deja GCM
    const migrateField = (value) => {
        if (!value) return null;
        if (isEncrypted(value)) return null; // Deja en GCM
        if (isCbcFormat(value)) {
            try {
                return encryptData(decryptLegacyCbc(value));
            } catch {
                return null;
            }
        }
        return encryptData(value); // Texte clair → GCM
    };

    // Migrer les utilisateurs
    const users = await dbAll('SELECT id, email, adresse, telephone FROM users');
    let usersMigrated = 0;
    for (const user of users) {
        const emailUpdate = migrateField(user.email);
        const adresseUpdate = migrateField(user.adresse);
        const telephoneUpdate = migrateField(user.telephone);

        if (emailUpdate || adresseUpdate || telephoneUpdate) {
            await dbRun(`
                UPDATE users SET
                    email = COALESCE(?, email),
                    adresse = COALESCE(?, adresse),
                    telephone = COALESCE(?, telephone)
                WHERE id = ?
            `, [emailUpdate, adresseUpdate, telephoneUpdate, user.id]);
            usersMigrated++;
        }
    }
    if (usersMigrated > 0) {
        logger.info(`Migration: ${usersMigrated} utilisateur(s) migre(s) vers GCM`);
    }

    // Migrer la newsletter
    const subscribers = await dbAll('SELECT id, email FROM newsletter');
    let newsletterMigrated = 0;
    for (const sub of subscribers) {
        const emailUpdate = migrateField(sub.email);
        if (emailUpdate) {
            await dbRun('UPDATE newsletter SET email = ? WHERE id = ?', [emailUpdate, sub.id]);
            newsletterMigrated++;
        }
    }
    if (newsletterMigrated > 0) {
        logger.info(`Migration: ${newsletterMigrated} email(s) newsletter migre(s) vers GCM`);
    }

    logger.info('Chiffrement des donnees verifie');
}

// Decrementer le stock des produits d'une commande
async function decrementOrderStock(orderItems) {
    const items = JSON.parse(orderItems || '[]');
    for (const item of items) {
        const product = await dbGet('SELECT stock FROM products WHERE id = ?', [item.id]);
        if (product) {
            const newStock = Math.max(0, product.stock - (item.quantity || 1));
            await dbRun('UPDATE products SET stock = ? WHERE id = ?', [newStock, item.id]);
        }
    }
}

// Traiter une commande apres paiement confirme
async function processCompletedPayment(order) {
    await dbRun(
        "UPDATE orders SET status = 'paid', paid_at = CURRENT_TIMESTAMP WHERE stripe_session_id = ?",
        [order.stripe_session_id]
    );

    try {
        await decrementOrderStock(order.items);
    } catch (err) {
        logger.error('Erreur decrementation stock:', err);
    }

    if (order.promo_code) {
        await dbRun(
            'UPDATE promo_codes SET used_count = used_count + 1 WHERE code = ?',
            [order.promo_code]
        );
    }

    const user = await dbGet('SELECT * FROM users WHERE id = ?', [order.user_id]);
    if (user) {
        const email = decryptData(user.email);
        const name = user.prenom
            ? `${user.prenom} ${user.nom || ''}`.trim()
            : email;
        await sendOrderConfirmationEmail({ ...order, status: 'paid' }, email, name);
    }
}

// Helpers pour simplifier les requetes (async - Turso)
async function dbGet(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return result.rows[0] || null;
}

async function dbAll(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return result.rows;
}

async function dbRun(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return { lastID: Number(result.lastInsertRowid) };
}

// ==================== MIDDLEWARE AUTH ====================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide' });
        }
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acces refuse' });
    }
    next();
}

// ==================== ROUTES PAGES ====================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== API AUTHENTIFICATION ====================

// Connexion avec Google
app.post('/api/auth/google', authLimiter, async (req, res) => {
    try {
        const { credential, clientId } = req.body;

        if (!credential) {
            return res.status(400).json({ error: 'Token Google manquant' });
        }

        // Decoder le token JWT Google (sans verification complete pour simplifier)
        // En production, utiliser google-auth-library pour verifier
        const base64Url = credential.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(Buffer.from(base64, 'base64').toString().split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        const googleUser = JSON.parse(jsonPayload);

        // Verifier que le token n'est pas expire
        if (googleUser.exp * 1000 < Date.now()) {
            return res.status(401).json({ error: 'Token Google expire' });
        }

        const email = googleUser.email;
        const nom = googleUser.family_name || '';
        const prenom = googleUser.given_name || googleUser.name || '';

        // Chercher l'utilisateur avec email chiffre ou non
        const allUsers = await dbAll('SELECT * FROM users');
        let user = allUsers.find(u => {
            const decryptedEmail = decryptData(u.email);
            return decryptedEmail === email || u.email === email;
        });

        if (!user) {
            // Creer un nouvel utilisateur Google avec email chiffre
            const randomPassword = bcrypt.hashSync(Math.random().toString(36), 10);
            const encryptedEmail = encryptData(email);
            const result = await dbRun(`
                INSERT INTO users (email, password, nom, prenom, role, auth_provider)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [encryptedEmail, randomPassword, nom, prenom, 'user', 'google']);

            user = {
                id: result.lastID,
                email: email,
                nom: nom,
                prenom: prenom,
                role: 'user',
                auth_provider: 'google'
            };
        }

        // Dechiffrer l'email pour le token
        const decryptedEmail = user.email ? decryptData(user.email) : email;

        // Generer le token JWT
        const token = jwt.sign(
            { id: user.id, email: decryptedEmail, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: decryptedEmail,
                nom: user.nom,
                prenom: user.prenom,
                role: user.role
            }
        });
    } catch (error) {
        logger.error('Erreur connexion Google:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion Google' });
    }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { email, password, nom, prenom, adresse, code_postal, ville, telephone } = req.body;

        // Rechercher avec email chiffre ou non (pour compatibilite)
        const allUsers = await dbAll('SELECT id, email FROM users');
        const existingUser = allUsers.find(u => {
            const decryptedEmail = decryptData(u.email);
            return decryptedEmail === email || u.email === email;
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est deja utilise' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        // Chiffrer les donnees sensibles
        const encryptedEmail = encryptData(email);
        const encryptedAdresse = adresse ? encryptData(adresse) : null;
        const encryptedTelephone = telephone ? encryptData(telephone) : null;

        const result = await dbRun(`
            INSERT INTO users (email, password, nom, prenom, adresse, code_postal, ville, telephone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [encryptedEmail, hashedPassword, nom, prenom, encryptedAdresse, code_postal, ville, encryptedTelephone]);

        const token = jwt.sign(
            { id: result.lastID, email, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Inscription reussie',
            token,
            user: { id: result.lastID, email, nom, prenom, role: 'user' }
        });
    } catch (error) {
        logger.error('Erreur inscription:', error);
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Rechercher l'utilisateur avec email chiffre ou non
        const allUsers = await dbAll('SELECT * FROM users');
        const user = allUsers.find(u => {
            const decryptedEmail = decryptData(u.email);
            return decryptedEmail === email || u.email === email;
        });

        if (!user) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Dechiffrer l'email pour le token et la reponse
        const decryptedEmail = decryptData(user.email);

        const token = jwt.sign(
            { id: user.id, email: decryptedEmail, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: decryptedEmail,
                nom: user.nom,
                prenom: user.prenom,
                role: user.role,
                adresse: decryptData(user.adresse),
                code_postal: user.code_postal,
                ville: user.ville,
                telephone: decryptData(user.telephone)
            }
        });
    } catch (error) {
        logger.error('Erreur connexion:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion' });
    }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT id, email, nom, prenom, adresse, code_postal, ville, telephone, role FROM users WHERE id = ?', [req.user.id]);
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouve' });
        }
        // Dechiffrer les donnees sensibles
        res.json({
            ...user,
            email: decryptData(user.email),
            adresse: decryptData(user.adresse),
            telephone: decryptData(user.telephone)
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { nom, prenom, adresse, code_postal, ville, telephone } = req.body;

        // Chiffrer les donnees sensibles
        const encryptedAdresse = adresse ? encryptData(adresse) : null;
        const encryptedTelephone = telephone ? encryptData(telephone) : null;

        await dbRun(`
            UPDATE users SET nom = ?, prenom = ?, adresse = ?, code_postal = ?, ville = ?, telephone = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [nom, prenom, encryptedAdresse, code_postal, ville, encryptedTelephone, req.user.id]);

        res.json({ success: true, message: 'Profil mis a jour' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la mise a jour' });
    }
});

app.put('/api/auth/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);

        if (!bcrypt.compareSync(currentPassword, user.password)) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect' });
        }

        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        await dbRun('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [hashedPassword, req.user.id]);

        res.json({ success: true, message: 'Mot de passe modifie' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du changement de mot de passe' });
    }
});

// ==================== API PRODUITS ====================

app.get('/api/products', async (req, res) => {
    try {
        const products = await dbAll('SELECT * FROM products WHERE actif = 1 ORDER BY created_at DESC');
        res.json(products.map(p => ({
            ...p,
            images: p.images ? JSON.parse(p.images) : [],
            tailles: p.tailles ? JSON.parse(p.tailles) : []
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await dbGet('SELECT * FROM products WHERE id = ?', [req.params.id]);
        if (!product) {
            return res.status(404).json({ error: 'Produit non trouve' });
        }
        res.json({
            ...product,
            images: product.images ? JSON.parse(product.images) : [],
            tailles: product.tailles ? JSON.parse(product.tailles) : []
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { nom, description, prix, prix_promo, image, images, tailles, categorie, type, stock } = req.body;

        const result = await dbRun(`
            INSERT INTO products (nom, description, prix, prix_promo, image, images, tailles, categorie, type, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [nom, description, prix, prix_promo, image, JSON.stringify(images || []), JSON.stringify(tailles || []), categorie, type || '', stock || 0]);

        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la creation' });
    }
});

app.put('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Charger le produit existant pour ne modifier que les champs fournis
        const existing = await dbGet('SELECT * FROM products WHERE id = ?', [req.params.id]);
        if (!existing) return res.status(404).json({ error: 'Produit introuvable' });

        const b = req.body;
        const nom = b.nom !== undefined ? b.nom : existing.nom;
        const description = b.description !== undefined ? b.description : existing.description;
        const prix = b.prix !== undefined ? b.prix : existing.prix;
        const prix_promo = b.prix_promo !== undefined ? b.prix_promo : existing.prix_promo;
        const image = b.image !== undefined ? b.image : existing.image;
        const images = b.images !== undefined ? JSON.stringify(b.images || []) : existing.images;
        const tailles = b.tailles !== undefined ? JSON.stringify(b.tailles || []) : existing.tailles;
        const categorie = b.categorie !== undefined ? b.categorie : existing.categorie;
        const type = b.type !== undefined ? b.type : (existing.type || '');
        const stock = b.stock !== undefined ? b.stock : existing.stock;
        const actif = b.actif !== undefined ? b.actif : existing.actif;

        await dbRun(`
            UPDATE products SET nom = ?, description = ?, prix = ?, prix_promo = ?, image = ?, images = ?, tailles = ?, categorie = ?, type = ?, stock = ?, actif = ?
            WHERE id = ?
        `, [nom, description, prix, prix_promo, image, images, tailles, categorie, type, stock, actif, req.params.id]);

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la modification' });
    }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM products WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
});

// ==================== API COMMANDES ====================

app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { items, adresse_livraison, total } = req.body;
        const numero = 'CMD-' + Date.now() + '-' + Math.random().toString(36).substring(2, 11).toUpperCase();

        const result = await dbRun(`
            INSERT INTO orders (user_id, numero, total, adresse_livraison, items)
            VALUES (?, ?, ?, ?, ?)
        `, [req.user.id, numero, total, adresse_livraison, JSON.stringify(items)]);

        res.json({ success: true, numero, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la creation de la commande' });
    }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const orders = await dbAll('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
        res.json(orders.map(o => ({
            ...o,
            items: JSON.parse(o.items || '[]')
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/admin/orders', authenticateToken, isAdmin, async (req, res) => {
    try {
        const orders = await dbAll(`
            SELECT o.*, u.email, u.nom, u.prenom
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
        `);
        // Dechiffrer les emails utilisateurs
        res.json(orders.map(o => ({
            ...o,
            email: decryptData(o.email),
            items: JSON.parse(o.items || '[]')
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/admin/orders/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { statut } = req.body;
        await dbRun('UPDATE orders SET statut = ? WHERE id = ?', [statut, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API NEWSLETTER ====================

app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = req.body;

        // Verifier si l'email existe deja (chiffre ou non)
        const allSubscribers = await dbAll('SELECT id, email FROM newsletter');
        const existing = allSubscribers.find(s => {
            const decryptedEmail = decryptData(s.email);
            return decryptedEmail === email || s.email === email;
        });

        if (existing) {
            return res.status(400).json({ error: 'Cet email est deja inscrit' });
        }

        // Chiffrer l'email avant stockage
        const encryptedEmail = encryptData(email);
        await dbRun('INSERT INTO newsletter (email) VALUES (?)', [encryptedEmail]);
        res.json({ success: true, message: 'Inscription reussie a la newsletter' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.get('/api/admin/newsletter', authenticateToken, isAdmin, async (req, res) => {
    try {
        const subscribers = await dbAll('SELECT * FROM newsletter WHERE actif = 1 ORDER BY created_at DESC');
        // Dechiffrer les emails pour l'affichage admin
        res.json((subscribers || []).map(s => ({
            ...s,
            email: decryptData(s.email)
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API EVENEMENTS ====================

app.get('/api/events', async (req, res) => {
    try {
        const events = await dbAll('SELECT * FROM events ORDER BY date DESC');
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/events', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { titre, description, date, lieu, image, statut } = req.body;
        const result = await dbRun(`
            INSERT INTO events (titre, description, date, lieu, image, statut)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [titre, description, date, lieu, image, statut]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/events/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { titre, description, date, lieu, image, statut } = req.body;
        await dbRun(`
            UPDATE events SET titre = ?, description = ?, date = ?, lieu = ?, image = ?, statut = ?
            WHERE id = ?
        `, [titre, description, date, lieu, image, statut, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/events/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM events WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API GALERIE ====================

app.get('/api/gallery', async (req, res) => {
    try {
        const images = await dbAll('SELECT * FROM gallery ORDER BY ordre ASC, created_at DESC');
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/gallery', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { titre, description, image, categorie, ordre } = req.body;
        const result = await dbRun(`
            INSERT INTO gallery (titre, description, image, categorie, ordre)
            VALUES (?, ?, ?, ?, ?)
        `, [titre, description, image, categorie, ordre || 0]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/gallery/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM gallery WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API CARROUSEL ====================

app.get('/api/carousel', async (req, res) => {
    try {
        const images = await dbAll('SELECT * FROM carousel ORDER BY ordre ASC, created_at DESC');
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/carousel', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { titre, description, image, ordre } = req.body;
        const result = await dbRun(`
            INSERT INTO carousel (titre, description, image, ordre)
            VALUES (?, ?, ?, ?)
        `, [titre || '', description || '', image, ordre || 0]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/carousel/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { titre, description, image, ordre } = req.body;
        await dbRun(`
            UPDATE carousel SET titre = ?, description = ?, image = ?, ordre = ?
            WHERE id = ?
        `, [titre, description, image, ordre, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/carousel/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM carousel WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API PAIEMENT (Stripe) ====================

// Recuperer la cle publique Stripe
app.get('/api/payment/config', (req, res) => {
    res.json({
        publishableKey: STRIPE_PUBLISHABLE_KEY,
        configured: !!stripe,
        testMode: !STRIPE_PUBLISHABLE_KEY || STRIPE_PUBLISHABLE_KEY.includes('test')
    });
});

// Creer une session de paiement Stripe Checkout
app.post('/api/payment/create-checkout-session', authenticateToken, async (req, res) => {
    try {
        // Verifier que Stripe est configure
        if (!stripe) {
            return res.status(503).json({ error: 'Paiement non disponible - Stripe non configure' });
        }

        const { items, successUrl, cancelUrl, promoCode } = req.body;

        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'Panier vide' });
        }

        // Verifier le stock disponible
        for (const item of items) {
            const product = await dbGet('SELECT stock, nom FROM products WHERE id = ?', [item.id]);
            if (product && product.stock < (item.quantity || 1)) {
                return res.status(400).json({
                    error: `Stock insuffisant pour "${product.nom}" (${product.stock} disponible)`
                });
            }
        }

        let subtotal = items.reduce((sum, item) => sum + (item.price * (item.quantity || 1)), 0);
        let discountAmount = 0;
        let promoCodeUsed = null;

        // Appliquer le code promo si fourni
        if (promoCode) {
            const promo = await dbGet(`
                SELECT * FROM promo_codes
                WHERE code = ? AND active = 1
            `, [promoCode.toUpperCase()]);

            if (promo) {
                const validExpiry = !promo.expires_at || new Date(promo.expires_at) >= new Date();
                const validUses = !promo.max_uses || promo.used_count < promo.max_uses;
                const validMinOrder = subtotal >= (promo.min_order_amount || 0);

                if (validExpiry && validUses && validMinOrder) {
                    discountAmount = (subtotal * promo.discount_percent) / 100;
                    promoCodeUsed = promo.code;
                }
            }
        }

        const finalTotal = subtotal - discountAmount;

        // Construire les line items pour Stripe
        const lineItems = items.map(item => {
            // Stripe exige des URLs HTTPS completes pour les images
            let images = undefined;
            if (item.image && item.image.startsWith('https://')) {
                images = [item.image];
            }

            return {
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: item.name || 'Produit',
                        ...(item.description && { description: item.description }),
                        ...(images && { images: images }),
                    },
                    unit_amount: Math.round(item.price * 100), // Stripe utilise les centimes
                },
                quantity: item.quantity || 1,
            };
        });

        // Ajouter la reduction comme line item negatif si applicable
        if (discountAmount > 0) {
            lineItems.push({
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: `Reduction (${promoCodeUsed})`,
                    },
                    unit_amount: -Math.round(discountAmount * 100),
                },
                quantity: 1,
            });
        }

        // Creer la session Stripe Checkout
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: successUrl || `${req.headers.origin}/boutique.html?payment=success`,
            cancel_url: cancelUrl || `${req.headers.origin}/boutique.html?payment=cancel`,
            customer_email: req.user.email,
            metadata: {
                user_id: req.user.id.toString(),
                promo_code: promoCodeUsed || '',
            },
            shipping_address_collection: {
                allowed_countries: ['FR', 'BE', 'CH', 'LU', 'MC'],
            },
            billing_address_collection: 'required',
        });

        // Enregistrer la commande en base
        const orderResult = await dbRun(`
            INSERT INTO orders (user_id, stripe_session_id, total, status, items, promo_code, discount_amount)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            req.user.id,
            session.id,
            finalTotal,
            'pending',
            JSON.stringify(items),
            promoCodeUsed,
            discountAmount
        ]);

        res.json({
            sessionId: session.id,
            url: session.url,
            orderId: orderResult.lastID
        });
    } catch (error) {
        logger.error('Erreur creation session Stripe:', error);
        // Retourner le message d'erreur Stripe pour debug
        const errorMessage = error.message || 'Erreur lors de la creation du paiement';
        res.status(500).json({ error: errorMessage });
    }
});

// Verifier le statut d'un paiement
app.get('/api/payment/status/:sessionId', authenticateToken, async (req, res) => {
    try {
        if (!stripe) {
            return res.status(503).json({ error: 'Stripe non configure' });
        }
        const session = await stripe.checkout.sessions.retrieve(req.params.sessionId);

        // Traiter le paiement si confirme et pas encore traite
        if (session.payment_status === 'paid') {
            const order = await dbGet(
                'SELECT * FROM orders WHERE stripe_session_id = ?',
                [session.id]
            );
            if (order && order.status !== 'paid') {
                await processCompletedPayment(order);
            }
        }

        res.json({
            status: session.payment_status,
            customerEmail: session.customer_details?.email,
            amountTotal: session.amount_total / 100,
        });
    } catch (error) {
        logger.error('Erreur verification paiement:', error);
        res.status(500).json({ error: 'Erreur verification paiement' });
    }
});

// ==================== API UPLOAD (Cloudinary) ====================

app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Aucun fichier uploade' });
        }

        // Upload vers Cloudinary
        const b64 = Buffer.from(req.file.buffer).toString('base64');
        const dataURI = 'data:' + req.file.mimetype + ';base64,' + b64;

        const result = await cloudinary.uploader.upload(dataURI, {
            folder: 'alphamouv',
            resource_type: 'auto'
        });

        res.json({
            success: true,
            url: result.secure_url,
            filename: result.public_id
        });
    } catch (error) {
        logger.error('Erreur upload Cloudinary:', error.message || error);
        res.status(500).json({ error: 'Erreur upload: ' + (error.message || 'Cloudinary indisponible') });
    }
});

// ==================== API INSTAGRAM POSTS ====================

// Liste des posts Instagram
app.get('/api/instagram-posts', async (req, res) => {
    try {
        const posts = await dbAll('SELECT * FROM instagram_posts ORDER BY position ASC, created_at DESC');
        res.json(posts || []);
    } catch (error) {
        logger.error('Erreur chargement posts Instagram:', error);
        res.json([]);
    }
});

// Ajouter un post Instagram (admin)
const instaUpload = upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]);

app.post('/api/instagram-posts', authenticateToken, isAdmin, instaUpload, async (req, res) => {
    try {
        const { instagram_url, caption } = req.body;

        if (!instagram_url) {
            return res.status(400).json({ error: 'URL Instagram requise' });
        }
        if (!req.files || !req.files.image) {
            return res.status(400).json({ error: 'Image requise' });
        }

        // Image en base64
        const imgFile = req.files.image[0];
        const imageData = 'data:' + imgFile.mimetype + ';base64,' + Buffer.from(imgFile.buffer).toString('base64');

        // Video en base64 (optionnel)
        let videoData = '';
        if (req.files.video && req.files.video[0]) {
            const vidFile = req.files.video[0];
            videoData = 'data:' + vidFile.mimetype + ';base64,' + Buffer.from(vidFile.buffer).toString('base64');
        }

        const maxPos = await dbGet('SELECT MAX(position) as maxPos FROM instagram_posts');
        const nextPos = (maxPos && maxPos.maxPos != null) ? maxPos.maxPos + 1 : 0;

        const result = await dbRun(
            'INSERT INTO instagram_posts (instagram_url, image, video, caption, position) VALUES (?, ?, ?, ?, ?)',
            [instagram_url, imageData, videoData, caption || '', nextPos]
        );

        res.json({ success: true, id: result.lastID });
    } catch (error) {
        logger.error('Erreur ajout post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Modifier un post Instagram (admin)
app.put('/api/instagram-posts/:id', authenticateToken, isAdmin, instaUpload, async (req, res) => {
    try {
        const { instagram_url, caption } = req.body;
        const postId = req.params.id;

        let updates = ['instagram_url = ?', 'caption = ?'];
        let params = [instagram_url, caption || ''];

        if (req.files && req.files.image && req.files.image[0]) {
            const imgFile = req.files.image[0];
            const imageData = 'data:' + imgFile.mimetype + ';base64,' + Buffer.from(imgFile.buffer).toString('base64');
            updates.push('image = ?');
            params.push(imageData);
        }

        if (req.files && req.files.video && req.files.video[0]) {
            const vidFile = req.files.video[0];
            const videoData = 'data:' + vidFile.mimetype + ';base64,' + Buffer.from(vidFile.buffer).toString('base64');
            updates.push('video = ?');
            params.push(videoData);
        }

        // Si remove_video est envoye, supprimer la video
        if (req.body.remove_video === 'true') {
            updates.push('video = ?');
            params.push('');
        }

        params.push(postId);
        await dbRun('UPDATE instagram_posts SET ' + updates.join(', ') + ' WHERE id = ?', params);

        res.json({ success: true });
    } catch (error) {
        logger.error('Erreur modification post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Supprimer un post Instagram (admin)
app.delete('/api/instagram-posts/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM instagram_posts WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        logger.error('Erreur suppression post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API CONTACT ====================

app.post('/api/contact', (req, res) => {
    try {
        const { nom, email, sujet, message } = req.body;
        logger.info('Message de contact recu:', { nom, email, sujet, message });
        res.json({ success: true, message: 'Message envoye avec succes' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'envoi' });
    }
});

// ==================== API STATS ADMIN ====================

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const usersCount = await dbGet('SELECT COUNT(*) as count FROM users');
        const ordersCount = await dbGet('SELECT COUNT(*) as count FROM orders');
        const productsCount = await dbGet('SELECT COUNT(*) as count FROM products WHERE actif = 1');
        const newsletterCount = await dbGet('SELECT COUNT(*) as count FROM newsletter WHERE actif = 1');
        const revenueResult = await dbGet("SELECT SUM(total) as total FROM orders WHERE statut != 'annulee'");

        res.json({
            users: usersCount?.count || 0,
            orders: ordersCount?.count || 0,
            products: productsCount?.count || 0,
            newsletter: newsletterCount?.count || 0,
            revenue: revenueResult?.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API GESTION UTILISATEURS (ADMIN) ====================

// Liste tous les utilisateurs
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await dbAll('SELECT id, email, nom, prenom, role, created_at FROM users ORDER BY created_at DESC');
        // Dechiffrer les emails pour l'affichage admin
        const decryptedUsers = (users || []).map(u => {
            try {
                return { ...u, email: decryptData(u.email) };
            } catch (e) {
                return { ...u, email: u.email };
            }
        });
        res.json(decryptedUsers);
    } catch (error) {
        logger.error('Erreur chargement utilisateurs:', error);
        res.status(500).json({ error: 'Erreur serveur: ' + error.message });
    }
});

// Supprimer un utilisateur
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const userId = req.params.id;

        // Ne pas permettre de supprimer son propre compte
        if (parseInt(userId) === req.user.id) {
            return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
        }

        await dbRun('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ success: true, message: 'Utilisateur supprime' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Changer le role d'un utilisateur
app.put('/api/admin/users/:id/role', authenticateToken, isAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const { role } = req.body;

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Role invalide' });
        }

        // Ne pas permettre de modifier son propre role
        if (parseInt(userId) === req.user.id) {
            return res.status(400).json({ error: 'Impossible de modifier votre propre role' });
        }

        await dbRun('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
        res.json({ success: true, message: 'Role mis a jour' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API WISHLIST ====================

// Ajouter a la wishlist
app.post('/api/wishlist', authenticateToken, async (req, res) => {
    try {
        const { product_id } = req.body;

        // Verifier que le produit existe
        const product = await dbGet('SELECT id FROM products WHERE id = ?', [product_id]);
        if (!product) {
            return res.status(404).json({ error: 'Produit non trouve' });
        }

        // Verifier si deja dans la wishlist
        const existing = await dbGet('SELECT id FROM wishlist WHERE user_id = ? AND product_id = ?', [req.user.id, product_id]);
        if (existing) {
            return res.status(400).json({ error: 'Produit deja dans la wishlist' });
        }

        await dbRun('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)', [req.user.id, product_id]);
        res.json({ success: true, message: 'Produit ajoute a la wishlist' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Retirer de la wishlist
app.delete('/api/wishlist/:productId', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
        res.json({ success: true, message: 'Produit retire de la wishlist' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Obtenir la wishlist
app.get('/api/wishlist', authenticateToken, async (req, res) => {
    try {
        const wishlist = await dbAll(`
            SELECT w.id, w.product_id, w.created_at, p.nom, p.prix, p.prix_promo, p.image, p.images, p.stock
            FROM wishlist w
            JOIN products p ON w.product_id = p.id
            WHERE w.user_id = ?
            ORDER BY w.created_at DESC
        `, [req.user.id]);

        res.json(wishlist.map(item => ({
            ...item,
            images: item.images ? JSON.parse(item.images) : []
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API CODES PROMO ====================

// Verifier un code promo
app.post('/api/promo/verify', authenticateToken, async (req, res) => {
    try {
        const { code, orderTotal } = req.body;

        const promo = await dbGet(`
            SELECT * FROM promo_codes
            WHERE code = ? AND active = 1
        `, [code.toUpperCase()]);

        if (!promo) {
            return res.status(404).json({ error: 'Code promo invalide' });
        }

        // Verifier expiration
        if (promo.expires_at && new Date(promo.expires_at) < new Date()) {
            return res.status(400).json({ error: 'Code promo expire' });
        }

        // Verifier nombre d'utilisations
        if (promo.max_uses && promo.used_count >= promo.max_uses) {
            return res.status(400).json({ error: 'Code promo epuise' });
        }

        // Verifier montant minimum
        if (promo.min_order_amount && orderTotal < promo.min_order_amount) {
            return res.status(400).json({
                error: `Commande minimum de ${promo.min_order_amount}€ requise`
            });
        }

        const discount = (orderTotal * promo.discount_percent) / 100;

        res.json({
            valid: true,
            code: promo.code,
            discount_percent: promo.discount_percent,
            discount_amount: discount,
            new_total: orderTotal - discount
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Creer un code promo
app.post('/api/admin/promo', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { code, discount_percent, max_uses, min_order_amount, expires_at } = req.body;

        if (!code || !discount_percent) {
            return res.status(400).json({ error: 'Code et pourcentage requis' });
        }

        if (discount_percent < 1 || discount_percent > 100) {
            return res.status(400).json({ error: 'Pourcentage entre 1 et 100' });
        }

        const result = await dbRun(`
            INSERT INTO promo_codes (code, discount_percent, max_uses, min_order_amount, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `, [code.toUpperCase(), discount_percent, max_uses || null, min_order_amount || 0, expires_at || null]);

        res.json({ success: true, id: result.lastID });
    } catch (error) {
        if (error.message?.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Ce code existe deja' });
        }
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Liste des codes promo
app.get('/api/admin/promo', authenticateToken, isAdmin, async (req, res) => {
    try {
        const promos = await dbAll('SELECT * FROM promo_codes ORDER BY created_at DESC');
        res.json(promos);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Modifier un code promo
app.put('/api/admin/promo/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { active, discount_percent, max_uses, min_order_amount, expires_at } = req.body;

        await dbRun(`
            UPDATE promo_codes
            SET active = ?, discount_percent = ?, max_uses = ?, min_order_amount = ?, expires_at = ?
            WHERE id = ?
        `, [active ? 1 : 0, discount_percent, max_uses || null, min_order_amount || 0, expires_at || null, req.params.id]);

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Supprimer un code promo
app.delete('/api/admin/promo/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dbRun('DELETE FROM promo_codes WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API STATS AVANCEES ====================

app.get('/api/admin/stats/advanced', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Stats de base
        const usersCount = await dbGet('SELECT COUNT(*) as count FROM users WHERE role = "user"');
        const ordersCount = await dbGet('SELECT COUNT(*) as count FROM orders WHERE status = "paid"');
        const productsCount = await dbGet('SELECT COUNT(*) as count FROM products WHERE actif = 1');
        const newsletterCount = await dbGet('SELECT COUNT(*) as count FROM newsletter WHERE actif = 1');

        // Revenue total
        const revenueResult = await dbGet('SELECT SUM(total) as total FROM orders WHERE status = "paid"');

        // Revenue du mois
        const monthRevenue = await dbGet(`
            SELECT SUM(total) as total FROM orders
            WHERE status = "paid"
            AND strftime('%Y-%m', paid_at) = strftime('%Y-%m', 'now')
        `);

        // Commandes du mois
        const monthOrders = await dbGet(`
            SELECT COUNT(*) as count FROM orders
            WHERE status = "paid"
            AND strftime('%Y-%m', paid_at) = strftime('%Y-%m', 'now')
        `);

        // Top 5 produits vendus
        const topProducts = await dbAll(`
            SELECT p.id, p.nom, p.image, SUM(1) as total_sold
            FROM orders o, json_each(o.items) as item
            JOIN products p ON json_extract(item.value, '$.id') = p.id
            WHERE o.status = 'paid'
            GROUP BY p.id
            ORDER BY total_sold DESC
            LIMIT 5
        `);

        // Produits en rupture de stock
        const lowStock = await dbAll(`
            SELECT id, nom, stock FROM products
            WHERE actif = 1 AND stock <= 5
            ORDER BY stock ASC
            LIMIT 10
        `);

        // Dernieres commandes
        const recentOrdersRaw = await dbAll(`
            SELECT o.id, o.total, o.status, o.created_at, u.email, u.prenom, u.nom
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
            LIMIT 10
        `);
        // Dechiffrer les emails
        const recentOrders = recentOrdersRaw.map(o => ({
            ...o,
            email: decryptData(o.email)
        }));

        // Stats par statut de commande
        const ordersByStatus = await dbAll(`
            SELECT status, COUNT(*) as count FROM orders
            GROUP BY status
        `);

        // Codes promo actifs
        const activePromos = await dbGet('SELECT COUNT(*) as count FROM promo_codes WHERE active = 1');

        res.json({
            users: usersCount?.count || 0,
            orders: ordersCount?.count || 0,
            products: productsCount?.count || 0,
            newsletter: newsletterCount?.count || 0,
            revenue: revenueResult?.total || 0,
            monthRevenue: monthRevenue?.total || 0,
            monthOrders: monthOrders?.count || 0,
            topProducts: topProducts || [],
            lowStock: lowStock || [],
            recentOrders: recentOrders || [],
            ordersByStatus: ordersByStatus || [],
            activePromos: activePromos?.count || 0
        });
    } catch (error) {
        logger.error('Erreur stats avancees:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API GESTION STOCK ====================

// Decrementer le stock apres paiement
app.post('/api/stock/decrement', authenticateToken, async (req, res) => {
    try {
        const { items } = req.body;

        for (const item of items) {
            const product = await dbGet('SELECT stock FROM products WHERE id = ?', [item.id]);
            if (product && product.stock > 0) {
                const newStock = Math.max(0, product.stock - (item.quantity || 1));
                await dbRun('UPDATE products SET stock = ? WHERE id = ?', [newStock, item.id]);
            }
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Mettre a jour le statut d'une commande
app.put('/api/admin/orders/:id/status', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled'];

        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Statut invalide' });
        }

        await dbRun('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== GESTION 404 ====================

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// ==================== GESTION ERREURS GLOBALE ====================

// Gestionnaire d'erreurs global Express (4 parametres requis par Express)
app.use((err, req, res, _next) => {
    logger.error('Erreur non geree:', err.message || err);
    res.status(err.status || 500).json({
        error: isProduction ? 'Erreur serveur interne' : err.message
    });
});

// ==================== DEMARRAGE SERVEUR ====================

initDatabase()
    .then(() => {
        app.listen(PORT, () => {
            logger.info(`AlphaMouv - Serveur demarre sur http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        logger.error('Erreur initialisation base de donnees:', err);
        process.exit(1);
    });
