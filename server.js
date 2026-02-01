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
const fs = require('fs');
const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');

// ==================== SECURITE ====================
const helmet = require('helmet');

// ==================== CHIFFREMENT DES DONNEES ====================
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.createHash('sha256').update(process.env.JWT_SECRET || 'alphamouv_default_key_2024').digest();
const IV_LENGTH = 16;

// Chiffrer une donnee sensible
function encryptData(text) {
    if (!text) return text;
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
        console.error('Erreur chiffrement:', error);
        return text;
    }
}

// Dechiffrer une donnee sensible
function decryptData(encryptedText) {
    if (!encryptedText || !encryptedText.includes(':')) return encryptedText;
    try {
        const parts = encryptedText.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        // Retourner la valeur originale si echec (donnees non chiffrees)
        return encryptedText;
    }
}

// Verifier si une donnee est chiffree
function isEncrypted(text) {
    if (!text || typeof text !== 'string') return false;
    return text.includes(':') && /^[a-f0-9]{32}:/.test(text);
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

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 500, // 500 requetes API par minute
    message: { error: 'Trop de requetes API, reessayez dans 1 minute' },
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
    console.log('Stripe configure en mode', STRIPE_PUBLISHABLE_KEY.includes('test') ? 'TEST' : 'PRODUCTION');
} else {
    console.log('Stripe non configure - ajoutez STRIPE_SECRET_KEY pour activer les paiements');
}

// Configuration Resend (emails)
let resend = null;
if (process.env.RESEND_API_KEY) {
    const { Resend } = require('resend');
    resend = new Resend(process.env.RESEND_API_KEY);
    console.log('Resend configure pour les emails');
} else {
    console.log('Resend non configure - ajoutez RESEND_API_KEY pour activer les emails');
}

// Fonction d'envoi d'email de confirmation de commande
async function sendOrderConfirmationEmail(order, customerEmail, customerName) {
    if (!resend) {
        console.log('Email non envoye - Resend non configure');
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
            console.error('Erreur envoi email:', error);
            return false;
        }

        console.log('Email de confirmation envoye:', data?.id);
        return true;
    } catch (error) {
        console.error('Erreur envoi email:', error);
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

// Creer le dossier uploads s'il n'existe pas
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
}

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

// ==================== BASE DE DONNEES SQL.JS ====================

let db;
const DB_PATH = path.join(__dirname, 'alphamouv.db');

async function initDatabase() {
    const initSqlJs = require('sql.js');
    const SQL = await initSqlJs();

    // Charger la base existante ou en creer une nouvelle
    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
        console.log('Base de donnees chargee');
    } else {
        db = new SQL.Database();
        console.log('Nouvelle base de donnees creee');
    }

    // Creer les tables
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nom TEXT,
            prenom TEXT,
            adresse TEXT,
            code_postal TEXT,
            ville TEXT,
            telephone TEXT,
            role TEXT DEFAULT 'user',
            two_factor_secret TEXT,
            two_factor_enabled INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            description TEXT,
            prix REAL NOT NULL,
            prix_promo REAL,
            image TEXT,
            images TEXT,
            tailles TEXT,
            categorie TEXT,
            stock INTEGER DEFAULT 0,
            actif INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);


    db.run(`
        CREATE TABLE IF NOT EXISTS newsletter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            actif INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT NOT NULL,
            description TEXT,
            date TEXT,
            lieu TEXT,
            image TEXT,
            statut TEXT DEFAULT 'a_venir',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT,
            description TEXT,
            image TEXT NOT NULL,
            categorie TEXT,
            ordre INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS carousel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT,
            description TEXT,
            image TEXT NOT NULL,
            ordre INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stripe_session_id TEXT,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            items TEXT,
            shipping_address TEXT,
            paid_at TEXT,
            promo_code TEXT,
            discount_amount REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Table wishlist
    db.run(`
        CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id),
            UNIQUE(user_id, product_id)
        )
    `);

    // Table codes promo
    db.run(`
        CREATE TABLE IF NOT EXISTS promo_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount_percent INTEGER NOT NULL,
            max_uses INTEGER DEFAULT NULL,
            used_count INTEGER DEFAULT 0,
            min_order_amount REAL DEFAULT 0,
            active INTEGER DEFAULT 1,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS instagram_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instagram_url TEXT NOT NULL,
            image TEXT NOT NULL,
            caption TEXT DEFAULT '',
            position INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Migration: ajouter stripe_session_id si la table existe deja sans cette colonne
    try {
        const tableInfo = db.exec("PRAGMA table_info(orders)");
        if (tableInfo.length > 0) {
            const columns = tableInfo[0].values.map(col => col[1]);
            if (!columns.includes('stripe_session_id')) {
                db.run('ALTER TABLE orders ADD COLUMN stripe_session_id TEXT');
                console.log('Migration: colonne stripe_session_id ajoutee');
            }
            if (!columns.includes('status')) {
                db.run('ALTER TABLE orders ADD COLUMN status TEXT DEFAULT "pending"');
                console.log('Migration: colonne status ajoutee');
            }
            if (!columns.includes('shipping_address')) {
                db.run('ALTER TABLE orders ADD COLUMN shipping_address TEXT');
                console.log('Migration: colonne shipping_address ajoutee');
            }
            if (!columns.includes('paid_at')) {
                db.run('ALTER TABLE orders ADD COLUMN paid_at TEXT');
                console.log('Migration: colonne paid_at ajoutee');
            }
            if (!columns.includes('promo_code')) {
                db.run('ALTER TABLE orders ADD COLUMN promo_code TEXT');
                console.log('Migration: colonne promo_code ajoutee');
            }
            if (!columns.includes('discount_amount')) {
                db.run('ALTER TABLE orders ADD COLUMN discount_amount REAL DEFAULT 0');
                console.log('Migration: colonne discount_amount ajoutee');
            }
        }
    } catch (e) {
        console.log('Migration orders: ', e.message);
    }

    // Migration: ajouter stock aux produits si manquant
    try {
        const productTableInfo = db.exec("PRAGMA table_info(products)");
        if (productTableInfo.length > 0) {
            const productColumns = productTableInfo[0].values.map(col => col[1]);
            if (!productColumns.includes('stock')) {
                db.run('ALTER TABLE products ADD COLUMN stock INTEGER DEFAULT 0');
                console.log('Migration: colonne stock ajoutee aux produits');
            }
        }
    } catch (e) {
        console.log('Migration products: ', e.message);
    }

    // Migration: ajouter auth_provider a la table users
    try {
        const userTableInfo = db.exec("PRAGMA table_info(users)");
        if (userTableInfo.length > 0) {
            const userColumns = userTableInfo[0].values.map(col => col[1]);
            if (!userColumns.includes('auth_provider')) {
                db.run('ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT "email"');
                console.log('Migration: colonne auth_provider ajoutee');
            }
        }
    } catch (e) {
        console.log('Migration users: ', e.message);
    }

    // Migration: ajouter colonne video aux posts Instagram
    try {
        const instaTableInfo = db.exec("PRAGMA table_info(instagram_posts)");
        if (instaTableInfo.length > 0) {
            const instaColumns = instaTableInfo[0].values.map(col => col[1]);
            if (!instaColumns.includes('video')) {
                db.run('ALTER TABLE instagram_posts ADD COLUMN video TEXT DEFAULT ""');
                console.log('Migration: colonne video ajoutee aux posts Instagram');
            }
        }
    } catch (e) {
        console.log('Migration instagram_posts: ', e.message);
    }

    // Creer ou mettre a jour admin par defaut
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@alphamouv.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hashedPassword = bcrypt.hashSync(adminPassword, 10);
    const encryptedAdminEmail = encryptData(adminEmail);

    const adminResult = db.exec("SELECT id FROM users WHERE role = 'admin'");
    if (adminResult.length === 0 || adminResult[0].values.length === 0) {
        // Creer l'admin s'il n'existe pas
        db.run(`
            INSERT INTO users (email, password, nom, prenom, role)
            VALUES (?, ?, ?, ?, ?)
        `, [encryptedAdminEmail, hashedPassword, 'Admin', 'AlphaMouv', 'admin']);
        console.log('Admin cree');
    } else {
        // Mettre a jour l'email et mot de passe admin
        db.run(`
            UPDATE users SET email = ?, password = ? WHERE role = 'admin'
        `, [encryptedAdminEmail, hashedPassword]);
        console.log('Admin mis a jour');
    }

    // Migration: chiffrer les donnees existantes non chiffrees
    await migrateEncryption();

    saveDatabase();
}

// Migration pour chiffrer les donnees existantes
async function migrateEncryption() {
    console.log('Verification du chiffrement des donnees...');

    // Migrer les utilisateurs
    const users = dbAll('SELECT id, email, adresse, telephone FROM users');
    let usersMigrated = 0;
    for (const user of users) {
        let needsUpdate = false;
        const updates = {};

        if (user.email && !isEncrypted(user.email)) {
            updates.email = encryptData(user.email);
            needsUpdate = true;
        }
        if (user.adresse && !isEncrypted(user.adresse)) {
            updates.adresse = encryptData(user.adresse);
            needsUpdate = true;
        }
        if (user.telephone && !isEncrypted(user.telephone)) {
            updates.telephone = encryptData(user.telephone);
            needsUpdate = true;
        }

        if (needsUpdate) {
            db.run(`
                UPDATE users SET
                    email = COALESCE(?, email),
                    adresse = COALESCE(?, adresse),
                    telephone = COALESCE(?, telephone)
                WHERE id = ?
            `, [updates.email || null, updates.adresse || null, updates.telephone || null, user.id]);
            usersMigrated++;
        }
    }
    if (usersMigrated > 0) {
        console.log(`Migration: ${usersMigrated} utilisateur(s) chiffre(s)`);
    }

    // Migrer la newsletter
    const subscribers = dbAll('SELECT id, email FROM newsletter');
    let newsletterMigrated = 0;
    for (const sub of subscribers) {
        if (sub.email && !isEncrypted(sub.email)) {
            const encryptedEmail = encryptData(sub.email);
            db.run('UPDATE newsletter SET email = ? WHERE id = ?', [encryptedEmail, sub.id]);
            newsletterMigrated++;
        }
    }
    if (newsletterMigrated > 0) {
        console.log(`Migration: ${newsletterMigrated} email(s) newsletter chiffre(s)`);
    }

    console.log('Chiffrement des donnees verifie');
}

function saveDatabase() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
}

// Helpers pour simplifier les requetes
function dbGet(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
        const row = stmt.getAsObject();
        stmt.free();
        return row;
    }
    stmt.free();
    return null;
}

function dbAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

function dbRun(sql, params = []) {
    db.run(sql, params);
    saveDatabase();
    return { lastID: db.exec("SELECT last_insert_rowid()")[0]?.values[0]?.[0] };
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
        const allUsers = dbAll('SELECT * FROM users');
        let user = allUsers.find(u => {
            const decryptedEmail = decryptData(u.email);
            return decryptedEmail === email || u.email === email;
        });

        if (!user) {
            // Creer un nouvel utilisateur Google avec email chiffre
            const randomPassword = bcrypt.hashSync(Math.random().toString(36), 10);
            const encryptedEmail = encryptData(email);
            const result = dbRun(`
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
        console.error('Erreur connexion Google:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion Google' });
    }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { email, password, nom, prenom, adresse, code_postal, ville, telephone } = req.body;

        // Rechercher avec email chiffre ou non (pour compatibilite)
        const allUsers = dbAll('SELECT id, email FROM users');
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

        const result = dbRun(`
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
        console.error('Erreur inscription:', error);
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Rechercher l'utilisateur avec email chiffre ou non
        const allUsers = dbAll('SELECT * FROM users');
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
        console.error('Erreur connexion:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion' });
    }
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
    try {
        const user = dbGet('SELECT id, email, nom, prenom, adresse, code_postal, ville, telephone, role FROM users WHERE id = ?', [req.user.id]);
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

app.put('/api/auth/profile', authenticateToken, (req, res) => {
    try {
        const { nom, prenom, adresse, code_postal, ville, telephone } = req.body;

        // Chiffrer les donnees sensibles
        const encryptedAdresse = adresse ? encryptData(adresse) : null;
        const encryptedTelephone = telephone ? encryptData(telephone) : null;

        dbRun(`
            UPDATE users SET nom = ?, prenom = ?, adresse = ?, code_postal = ?, ville = ?, telephone = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [nom, prenom, encryptedAdresse, code_postal, ville, encryptedTelephone, req.user.id]);

        res.json({ success: true, message: 'Profil mis a jour' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la mise a jour' });
    }
});

app.put('/api/auth/password', authenticateToken, (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);

        if (!bcrypt.compareSync(currentPassword, user.password)) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect' });
        }

        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        dbRun('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [hashedPassword, req.user.id]);

        res.json({ success: true, message: 'Mot de passe modifie' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du changement de mot de passe' });
    }
});

// ==================== API PRODUITS ====================

app.get('/api/products', (req, res) => {
    try {
        const products = dbAll('SELECT * FROM products WHERE actif = 1 ORDER BY created_at DESC');
        res.json(products.map(p => ({
            ...p,
            images: p.images ? JSON.parse(p.images) : [],
            tailles: p.tailles ? JSON.parse(p.tailles) : []
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/products/:id', (req, res) => {
    try {
        const product = dbGet('SELECT * FROM products WHERE id = ?', [req.params.id]);
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

app.post('/api/products', authenticateToken, isAdmin, (req, res) => {
    try {
        const { nom, description, prix, prix_promo, image, images, tailles, categorie, stock } = req.body;

        const result = dbRun(`
            INSERT INTO products (nom, description, prix, prix_promo, image, images, tailles, categorie, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [nom, description, prix, prix_promo, image, JSON.stringify(images || []), JSON.stringify(tailles || []), categorie, stock || 0]);

        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la creation' });
    }
});

app.put('/api/products/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const { nom, description, prix, prix_promo, image, images, tailles, categorie, stock, actif } = req.body;

        dbRun(`
            UPDATE products SET nom = ?, description = ?, prix = ?, prix_promo = ?, image = ?, images = ?, tailles = ?, categorie = ?, stock = ?, actif = ?
            WHERE id = ?
        `, [nom, description, prix, prix_promo, image, JSON.stringify(images || []), JSON.stringify(tailles || []), categorie, stock, actif, req.params.id]);

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la modification' });
    }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM products WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
});

// ==================== API COMMANDES ====================

app.post('/api/orders', authenticateToken, (req, res) => {
    try {
        const { items, adresse_livraison, total } = req.body;
        const numero = 'CMD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();

        const result = dbRun(`
            INSERT INTO orders (user_id, numero, total, adresse_livraison, items)
            VALUES (?, ?, ?, ?, ?)
        `, [req.user.id, numero, total, adresse_livraison, JSON.stringify(items)]);

        res.json({ success: true, numero, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la creation de la commande' });
    }
});

app.get('/api/orders', authenticateToken, (req, res) => {
    try {
        const orders = dbAll('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
        res.json(orders.map(o => ({
            ...o,
            items: JSON.parse(o.items || '[]')
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/admin/orders', authenticateToken, isAdmin, (req, res) => {
    try {
        const orders = dbAll(`
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

app.put('/api/admin/orders/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const { statut } = req.body;
        dbRun('UPDATE orders SET statut = ? WHERE id = ?', [statut, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API NEWSLETTER ====================

app.post('/api/newsletter', (req, res) => {
    try {
        const { email } = req.body;

        // Verifier si l'email existe deja (chiffre ou non)
        const allSubscribers = dbAll('SELECT id, email FROM newsletter');
        const existing = allSubscribers.find(s => {
            const decryptedEmail = decryptData(s.email);
            return decryptedEmail === email || s.email === email;
        });

        if (existing) {
            return res.status(400).json({ error: 'Cet email est deja inscrit' });
        }

        // Chiffrer l'email avant stockage
        const encryptedEmail = encryptData(email);
        dbRun('INSERT INTO newsletter (email) VALUES (?)', [encryptedEmail]);
        res.json({ success: true, message: 'Inscription reussie a la newsletter' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.get('/api/admin/newsletter', authenticateToken, isAdmin, (req, res) => {
    try {
        const subscribers = dbAll('SELECT * FROM newsletter WHERE actif = 1 ORDER BY created_at DESC');
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

app.get('/api/events', (req, res) => {
    try {
        const events = dbAll('SELECT * FROM events ORDER BY date DESC');
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/events', authenticateToken, isAdmin, (req, res) => {
    try {
        const { titre, description, date, lieu, image, statut } = req.body;
        const result = dbRun(`
            INSERT INTO events (titre, description, date, lieu, image, statut)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [titre, description, date, lieu, image, statut]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/events/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const { titre, description, date, lieu, image, statut } = req.body;
        dbRun(`
            UPDATE events SET titre = ?, description = ?, date = ?, lieu = ?, image = ?, statut = ?
            WHERE id = ?
        `, [titre, description, date, lieu, image, statut, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/events/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM events WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API GALERIE ====================

app.get('/api/gallery', (req, res) => {
    try {
        const images = dbAll('SELECT * FROM gallery ORDER BY ordre ASC, created_at DESC');
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/gallery', authenticateToken, isAdmin, (req, res) => {
    try {
        const { titre, description, image, categorie, ordre } = req.body;
        const result = dbRun(`
            INSERT INTO gallery (titre, description, image, categorie, ordre)
            VALUES (?, ?, ?, ?, ?)
        `, [titre, description, image, categorie, ordre || 0]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/gallery/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM gallery WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API CARROUSEL ====================

app.get('/api/carousel', (req, res) => {
    try {
        const images = dbAll('SELECT * FROM carousel ORDER BY ordre ASC, created_at DESC');
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/carousel', authenticateToken, isAdmin, (req, res) => {
    try {
        const { titre, description, image, ordre } = req.body;
        const result = dbRun(`
            INSERT INTO carousel (titre, description, image, ordre)
            VALUES (?, ?, ?, ?)
        `, [titre || '', description || '', image, ordre || 0]);
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/carousel/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const { titre, description, image, ordre } = req.body;
        dbRun(`
            UPDATE carousel SET titre = ?, description = ?, image = ?, ordre = ?
            WHERE id = ?
        `, [titre, description, image, ordre, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/carousel/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM carousel WHERE id = ?', [req.params.id]);
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
            const product = dbGet('SELECT stock, nom FROM products WHERE id = ?', [item.id]);
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
            const promo = dbGet(`
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
        const orderResult = dbRun(`
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
        console.error('Erreur creation session Stripe:', error);
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

        // Mettre a jour le statut de la commande si paye
        if (session.payment_status === 'paid') {
            // Verifier si la commande n'a pas deja ete traitee
            const order = dbGet('SELECT * FROM orders WHERE stripe_session_id = ?', [session.id]);

            if (order && order.status !== 'paid') {
                // Mettre a jour le statut
                dbRun(`
                    UPDATE orders SET status = 'paid', paid_at = CURRENT_TIMESTAMP
                    WHERE stripe_session_id = ?
                `, [session.id]);

                // Decrementer le stock des produits
                try {
                    const items = JSON.parse(order.items || '[]');
                    for (const item of items) {
                        const product = dbGet('SELECT stock FROM products WHERE id = ?', [item.id]);
                        if (product) {
                            const newStock = Math.max(0, product.stock - (item.quantity || 1));
                            dbRun('UPDATE products SET stock = ? WHERE id = ?', [newStock, item.id]);
                        }
                    }
                } catch (e) {
                    console.error('Erreur decrementation stock:', e);
                }

                // Incrementer le compteur du code promo si utilise
                if (order.promo_code) {
                    dbRun(`
                        UPDATE promo_codes SET used_count = used_count + 1
                        WHERE code = ?
                    `, [order.promo_code]);
                }

                // Envoyer l'email de confirmation
                const user = dbGet('SELECT * FROM users WHERE id = ?', [order.user_id]);
                if (user) {
                    const decryptedEmail = decryptData(user.email);
                    const customerName = user.prenom ? `${user.prenom} ${user.nom || ''}`.trim() : decryptedEmail;
                    await sendOrderConfirmationEmail(
                        { ...order, status: 'paid' },
                        decryptedEmail,
                        customerName
                    );
                }
            }
        }

        res.json({
            status: session.payment_status,
            customerEmail: session.customer_details?.email,
            amountTotal: session.amount_total / 100,
        });
    } catch (error) {
        console.error('Erreur verification paiement:', error);
        res.status(500).json({ error: 'Erreur verification paiement' });
    }
});

// Historique des commandes utilisateur
app.get('/api/orders', authenticateToken, (req, res) => {
    try {
        const orders = dbAll(`
            SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC
        `, [req.user.id]);
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Toutes les commandes
app.get('/api/admin/orders', authenticateToken, isAdmin, (req, res) => {
    try {
        const orders = dbAll(`
            SELECT o.*, u.email, u.nom, u.prenom
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
        `);
        // Dechiffrer les emails utilisateurs
        res.json(orders.map(o => ({
            ...o,
            email: decryptData(o.email)
        })));
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
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
        res.status(500).json({ error: 'Erreur lors de l\'upload' });
    }
});

// ==================== API INSTAGRAM POSTS ====================

// Liste des posts Instagram
app.get('/api/instagram-posts', (req, res) => {
    try {
        const posts = dbAll('SELECT * FROM instagram_posts ORDER BY position ASC, created_at DESC');
        res.json(posts || []);
    } catch (error) {
        console.error('Erreur chargement posts Instagram:', error);
        res.json([]);
    }
});

// Ajouter un post Instagram (admin)
var instaUpload = upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]);

app.post('/api/instagram-posts', authenticateToken, isAdmin, instaUpload, (req, res) => {
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

        const maxPos = dbGet('SELECT MAX(position) as maxPos FROM instagram_posts');
        const nextPos = (maxPos && maxPos.maxPos != null) ? maxPos.maxPos + 1 : 0;

        const result = dbRun(
            'INSERT INTO instagram_posts (instagram_url, image, video, caption, position) VALUES (?, ?, ?, ?, ?)',
            [instagram_url, imageData, videoData, caption || '', nextPos]
        );

        res.json({ success: true, id: result.lastID });
    } catch (error) {
        console.error('Erreur ajout post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Modifier un post Instagram (admin)
app.put('/api/instagram-posts/:id', authenticateToken, isAdmin, instaUpload, (req, res) => {
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
        dbRun('UPDATE instagram_posts SET ' + updates.join(', ') + ' WHERE id = ?', params);

        res.json({ success: true });
    } catch (error) {
        console.error('Erreur modification post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Supprimer un post Instagram (admin)
app.delete('/api/instagram-posts/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM instagram_posts WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Erreur suppression post Instagram:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API CONTACT ====================

app.post('/api/contact', (req, res) => {
    try {
        const { nom, email, sujet, message } = req.body;
        console.log('Message de contact recu:', { nom, email, sujet, message });
        res.json({ success: true, message: 'Message envoye avec succes' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'envoi' });
    }
});

// ==================== API STATS ADMIN ====================

app.get('/api/admin/stats', authenticateToken, isAdmin, (req, res) => {
    try {
        const usersCount = dbGet('SELECT COUNT(*) as count FROM users');
        const ordersCount = dbGet('SELECT COUNT(*) as count FROM orders');
        const productsCount = dbGet('SELECT COUNT(*) as count FROM products WHERE actif = 1');
        const newsletterCount = dbGet('SELECT COUNT(*) as count FROM newsletter WHERE actif = 1');
        const revenueResult = dbGet("SELECT SUM(total) as total FROM orders WHERE statut != 'annulee'");

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
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    try {
        const users = dbAll('SELECT id, email, nom, prenom, role, created_at FROM users ORDER BY created_at DESC');
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
        console.error('Erreur chargement utilisateurs:', error);
        res.status(500).json({ error: 'Erreur serveur: ' + error.message });
    }
});

// Supprimer un utilisateur
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const userId = req.params.id;

        // Ne pas permettre de supprimer son propre compte
        if (parseInt(userId) === req.user.id) {
            return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
        }

        dbRun('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ success: true, message: 'Utilisateur supprime' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Changer le role d'un utilisateur
app.put('/api/admin/users/:id/role', authenticateToken, isAdmin, (req, res) => {
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

        dbRun('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
        res.json({ success: true, message: 'Role mis a jour' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API WISHLIST ====================

// Ajouter a la wishlist
app.post('/api/wishlist', authenticateToken, (req, res) => {
    try {
        const { product_id } = req.body;

        // Verifier que le produit existe
        const product = dbGet('SELECT id FROM products WHERE id = ?', [product_id]);
        if (!product) {
            return res.status(404).json({ error: 'Produit non trouve' });
        }

        // Verifier si deja dans la wishlist
        const existing = dbGet('SELECT id FROM wishlist WHERE user_id = ? AND product_id = ?', [req.user.id, product_id]);
        if (existing) {
            return res.status(400).json({ error: 'Produit deja dans la wishlist' });
        }

        dbRun('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)', [req.user.id, product_id]);
        res.json({ success: true, message: 'Produit ajoute a la wishlist' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Retirer de la wishlist
app.delete('/api/wishlist/:productId', authenticateToken, (req, res) => {
    try {
        dbRun('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
        res.json({ success: true, message: 'Produit retire de la wishlist' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Obtenir la wishlist
app.get('/api/wishlist', authenticateToken, (req, res) => {
    try {
        const wishlist = dbAll(`
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
app.post('/api/promo/verify', authenticateToken, (req, res) => {
    try {
        const { code, orderTotal } = req.body;

        const promo = dbGet(`
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
app.post('/api/admin/promo', authenticateToken, isAdmin, (req, res) => {
    try {
        const { code, discount_percent, max_uses, min_order_amount, expires_at } = req.body;

        if (!code || !discount_percent) {
            return res.status(400).json({ error: 'Code et pourcentage requis' });
        }

        if (discount_percent < 1 || discount_percent > 100) {
            return res.status(400).json({ error: 'Pourcentage entre 1 et 100' });
        }

        const result = dbRun(`
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
app.get('/api/admin/promo', authenticateToken, isAdmin, (req, res) => {
    try {
        const promos = dbAll('SELECT * FROM promo_codes ORDER BY created_at DESC');
        res.json(promos);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Modifier un code promo
app.put('/api/admin/promo/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        const { active, discount_percent, max_uses, min_order_amount, expires_at } = req.body;

        dbRun(`
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
app.delete('/api/admin/promo/:id', authenticateToken, isAdmin, (req, res) => {
    try {
        dbRun('DELETE FROM promo_codes WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API STATS AVANCEES ====================

app.get('/api/admin/stats/advanced', authenticateToken, isAdmin, (req, res) => {
    try {
        // Stats de base
        const usersCount = dbGet('SELECT COUNT(*) as count FROM users WHERE role = "user"');
        const ordersCount = dbGet('SELECT COUNT(*) as count FROM orders WHERE status = "paid"');
        const productsCount = dbGet('SELECT COUNT(*) as count FROM products WHERE actif = 1');
        const newsletterCount = dbGet('SELECT COUNT(*) as count FROM newsletter WHERE actif = 1');

        // Revenue total
        const revenueResult = dbGet('SELECT SUM(total) as total FROM orders WHERE status = "paid"');

        // Revenue du mois
        const monthRevenue = dbGet(`
            SELECT SUM(total) as total FROM orders
            WHERE status = "paid"
            AND strftime('%Y-%m', paid_at) = strftime('%Y-%m', 'now')
        `);

        // Commandes du mois
        const monthOrders = dbGet(`
            SELECT COUNT(*) as count FROM orders
            WHERE status = "paid"
            AND strftime('%Y-%m', paid_at) = strftime('%Y-%m', 'now')
        `);

        // Top 5 produits vendus
        const topProducts = dbAll(`
            SELECT p.id, p.nom, p.image, SUM(1) as total_sold
            FROM orders o, json_each(o.items) as item
            JOIN products p ON json_extract(item.value, '$.id') = p.id
            WHERE o.status = 'paid'
            GROUP BY p.id
            ORDER BY total_sold DESC
            LIMIT 5
        `);

        // Produits en rupture de stock
        const lowStock = dbAll(`
            SELECT id, nom, stock FROM products
            WHERE actif = 1 AND stock <= 5
            ORDER BY stock ASC
            LIMIT 10
        `);

        // Dernieres commandes
        const recentOrdersRaw = dbAll(`
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
        const ordersByStatus = dbAll(`
            SELECT status, COUNT(*) as count FROM orders
            GROUP BY status
        `);

        // Codes promo actifs
        const activePromos = dbGet('SELECT COUNT(*) as count FROM promo_codes WHERE active = 1');

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
        console.error('Erreur stats avancees:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== API GESTION STOCK ====================

// Decrementer le stock apres paiement
app.post('/api/stock/decrement', authenticateToken, async (req, res) => {
    try {
        const { items } = req.body;

        for (const item of items) {
            const product = dbGet('SELECT stock FROM products WHERE id = ?', [item.id]);
            if (product && product.stock > 0) {
                const newStock = Math.max(0, product.stock - (item.quantity || 1));
                dbRun('UPDATE products SET stock = ? WHERE id = ?', [newStock, item.id]);
            }
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Admin: Mettre a jour le statut d'une commande
app.put('/api/admin/orders/:id/status', authenticateToken, isAdmin, (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled'];

        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Statut invalide' });
        }

        dbRun('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== GESTION 404 ====================

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// ==================== DEMARRAGE SERVEUR ====================

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`
    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║     AlphaMouv - Serveur demarre            ║
    ║                                            ║
    ║     URL: http://localhost:${PORT}             ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
        `);
    });
}).catch(err => {
    console.error('Erreur initialisation base de donnees:', err);
});
