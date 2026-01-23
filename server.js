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

// ==================== SECURITE ====================
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Rate limiters pour differentes routes
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requetes par IP
    message: { error: 'Trop de requetes, reessayez dans 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 tentatives de login par IP
    message: { error: 'Trop de tentatives de connexion, reessayez dans 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // 30 requetes API par minute
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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'alphamouv_secret_2024';

// ==================== CONFIGURATION ====================

// Middleware de securite
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://accounts.google.com", "https://www.instagram.com"],
            imgSrc: ["'self'", "data:", "blob:", "https:", "http:"],
            connectSrc: ["'self'", "https://accounts.google.com", "https://www.instagram.com", "https://res.cloudinary.com"],
            frameSrc: ["'self'", "https://accounts.google.com", "https://www.instagram.com"],
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
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            numero TEXT UNIQUE NOT NULL,
            total REAL NOT NULL,
            statut TEXT DEFAULT 'en_attente',
            adresse_livraison TEXT,
            items TEXT,
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

    // Creer ou mettre a jour admin par defaut
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@alphamouv.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hashedPassword = bcrypt.hashSync(adminPassword, 10);

    const adminResult = db.exec("SELECT id FROM users WHERE role = 'admin'");
    if (adminResult.length === 0 || adminResult[0].values.length === 0) {
        // Creer l'admin s'il n'existe pas
        db.run(`
            INSERT INTO users (email, password, nom, prenom, role)
            VALUES (?, ?, ?, ?, ?)
        `, [adminEmail, hashedPassword, 'Admin', 'AlphaMouv', 'admin']);
        console.log('Admin cree');
    } else {
        // Mettre a jour l'email et mot de passe admin
        db.run(`
            UPDATE users SET email = ?, password = ? WHERE role = 'admin'
        `, [adminEmail, hashedPassword]);
        console.log('Admin mis a jour');
    }

    saveDatabase();
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

        // Chercher ou creer l'utilisateur
        let user = dbGet('SELECT * FROM users WHERE email = ?', [email]);

        if (!user) {
            // Creer un nouvel utilisateur
            const randomPassword = bcrypt.hashSync(Math.random().toString(36), 10);
            const result = dbRun(`
                INSERT INTO users (email, password, nom, prenom, role)
                VALUES (?, ?, ?, ?, ?)
            `, [email, randomPassword, nom, prenom, 'user']);

            user = {
                id: result.lastID,
                email: email,
                nom: nom,
                prenom: prenom,
                role: 'user'
            };
        }

        // Generer le token JWT
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
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

        const existingUser = dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est deja utilise' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        const result = dbRun(`
            INSERT INTO users (email, password, nom, prenom, adresse, code_postal, ville, telephone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [email, hashedPassword, nom, prenom, adresse, code_postal, ville, telephone]);

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

        const user = dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                nom: user.nom,
                prenom: user.prenom,
                role: user.role,
                adresse: user.adresse,
                code_postal: user.code_postal,
                ville: user.ville,
                telephone: user.telephone
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
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.put('/api/auth/profile', authenticateToken, (req, res) => {
    try {
        const { nom, prenom, adresse, code_postal, ville, telephone } = req.body;

        dbRun(`
            UPDATE users SET nom = ?, prenom = ?, adresse = ?, code_postal = ?, ville = ?, telephone = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [nom, prenom, adresse, code_postal, ville, telephone, req.user.id]);

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
        res.json(orders.map(o => ({
            ...o,
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

        const existing = dbGet('SELECT id FROM newsletter WHERE email = ?', [email]);
        if (existing) {
            return res.status(400).json({ error: 'Cet email est deja inscrit' });
        }

        dbRun('INSERT INTO newsletter (email) VALUES (?)', [email]);
        res.json({ success: true, message: 'Inscription reussie a la newsletter' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.get('/api/admin/newsletter', authenticateToken, isAdmin, (req, res) => {
    try {
        const subscribers = dbAll('SELECT * FROM newsletter WHERE actif = 1 ORDER BY created_at DESC');
        res.json(subscribers);
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
        res.json(users || []);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
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
