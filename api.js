/**
 * API Client - AlphaMouv
 * Gestion des communications avec le backend
 */

// Detecte automatiquement l'URL (localhost ou production)
const API_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:3000/api'
    : window.location.origin + '/api';

// Stockage du token
let authToken = localStorage.getItem('alphamouv_token');

// ==================== UTILITAIRES ====================

function setAuthToken(token) {
    authToken = token;
    if (token) {
        localStorage.setItem('alphamouv_token', token);
    } else {
        localStorage.removeItem('alphamouv_token');
    }
}

function getAuthToken() {
    return authToken || localStorage.getItem('alphamouv_token');
}

async function apiRequest(endpoint, options = {}) {
    const url = `${API_URL}${endpoint}`;
    const token = getAuthToken();

    const config = {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
    };

    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Erreur serveur');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ==================== AUTHENTIFICATION ====================

const AuthAPI = {
    // Inscription
    async register(userData) {
        const data = await apiRequest('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData),
        });
        if (data.token) {
            setAuthToken(data.token);
        }
        return data;
    },

    // Connexion
    async login(email, password) {
        const data = await apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });
        if (data.token) {
            setAuthToken(data.token);
        }
        return data;
    },

    // Deconnexion
    logout() {
        setAuthToken(null);
        localStorage.removeItem('alphamouv_user');
    },

    // Profil
    async getProfile() {
        return await apiRequest('/auth/profile');
    },

    // Mise a jour profil
    async updateProfile(profileData) {
        return await apiRequest('/auth/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData),
        });
    },

    // Changement mot de passe
    async changePassword(currentPassword, newPassword) {
        return await apiRequest('/auth/password', {
            method: 'PUT',
            body: JSON.stringify({ currentPassword, newPassword }),
        });
    },

    // Verifier si connecte
    isLoggedIn() {
        return !!getAuthToken();
    },
};

// ==================== PRODUITS ====================

const ProductsAPI = {
    // Liste des produits
    async getAll() {
        return await apiRequest('/products');
    },

    // Detail d'un produit
    async getById(id) {
        return await apiRequest(`/products/${id}`);
    },

    // Creer un produit (admin)
    async create(productData) {
        return await apiRequest('/products', {
            method: 'POST',
            body: JSON.stringify(productData),
        });
    },

    // Modifier un produit (admin)
    async update(id, productData) {
        return await apiRequest(`/products/${id}`, {
            method: 'PUT',
            body: JSON.stringify(productData),
        });
    },

    // Supprimer un produit (admin)
    async delete(id) {
        return await apiRequest(`/products/${id}`, {
            method: 'DELETE',
        });
    },
};

// ==================== COMMANDES ====================

const OrdersAPI = {
    // Creer une commande
    async create(orderData) {
        return await apiRequest('/orders', {
            method: 'POST',
            body: JSON.stringify(orderData),
        });
    },

    // Mes commandes
    async getMyOrders() {
        return await apiRequest('/orders');
    },

    // Toutes les commandes (admin)
    async getAllOrders() {
        return await apiRequest('/admin/orders');
    },

    // Mettre a jour statut (admin)
    async updateStatus(id, statut) {
        return await apiRequest(`/admin/orders/${id}`, {
            method: 'PUT',
            body: JSON.stringify({ statut }),
        });
    },
};

// ==================== NEWSLETTER ====================

const NewsletterAPI = {
    // S'inscrire
    async subscribe(email) {
        return await apiRequest('/newsletter', {
            method: 'POST',
            body: JSON.stringify({ email }),
        });
    },

    // Liste des abonnes (admin)
    async getSubscribers() {
        return await apiRequest('/admin/newsletter');
    },
};

// ==================== EVENEMENTS ====================

const EventsAPI = {
    // Liste des evenements
    async getAll() {
        return await apiRequest('/events');
    },

    // Creer un evenement (admin)
    async create(eventData) {
        return await apiRequest('/events', {
            method: 'POST',
            body: JSON.stringify(eventData),
        });
    },

    // Modifier un evenement (admin)
    async update(id, eventData) {
        return await apiRequest(`/events/${id}`, {
            method: 'PUT',
            body: JSON.stringify(eventData),
        });
    },

    // Supprimer un evenement (admin)
    async delete(id) {
        return await apiRequest(`/events/${id}`, {
            method: 'DELETE',
        });
    },
};

// ==================== GALERIE ====================

const GalleryAPI = {
    // Liste des images
    async getAll() {
        return await apiRequest('/gallery');
    },

    // Ajouter une image (admin)
    async add(imageData) {
        return await apiRequest('/gallery', {
            method: 'POST',
            body: JSON.stringify(imageData),
        });
    },

    // Supprimer une image (admin)
    async delete(id) {
        return await apiRequest(`/gallery/${id}`, {
            method: 'DELETE',
        });
    },
};

// ==================== UPLOAD ====================

const UploadAPI = {
    // Upload d'image
    async uploadImage(file) {
        const formData = new FormData();
        formData.append('image', file);

        const token = getAuthToken();
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            body: formData,
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Erreur upload');
        }
        return data;
    },
};

// ==================== CONTACT ====================

const ContactAPI = {
    // Envoyer un message
    async send(contactData) {
        return await apiRequest('/contact', {
            method: 'POST',
            body: JSON.stringify(contactData),
        });
    },
};

// ==================== STATS ADMIN ====================

const StatsAPI = {
    // Statistiques
    async get() {
        return await apiRequest('/admin/stats');
    },
};

// ==================== UTILISATEURS (ADMIN) ====================

const UsersAPI = {
    // Liste des utilisateurs
    async getAll() {
        return await apiRequest('/admin/users');
    },

    // Supprimer un utilisateur
    async delete(id) {
        return await apiRequest(`/admin/users/${id}`, {
            method: 'DELETE',
        });
    },

    // Changer le role d'un utilisateur
    async updateRole(id, role) {
        return await apiRequest(`/admin/users/${id}/role`, {
            method: 'PUT',
            body: JSON.stringify({ role }),
        });
    },
};

// ==================== EXPORT ====================

// Pour utilisation dans le navigateur
window.AlphaMovAPI = {
    Auth: AuthAPI,
    Products: ProductsAPI,
    Orders: OrdersAPI,
    Newsletter: NewsletterAPI,
    Events: EventsAPI,
    Gallery: GalleryAPI,
    Upload: UploadAPI,
    Contact: ContactAPI,
    Stats: StatsAPI,
    Users: UsersAPI,
    setAuthToken,
    getAuthToken,
    isLoggedIn: AuthAPI.isLoggedIn,
};

console.log('AlphaMouv API Client loaded');
