import { verifyToken } from '../utils/auth.js';
import { query } from '../database/db.js';

/**
 * Middleware pour vérifier l'authentification JWT
 */
export const authMiddleware = async (req, res, next) => {
    try {
        console.log(`🔑 [AUTH MIDDLEWARE] Vérification d'authentification pour ${req.method} ${req.path}`);

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

        if (!token) {
            console.log('❌ [AUTH MIDDLEWARE] Token manquant');
            return res.status(401).json({
                success: false,
                message: 'Token d\'authentification manquant'
            });
        }

        console.log('🔑 [AUTH MIDDLEWARE] Token présent - Vérification...');
        // Vérification du token JWT
        const decoded = verifyToken(token);
        console.log(`✅ [AUTH MIDDLEWARE] Token décodé - User ID: ${decoded.id}`);

        // Vérifier si le token est toujours valide en base de données
        const sessionResult = await query(
            `SELECT * FROM user_sessions
            WHERE user_id = $1 AND expires_at > NOW()
            LIMIT 1`,
            [decoded.id]
        );

        if (sessionResult.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Session expirée ou invalide'
            });
        }

        // Récupérer les informations utilisateur. Some DB instances may not have the
        // new `permissions` column yet, so attempt the extended query and fall back.
        let userResult;
        try {
            userResult = await query(
                `SELECT u.*, r.name as role_name, r.priority as role_priority, r.permissions as role_permissions
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                WHERE u.id = $1`,
                [decoded.id]
            );
        } catch (err) {
            // If the permissions column doesn't exist (e.g., older schema), fall back
            // to the previous query and set role_permissions to {} later.
            if (err && err.code === '42703') {
                userResult = await query(
                    `SELECT u.*, r.name as role_name, r.priority as role_priority
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE u.id = $1`,
                    [decoded.id]
                );
                // Mark that permissions are not available in DB
                userResult.rows[0].role_permissions = {};
            } else {
                throw err;
            }
        }

        if (userResult.rows.length === 0) {
            console.log('❌ [AUTH MIDDLEWARE] Utilisateur non trouvé en base');
            return res.status(401).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        // Ajouter les informations utilisateur à la requête
        // role_permissions (JSONB) will be returned as an object by node-postgres
        req.user = userResult.rows[0];
        // Ensure role_permissions exists and is an object (normalize null -> {})
        req.user.role_permissions = req.user.role_permissions || {};

        console.log(`✅ [AUTH MIDDLEWARE] Authentification réussie - User: ${req.user.email}, Role: ${req.user.role_name || 'NULL'}`);
        next();
    } catch (error) {
        console.error('Erreur d\'authentification:', error);
        return res.status(403).json({
            success: false,
            message: error.message || 'Token invalide'
        });
    }
};

/**
 * Middleware to require a specific permission key (checks role permissions JSONB)
 * @param {String} permissionKey
 */
export const requirePermission = (permissionKey) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Non authentifié' });
        }

        // Admin override: if role_name is admin, allow
        if (req.user.role_name === 'admin') return next();

        const perms = req.user.role_permissions || {};
        if (!perms[permissionKey]) {
            return res.status(403).json({ success: false, message: 'Accès refusé: permission manquante' });
        }

        next();
    };
};

/**
 * Middleware pour vérifier les rôles (RBAC)
 * @param {Array} allowedRoles - Liste des rôles autorisés
 */
export const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Non authentifié'
            });
        }

        const userRole = req.user.role_name;

        if (!allowedRoles.includes(userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Accès refusé: permissions insuffisantes'
            });
        }

        next();
    };
};

/**
 * Middleware pour vérifier la priorité minimale du rôle
 * @param {Number} minPriority - Priorité minimale requise
 */
export const requireMinPriority = (minPriority) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Non authentifié'
            });
        }

        if (req.user.role_priority < minPriority) {
            return res.status(403).json({
                success: false,
                message: 'Accès refusé: niveau de priorité insuffisant'
            });
        }

        next();
    };
};

/**
 * Middleware pour vérifier que l'email est vérifié
 */
export const requireEmailVerified = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Non authentifié'
        });
    }

    if (!req.user.is_email_verified) {
        return res.status(403).json({
            success: false,
            message: 'Email non vérifié. Veuillez vérifier votre email avant de continuer.'
        });
    }

    next();
};

// Export alias for compatibility
export { authMiddleware as authenticateToken };
