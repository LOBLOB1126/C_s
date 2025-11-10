import { query, getClient } from '../database/db.js';
import { logSecurityEvent, SecurityActions } from '../utils/logger.js';

/**
 * Obtenir tous les utilisateurs (Admin/Moderator)
 */
export const getAllUsers = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;

        const usersResult = await query(
            `SELECT u.id, u.email, u.phone, u.is_email_verified, u.is_phone_verified,
                    u.is_2fa_enabled, u.last_login, u.created_at,
                    r.name as role, r.priority as role_priority
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC
            LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        const countResult = await query('SELECT COUNT(*) FROM users');
        const totalUsers = parseInt(countResult.rows[0].count);

        res.json({
            success: true,
            data: {
                users: usersResult.rows,
                pagination: {
                    page,
                    limit,
                    total: totalUsers,
                    totalPages: Math.ceil(totalUsers / limit)
                }
            }
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des utilisateurs:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la récupération des utilisateurs'
        });
    }
};

/**
 * Obtenir un utilisateur spécifique
 */
export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;

        const userResult = await query(
            `SELECT u.id, u.email, u.phone, u.is_email_verified, u.is_phone_verified,
                    u.is_2fa_enabled, u.last_login, u.created_at, u.login_attempts, u.locked_until,
                    r.name as role, r.priority as role_priority
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = $1`,
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        res.json({
            success: true,
            data: userResult.rows[0]
        });
    } catch (error) {
        console.error('Erreur lors de la récupération de l\'utilisateur:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la récupération de l\'utilisateur'
        });
    }
};

/**
 * Changer le rôle d'un utilisateur (Admin uniquement)
 */
export const changeUserRole = async (req, res) => {
    try {
        const { userId } = req.params;
        const { roleName } = req.body;
        const adminId = req.user.id;

        // Vérifier que l'utilisateur cible existe
        const userResult = await query(
            'SELECT id, email FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        // Empêcher l'admin de changer son propre rôle
        if (userId === adminId) {
            return res.status(403).json({
                success: false,
                message: 'Vous ne pouvez pas changer votre propre rôle'
            });
        }

        // Vérifier que le rôle existe
        const roleResult = await query(
            'SELECT id, name FROM roles WHERE name = $1',
            [roleName]
        );

        if (roleResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Rôle non trouvé'
            });
        }

        // Changer le rôle
        await query(
            'UPDATE users SET role_id = $1 WHERE id = $2',
            [roleResult.rows[0].id, userId]
        );

        await logSecurityEvent(
            adminId,
            SecurityActions.ROLE_CHANGE,
            true,
            `Changed role of user ${userResult.rows[0].email} to ${roleName}`,
            req
        );

        res.json({
            success: true,
            message: `Rôle de l'utilisateur changé en ${roleName}`
        });
    } catch (error) {
        console.error('Erreur lors du changement de rôle:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors du changement de rôle'
        });
    }
};

/**
 * Verrouiller/Déverrouiller un compte utilisateur
 */
export const toggleUserLock = async (req, res) => {
    try {
        const { userId } = req.params;
        const { lock } = req.body; // true pour verrouiller, false pour déverrouiller
        const adminId = req.user.id;

        // Empêcher l'admin de se verrouiller lui-même
        if (userId === adminId) {
            return res.status(403).json({
                success: false,
                message: 'Vous ne pouvez pas verrouiller votre propre compte'
            });
        }

        // Vérifier que l'utilisateur existe
        const userResult = await query(
            'SELECT id, email FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        const lockedUntil = lock ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) : null; // 1 an ou null

        await query(
            'UPDATE users SET locked_until = $1 WHERE id = $2',
            [lockedUntil, userId]
        );

        await logSecurityEvent(
            adminId,
            lock ? SecurityActions.ACCOUNT_LOCKED : SecurityActions.ACCOUNT_UNLOCKED,
            true,
            `${lock ? 'Locked' : 'Unlocked'} account of user ${userResult.rows[0].email}`,
            req
        );

        res.json({
            success: true,
            message: `Compte ${lock ? 'verrouillé' : 'déverrouillé'} avec succès`
        });
    } catch (error) {
        console.error('Erreur lors du verrouillage/déverrouillage:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de l\'opération'
        });
    }
};

/**
 * Supprimer un utilisateur (Admin uniquement)
 */
export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const adminId = req.user.id;

        // Empêcher l'admin de se supprimer lui-même
        if (userId === adminId) {
            return res.status(403).json({
                success: false,
                message: 'Vous ne pouvez pas supprimer votre propre compte'
            });
        }

        // Vérifier que l'utilisateur existe
        const userResult = await query(
            'SELECT id, email FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        // Supprimer l'utilisateur (CASCADE supprimera les enregistrements liés)
        await query('DELETE FROM users WHERE id = $1', [userId]);

        await logSecurityEvent(
            adminId,
            'USER_DELETED',
            true,
            `Deleted user account ${userResult.rows[0].email}`,
            req
        );

        res.json({
            success: true,
            message: 'Utilisateur supprimé avec succès'
        });
    } catch (error) {
        console.error('Erreur lors de la suppression de l\'utilisateur:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la suppression'
        });
    }
};

/**
 * Obtenir les statistiques de sécurité
 */
export const getSecurityStats = async (req, res) => {
    try {
        // Nombre total d'utilisateurs
        const totalUsers = await query('SELECT COUNT(*) as count FROM users');

        // Utilisateurs vérifiés
        const verifiedUsers = await query('SELECT COUNT(*) as count FROM users WHERE is_email_verified = TRUE');

        // Utilisateurs avec 2FA
        const users2FA = await query('SELECT COUNT(*) as count FROM users WHERE is_2fa_enabled = TRUE');

        // Tentatives de connexion échouées (dernières 24h)
        const failedLogins = await query(
            `SELECT COUNT(*) as count FROM security_logs
            WHERE action = $1 AND success = FALSE
            AND created_at > NOW() - INTERVAL '24 hours'`,
            [SecurityActions.FAILED_LOGIN_ATTEMPT]
        );

        // Comptes verrouillés
        const lockedAccounts = await query(
            'SELECT COUNT(*) as count FROM users WHERE locked_until > NOW()'
        );

        // Connexions réussies (dernières 24h)
        const successfulLogins = await query(
            `SELECT COUNT(*) as count FROM security_logs
            WHERE action = $1 AND success = TRUE
            AND created_at > NOW() - INTERVAL '24 hours'`,
            [SecurityActions.LOGIN]
        );

        // Activité suspecte (dernières 24h)
        const suspiciousActivity = await query(
            `SELECT COUNT(*) as count FROM security_logs
            WHERE action = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
            [SecurityActions.SUSPICIOUS_ACTIVITY]
        );

        res.json({
            success: true,
            data: {
                totalUsers: parseInt(totalUsers.rows[0].count),
                verifiedUsers: parseInt(verifiedUsers.rows[0].count),
                users2FA: parseInt(users2FA.rows[0].count),
                failedLogins24h: parseInt(failedLogins.rows[0].count),
                lockedAccounts: parseInt(lockedAccounts.rows[0].count),
                successfulLogins24h: parseInt(successfulLogins.rows[0].count),
                suspiciousActivity24h: parseInt(suspiciousActivity.rows[0].count)
            }
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des statistiques:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la récupération des statistiques'
        });
    }
};

/**
 * Obtenir les logs de sécurité globaux (Admin uniquement)
 */
export const getAllSecurityLogs = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 100;
        const offset = (page - 1) * limit;

        const logsResult = await query(
            `SELECT sl.*, u.email as user_email
            FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.id
            ORDER BY sl.created_at DESC
            LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        const countResult = await query('SELECT COUNT(*) FROM security_logs');
        const totalLogs = parseInt(countResult.rows[0].count);

        res.json({
            success: true,
            data: {
                logs: logsResult.rows,
                pagination: {
                    page,
                    limit,
                    total: totalLogs,
                    totalPages: Math.ceil(totalLogs / limit)
                }
            }
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la récupération des logs'
        });
    }
};

/**
 * Obtenir tous les rôles disponibles
 */
export const getRoles = async (req, res) => {
    try {
        let rolesResult;
        try {
            rolesResult = await query(
                'SELECT id, name, priority, description, permissions FROM roles ORDER BY priority DESC'
            );
        } catch (err) {
            // If the permissions column doesn't exist yet, fall back to a safer query
            if (err && err.code === '42703') {
                rolesResult = await query(
                    'SELECT id, name, priority, description FROM roles ORDER BY priority DESC'
                );
                // add empty permissions to each row for compatibility
                rolesResult.rows = rolesResult.rows.map(r => ({ ...r, permissions: {} }));
            } else {
                throw err;
            }
        }

        res.json({
            success: true,
            data: rolesResult.rows
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des rôles:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la récupération des rôles'
        });
    }
};

/**
 * Mettre à jour les permissions d'un rôle (Admin only)
 */
export const updateRolePermissions = async (req, res) => {
    try {
        const { roleId } = req.params;
        const { permissions } = req.body;

        // Validate input
        if (typeof permissions !== 'object' || permissions === null) {
            return res.status(400).json({ success: false, message: 'Permissions invalides' });
        }

        // Ensure role exists
        const roleResult = await query('SELECT id, name FROM roles WHERE id = $1', [roleId]);
        if (roleResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Rôle non trouvé' });
        }

        await query('UPDATE roles SET permissions = $1 WHERE id = $2', [permissions, roleId]);

        res.json({ success: true, message: 'Permissions du rôle mises à jour' });
    } catch (error) {
        console.error('Erreur lors de la mise à jour des permissions:', error);
        res.status(500).json({ success: false, message: 'Erreur lors de la mise à jour' });
    }
};
