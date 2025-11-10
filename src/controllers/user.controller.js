import { query } from '../database/db.js';
import bcrypt from 'bcrypt';
import { logSecurityEvent, SecurityActions } from '../utils/logger.js';

/**
 * Obtenir le profil utilisateur
 */
export const getProfile = async (req, res) => {
    try {
        res.json({
            success: true,
            data: req.user
        });
    } catch (error) {
        console.error('Error getting profile:', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving profile'
        });
    }
};

/**
 * Obtenir toutes les sessions actives de l'utilisateur
 */
export const getSessions = async (req, res) => {
    try {
        const userId = req.user.id;

        const result = await query(
            `SELECT id, created_at, expires_at, ip_address, user_agent
             FROM user_sessions
             WHERE user_id = $1 AND expires_at > NOW()
             ORDER BY created_at DESC`,
            [userId]
        );

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Error getting sessions:', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving sessions'
        });
    }
};

/**
 * Révoquer une session spécifique
 */
export const revokeSession = async (req, res) => {
    try {
        const userId = req.user.id;
        const { sessionId } = req.params;

        // Vérifier que la session appartient à l'utilisateur
        const sessionResult = await query(
            'SELECT id FROM user_sessions WHERE id = $1 AND user_id = $2',
            [sessionId, userId]
        );

        if (sessionResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        // Supprimer la session
        await query('DELETE FROM user_sessions WHERE id = $1', [sessionId]);

        res.json({
            success: true,
            message: 'Session revoked successfully'
        });
    } catch (error) {
        console.error('Error revoking session:', error);
        res.status(500).json({
            success: false,
            message: 'Error revoking session'
        });
    }
};

/**
 * Obtenir les logs de sécurité de l'utilisateur
 */
export const getSecurityLogs = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 20;

        const result = await query(
            `SELECT id, action, success, ip_address, created_at
             FROM security_logs
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT $2`,
            [userId, limit]
        );

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Error getting security logs:', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving security logs'
        });
    }
};

/**
 * Mettre à jour le profil utilisateur
 */
export const updateProfile = async (req, res) => {
    try {
        const userId = req.user.id;
        const { username, phone } = req.body;

        // Update only provided fields
        const updates = [];
        const values = [];
        let paramCount = 1;

        if (username) {
            updates.push(`username = $${paramCount}`);
            values.push(username);
            paramCount++;
        }

        if (phone !== undefined) {
            updates.push(`phone = $${paramCount}`);
            values.push(phone);
            paramCount++;
        }

        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }

        updates.push(`updated_at = NOW()`);
        values.push(userId);

        const updateQuery = `
            UPDATE users
            SET ${updates.join(', ')}
            WHERE id = $${paramCount}
            RETURNING id, email, username, phone
        `;

        const result = await query(updateQuery, values);

        res.json({
            success: true,
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating profile'
        });
    }
};

/**
 * Changer le mot de passe
 */
export const changePassword = async (req, res) => {
    try {
        console.log('🔐 [CHANGE PASSWORD] Début du changement de mot de passe');
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        // Validate input
        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        // Get current password hash
        const userResult = await query(
            'SELECT password_hash FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password
        const isValid = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
        if (!isValid) {
            console.log('❌ [CHANGE PASSWORD] Mot de passe actuel incorrect');
            await logSecurityEvent(userId, SecurityActions.PASSWORD_CHANGE, false, 'Invalid current password', req);
            return res.status(400).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS));

        // Update password
        await query(
            'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
            [hashedPassword, userId]
        );

        console.log('✅ [CHANGE PASSWORD] Mot de passe changé avec succès');
        await logSecurityEvent(userId, SecurityActions.PASSWORD_CHANGE, true, null, req);

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({
            success: false,
            message: 'Error changing password'
        });
    }
};
