import { query } from '../database/db.js';

/**
 * Logger un événement de sécurité
 * @param {number} userId - ID de l'utilisateur
 * @param {string} eventType - Type d'événement
 * @param {object} metadata - Métadonnées supplémentaires
 * @param {string} ipAddress - Adresse IP
 */
export const logSecurityEvent = async (userId, eventType, metadata = {}, ipAddress = null) => {
    try {
        await query(
            `INSERT INTO security_logs (user_id, event_type, metadata, ip_address)
             VALUES ($1, $2, $3, $4)`,
            [userId, eventType, JSON.stringify(metadata), ipAddress]
        );
    } catch (error) {
        console.error('Erreur lors de l\'enregistrement du log de sécurité:', error);
        // Ne pas propager l'erreur pour ne pas bloquer l'opération principale
    }
};

/**
 * Vérifier les tentatives de connexion échouées
 * @param {number} userId - ID de l'utilisateur
 * @returns {boolean} - True si le compte doit être verrouillé
 */
export const checkFailedLoginAttempts = async (userId) => {
    try {
        const result = await query(
            'SELECT failed_login_attempts FROM users WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            return false;
        }

        const attempts = result.rows[0].failed_login_attempts;
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;

        return attempts >= maxAttempts;
    } catch (error) {
        console.error('Erreur lors de la vérification des tentatives de connexion:', error);
        return false;
    }
};

/**
 * Incrémenter le compteur de tentatives de connexion échouées
 * @param {number} userId - ID de l'utilisateur
 */
export const incrementFailedLoginAttempts = async (userId) => {
    try {
        await query(
            `UPDATE users
             SET failed_login_attempts = failed_login_attempts + 1,
                 updated_at = NOW()
             WHERE id = $1`,
            [userId]
        );

        // Vérifier si le compte doit être verrouillé
        const shouldLock = await checkFailedLoginAttempts(userId);

        if (shouldLock) {
            await query(
                'UPDATE users SET is_locked = true, updated_at = NOW() WHERE id = $1',
                [userId]
            );
            await logSecurityEvent(userId, 'account_locked', {
                reason: 'too_many_failed_attempts'
            });
        }
    } catch (error) {
        console.error('Erreur lors de l\'incrémentation des tentatives échouées:', error);
    }
};

/**
 * Réinitialiser le compteur de tentatives de connexion échouées
 * @param {number} userId - ID de l'utilisateur
 */
export const resetFailedLoginAttempts = async (userId) => {
    try {
        await query(
            'UPDATE users SET failed_login_attempts = 0, updated_at = NOW() WHERE id = $1',
            [userId]
        );
    } catch (error) {
        console.error('Erreur lors de la réinitialisation des tentatives échouées:', error);
    }
};

/**
 * Vérifier si une adresse IP est bloquée
 * @param {string} ipAddress - Adresse IP à vérifier
 * @returns {boolean} - True si l'IP est bloquée
 */
export const isIpBlocked = async (ipAddress) => {
    try {
        const result = await query(
            `SELECT COUNT(*) as count FROM blocked_ips
             WHERE ip_address = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
            [ipAddress]
        );

        return parseInt(result.rows[0].count) > 0;
    } catch (error) {
        console.error('Erreur lors de la vérification de l\'IP bloquée:', error);
        return false;
    }
};
