import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { query } from '../database/db.js';
import { generateToken } from '../utils/auth.js';
import { logSecurityEvent, SecurityActions } from '../utils/logger.js';

/**
 * Generate 2FA secret and QR code
 */
export const generate2FA = async (req, res) => {
    try {
        console.log('🔒 [2FA GENERATE] Génération du secret 2FA');
        const userId = req.user.id;
        const userEmail = req.user.email;

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `SecureApp (${userEmail})`,
            length: 32
        });

        console.log(`✅ [2FA GENERATE] Secret généré pour user: ${userId}`);

        // Store secret in database (temporarily)
        await query(
            'UPDATE users SET two_fa_secret = $1 WHERE id = $2',
            [secret.base32, userId]
        );

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        console.log('✅ [2FA GENERATE] QR Code généré');

        res.json({
            success: true,
            data: {
                secret: secret.base32,
                qrCode: qrCodeUrl
            }
        });
    } catch (error) {
        console.error('❌ [2FA GENERATE] Erreur:', error);
        res.status(500).json({
            success: false,
            message: 'Error generating 2FA secret'
        });
    }
};

/**
 * Verify and enable 2FA
 */
export const enable2FA = async (req, res) => {
    try {
        console.log('🔒 [2FA ENABLE] Activation du 2FA');
        const userId = req.user.id;
        const { token } = req.body;

        console.log(`🔒 [2FA ENABLE] User: ${userId}, Token: ${token}`);

        // Get user's secret
        const userResult = await query(
            'SELECT two_fa_secret FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].two_fa_secret) {
            console.log('❌ [2FA ENABLE] Secret 2FA non trouvé');
            return res.status(400).json({
                success: false,
                message: '2FA secret not found'
            });
        }

        const secret = userResult.rows[0].two_fa_secret;

        console.log(`🔒 [2FA ENABLE] Secret trouvé (premiers 10 chars): ${secret.substring(0, 10)}...`);
        console.log(`🔒 [2FA ENABLE] Token reçu: ${token}, Type: ${typeof token}`);

        // Assurer que le token est une chaîne de caractères
        const tokenString = String(token).trim();
        console.log(`🔒 [2FA ENABLE] Token après conversion: ${tokenString}`);

        // Générer le token attendu pour comparaison
        const expectedToken = speakeasy.totp({
            secret: secret,
            encoding: 'base32'
        });
        console.log(`🔒 [2FA ENABLE] Token attendu actuellement: ${expectedToken}`);

        // Verify token with string conversion
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: tokenString,
            window: 6  // Increased tolerance for time sync issues (±3 minutes)
        });

        if (!verified) {
            console.log('❌ [2FA ENABLE] Token invalide');
            return res.status(400).json({
                success: false,
                message: 'Invalid 2FA token'
            });
        }

        console.log('✅ [2FA ENABLE] Token vérifié - Activation du 2FA');

        // Enable 2FA
        await query(
            'UPDATE users SET is_2fa_enabled = true WHERE id = $1',
            [userId]
        );

        await logSecurityEvent(userId, SecurityActions.ENABLE_2FA, true, null, req);

        console.log(`✅ [2FA ENABLE] 2FA activé pour user: ${userId}`);

        res.json({
            success: true,
            message: '2FA enabled successfully'
        });
    } catch (error) {
        console.error('❌ [2FA ENABLE] Erreur:', error);
        res.status(500).json({
            success: false,
            message: 'Error enabling 2FA'
        });
    }
};

/**
 * Disable 2FA
 */
export const disable2FA = async (req, res) => {
    try {
        console.log('🔒 [2FA DISABLE] Désactivation du 2FA');
        const userId = req.user.id;

        await query(
            'UPDATE users SET is_2fa_enabled = false, two_fa_secret = NULL WHERE id = $1',
            [userId]
        );

        await logSecurityEvent(userId, SecurityActions.DISABLE_2FA, true, null, req);

        console.log(`✅ [2FA DISABLE] 2FA désactivé pour user: ${userId}`);

        res.json({
            success: true,
            message: '2FA disabled successfully'
        });
    } catch (error) {
        console.error('❌ [2FA DISABLE] Erreur:', error);
        res.status(500).json({
            success: false,
            message: 'Error disabling 2FA'
        });
    }
};

/**
 * Verify 2FA token during login
 */
export const verify2FALogin = async (req, res) => {
    try {
        console.log('🔒 [2FA VERIFY LOGIN] Vérification du code 2FA pour connexion');
        const { userId, token } = req.body;

        console.log(`🔒 [2FA VERIFY LOGIN] User ID: ${userId}, Token: ${token}`);

        if (!userId || !token) {
            console.log('❌ [2FA VERIFY LOGIN] Paramètres manquants');
            return res.status(400).json({
                success: false,
                message: 'User ID and token are required'
            });
        }

        // Get user with secret and role
        const userResult = await query(
            `SELECT u.*, r.name as role_name
             FROM users u
             LEFT JOIN roles r ON u.role_id = r.id
             WHERE u.id = $1`,
            [userId]
        );

        if (userResult.rows.length === 0) {
            console.log('❌ [2FA VERIFY LOGIN] Utilisateur non trouvé');
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const user = userResult.rows[0];

        if (!user.is_2fa_enabled || !user.two_fa_secret) {
            console.log('❌ [2FA VERIFY LOGIN] 2FA non activé pour cet utilisateur');
            return res.status(400).json({
                success: false,
                message: '2FA is not enabled for this user'
            });
        }

        console.log(`🔒 [2FA VERIFY LOGIN] Vérification du token avec secret...`);

        // Verify token
        const verified = speakeasy.totp.verify({
            secret: user.two_fa_secret,
            encoding: 'base32',
            token: token,
            window: 6  // Increased tolerance for time sync issues (±3 minutes)
        });

        if (!verified) {
            console.log('❌ [2FA VERIFY LOGIN] Token 2FA invalide');
            await logSecurityEvent(userId, SecurityActions.FAILED_2FA, false, 'Invalid 2FA token', req);
            return res.status(400).json({
                success: false,
                message: 'Invalid 2FA token'
            });
        }

        console.log('✅ [2FA VERIFY LOGIN] Token 2FA valide - Génération du JWT');

        // Generate JWT token
        const jwtToken = generateToken(user);

        // Create user session in database
        console.log('🔐 [2FA VERIFY LOGIN] Création de la session...');
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';

        await query(
            `INSERT INTO user_sessions (user_id, token_hash, ip_address, user_agent, expires_at)
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')`,
            [user.id, jwtToken, ipAddress, userAgent]
        );
        console.log('✅ [2FA VERIFY LOGIN] Session créée');

        await logSecurityEvent(userId, SecurityActions.LOGIN, true, '2FA verified', req);

        console.log(`✅ [2FA VERIFY LOGIN] Connexion réussie - User: ${user.email}, Role: ${user.role_name}`);

        res.json({
            success: true,
            data: {
                token: jwtToken,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role_name,
                    isEmailVerified: user.is_email_verified,
                    is2FAEnabled: user.is_2fa_enabled
                }
            }
        });
    } catch (error) {
        console.error('❌ [2FA VERIFY LOGIN] Erreur:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying 2FA token'
        });
    }
};
