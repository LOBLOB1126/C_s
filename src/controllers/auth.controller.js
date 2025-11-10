import bcrypt from 'bcrypt';
import { query } from '../database/db.js';
import { generateToken } from '../utils/auth.js';
import { logSecurityEvent, SecurityActions } from '../utils/logger.js';
import { sendVerificationEmail, sendPasswordResetEmail, sendPasswordChangedEmail } from '../utils/email.js';

export const register = async (req, res) => {
    try {
        console.log('📝 [REGISTER] Début de l\'inscription');
        const { email, password, phone } = req.body;
        console.log(`📝 [REGISTER] Email: ${email}, Phone: ${phone || 'N/A'}`);

        // Check if user already exists
        console.log('📝 [REGISTER] Vérification si l\'utilisateur existe déjà...');
        const existingUser = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            console.log('❌ [REGISTER] Email déjà enregistré');
            return res.status(400).json({
                success: false,
                message: 'Email already registered'
            });
        }
        console.log('✅ [REGISTER] Email disponible');

        // Hash password
        console.log('📝 [REGISTER] Hashage du mot de passe...');
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS));
        console.log('✅ [REGISTER] Mot de passe hashé');

        // Get default role (user)
        console.log('📝 [REGISTER] Récupération du rôle par défaut...');
        const roleResult = await query(
            `SELECT id FROM roles WHERE name = 'user' LIMIT 1`
        );

        const defaultRoleId = roleResult.rows.length > 0 ? roleResult.rows[0].id : null;
        console.log(`✅ [REGISTER] Rôle par défaut ID: ${defaultRoleId || 'NULL'}`);

        // Create user with default role
        console.log('📝 [REGISTER] Création de l\'utilisateur...');
        const result = await query(
            `INSERT INTO users (email, password_hash, phone, role_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id`,
            [email, hashedPassword, phone, defaultRoleId]
        );

        const userId = result.rows[0].id;
        console.log(`✅ [REGISTER] Utilisateur créé avec ID: ${userId}`);

        // Generate verification code
        const verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await query(
            `INSERT INTO verification_codes (user_id, code, type, expires_at)
            VALUES ($1, $2, 'email', NOW() + INTERVAL '1 hour')`,
            [userId, verificationCode]
        );

        // Send verification email
        try {
            await sendVerificationEmail(email, verificationCode);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
            // Continue anyway - user can resend
        }

        await logSecurityEvent(userId, SecurityActions.REGISTER, true, null, req);

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please verify your email.'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during registration'
        });
    }
};

export const login = async (req, res) => {
    try {
        console.log('🔐 [LOGIN] Début de la connexion');
        const { email, password } = req.body;
        console.log(`🔐 [LOGIN] Email: ${email}`);

        // Get user
        console.log('🔐 [LOGIN] Récupération de l\'utilisateur...');
        const userResult = await query(
            `SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.email = $1`,
            [email]
        );

        if (userResult.rows.length === 0) {
            console.log('❌ [LOGIN] Utilisateur non trouvé');
            await logSecurityEvent(null, SecurityActions.FAILED_LOGIN_ATTEMPT, false, `Invalid email: ${email}`, req);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = userResult.rows[0];
        console.log(`✅ [LOGIN] Utilisateur trouvé - ID: ${user.id}, Role: ${user.role_name || 'NULL'}, Email vérifié: ${user.is_email_verified}, 2FA: ${user.is_2fa_enabled}`);

        // Check if account is locked
        console.log('🔐 [LOGIN] Vérification du verrouillage du compte...');
        if (user.locked_until && user.locked_until > new Date()) {
            console.log('❌ [LOGIN] Compte verrouillé');
            return res.status(403).json({
                success: false,
                message: 'Account is locked. Please try again later.'
            });
        }
        console.log('✅ [LOGIN] Compte non verrouillé');

        // Verify password
        console.log('🔐 [LOGIN] Vérification du mot de passe...');
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            console.log('❌ [LOGIN] Mot de passe invalide');
            // Increment login attempts
            await query(
                'UPDATE users SET login_attempts = login_attempts + 1 WHERE id = $1',
                [user.id]
            );

            if (user.login_attempts >= parseInt(process.env.MAX_LOGIN_ATTEMPTS) - 1) {
                // Lock account
                const lockDuration = parseInt(process.env.LOCKOUT_TIME);
                await query(
                    'UPDATE users SET locked_until = NOW() + INTERVAL \'15 minutes\' WHERE id = $1',
                    [user.id]
                );
            }

            await logSecurityEvent(user.id, SecurityActions.FAILED_LOGIN_ATTEMPT, false, 'Invalid password', req);

            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        console.log('✅ [LOGIN] Mot de passe valide');

        // Reset login attempts
        console.log('🔐 [LOGIN] Réinitialisation des tentatives de connexion...');
        await query(
            'UPDATE users SET login_attempts = 0, last_login = NOW() WHERE id = $1',
            [user.id]
        );
        console.log('✅ [LOGIN] Tentatives réinitialisées');

        // Check if 2FA is enabled
        console.log(`🔐 [LOGIN] Vérification 2FA - is_2fa_enabled: ${user.is_2fa_enabled}`);
        if (user.is_2fa_enabled) {
            console.log('🔒 [LOGIN] 2FA REQUIS - Redirection vers la vérification 2FA');
            // Don't provide token yet - require 2FA verification
            await logSecurityEvent(user.id, SecurityActions.LOGIN, true, '2FA required', req);

            return res.json({
                success: true,
                requires2FA: true,
                tempUserId: user.id,
                message: 'Please enter your 2FA code'
            });
        }
        console.log('✅ [LOGIN] 2FA non activé - Connexion directe');

        // Generate token
        console.log('🔐 [LOGIN] Génération du token JWT...');
        const token = generateToken(user);
        console.log('✅ [LOGIN] Token généré');

        // Create user session in database
        console.log('🔐 [LOGIN] Création de la session...');
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';

        await query(
            `INSERT INTO user_sessions (user_id, token_hash, ip_address, user_agent, expires_at)
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')`,
            [user.id, token, ipAddress, userAgent]
        );
        console.log('✅ [LOGIN] Session créée');

        await logSecurityEvent(user.id, SecurityActions.LOGIN, true, null, req);

        console.log(`✅ [LOGIN] Connexion réussie - User: ${user.email}, Role: ${user.role_name}`);
        res.json({
            success: true,
            data: {
                token,
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
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during login'
        });
    }
};

export const verifyEmail = async (req, res) => {
    try {
        const { email, code } = req.body;

        // Get user
        const userResult = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const userId = userResult.rows[0].id;

        // Verify code
        const codeResult = await query(
            `SELECT * FROM verification_codes
            WHERE user_id = $1 AND code = $2 AND type = 'email'
            AND expires_at > NOW() AND is_used = FALSE`,
            [userId, code]
        );

        if (codeResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification code'
            });
        }

        // Mark email as verified
        await query(
            'UPDATE users SET is_email_verified = TRUE WHERE id = $1',
            [userId]
        );

        // Mark code as used
        await query(
            'UPDATE verification_codes SET is_used = TRUE WHERE id = $1',
            [codeResult.rows[0].id]
        );

        await logSecurityEvent(userId, SecurityActions.EMAIL_VERIFICATION, true, null, req);

        res.json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during email verification'
        });
    }
};

export const resendVerificationCode = async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const userId = userResult.rows[0].id;

        // Get user email
        const userEmailResult = await query('SELECT email FROM users WHERE id = $1', [userId]);
        const userEmail = userEmailResult.rows[0].email;

        // Generate new code
        const verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await query(
            `INSERT INTO verification_codes (user_id, code, type, expires_at)
            VALUES ($1, $2, 'email', NOW() + INTERVAL '1 hour')`,
            [userId, verificationCode]
        );

        // Send verification email
        try {
            await sendVerificationEmail(userEmail, verificationCode);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification email'
            });
        }

        res.json({
            success: true,
            message: 'Verification code sent'
        });
    } catch (error) {
        console.error('Code resend error:', error);
        res.status(500).json({
            success: false,
            message: 'Error sending verification code'
        });
    }
};

export const requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const userId = userResult.rows[0].id;

        // Generate reset code
        const resetCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await query(
            `INSERT INTO verification_codes (user_id, code, type, expires_at)
            VALUES ($1, $2, 'password_reset', NOW() + INTERVAL '1 hour')`,
            [userId, resetCode]
        );

        // Send reset email
        try {
            await sendPasswordResetEmail(email, resetCode);
        } catch (emailError) {
            console.error('Failed to send password reset email:', emailError);
            return res.status(500).json({
                success: false,
                message: 'Failed to send reset email'
            });
        }

        await logSecurityEvent(userId, SecurityActions.PASSWORD_RESET_REQUEST, true, null, req);

        res.json({
            success: true,
            message: 'Password reset instructions sent to your email'
        });
    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({
            success: false,
            message: 'Error requesting password reset'
        });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;

        const userResult = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const userId = userResult.rows[0].id;

        // Verify code
        const codeResult = await query(
            `SELECT * FROM verification_codes
            WHERE user_id = $1 AND code = $2 AND type = 'password_reset'
            AND expires_at > NOW() AND is_used = FALSE`,
            [userId, code]
        );

        if (codeResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset code'
            });
        }

        // Update password
        const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS));
        await query(
            'UPDATE users SET password_hash = $1 WHERE id = $2',
            [hashedPassword, userId]
        );

        // Mark code as used
        await query(
            'UPDATE verification_codes SET is_used = TRUE WHERE id = $1',
            [codeResult.rows[0].id]
        );

        // Send confirmation email
        try {
            await sendPasswordChangedEmail(email);
        } catch (emailError) {
            console.error('Failed to send password changed confirmation email:', emailError);
            // Don't fail the request if email fails
        }

        await logSecurityEvent(userId, SecurityActions.PASSWORD_RESET, true, null, req);

        res.json({
            success: true,
            message: 'Password reset successful. You can now log in with your new password.'
        });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({
            success: false,
            message: 'Error resetting password'
        });
    }
};

export const logout = async (req, res) => {
    try {
        // Delete the user's session from the database
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            await query(
                'DELETE FROM user_sessions WHERE user_id = $1 AND token_hash = $2',
                [req.user.id, token]
            );
        }

        await logSecurityEvent(req.user.id, SecurityActions.LOGOUT, true, null, req);

        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during logout'
        });
    }
};