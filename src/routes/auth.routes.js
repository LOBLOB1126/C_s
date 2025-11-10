import express from 'express';
import {
    register,
    login,
    verifyEmail,
    resendVerificationCode,
    requestPasswordReset,
    resetPassword,
    logout
} from '../controllers/auth.controller.js';
import {
    validateRegister,
    validateLogin,
    validateVerificationCode,
    validatePasswordReset,
    validatePasswordResetRequest,
    validateResendCode
} from '../middleware/validator.middleware.js';
import { authenticateToken } from '../middleware/auth.middleware.js';
import {
    authLimiter,
    registerLimiter,
    verificationLimiter
} from '../middleware/security.middleware.js';
import { verifyRecaptcha } from '../middleware/recaptcha.middleware.js';

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Inscription d'un nouvel utilisateur
 * @access  Public
 */
router.post('/register', registerLimiter, verifyRecaptcha, validateRegister, register);

/**
 * @route   POST /api/auth/login
 * @desc    Connexion d'un utilisateur
 * @access  Public
 */
router.post('/login', authLimiter, verifyRecaptcha, validateLogin, login);

/**
 * @route   POST /api/auth/verify-email
 * @desc    Vérification de l'email avec un code
 * @access  Public
 */
router.post('/verify-email', verificationLimiter, validateVerificationCode, verifyEmail);

/**
 * @route   POST /api/auth/resend-code
 * @desc    Renvoyer un code de vérification
 * @access  Public
 */
router.post('/resend-code', verificationLimiter, validateResendCode, resendVerificationCode);

/**
 * @route   POST /api/auth/password-reset-request
 * @desc    Demander un code de réinitialisation de mot de passe
 * @access  Public
 */
router.post('/password-reset-request', authLimiter, validatePasswordResetRequest, requestPasswordReset);

/**
 * @route   POST /api/auth/password-reset
 * @desc    Réinitialiser le mot de passe avec un code
 * @access  Public
 */
router.post('/password-reset', authLimiter, validatePasswordReset, resetPassword);

/**
 * @route   POST /api/auth/logout
 * @desc    Déconnexion (invalide la session)
 * @access  Private
 */
router.post('/logout', authenticateToken, logout);

export { router as default };
