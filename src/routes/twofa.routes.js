import express from 'express';
import { authMiddleware } from '../middleware/auth.middleware.js';
import {
    generate2FA,
    enable2FA,
    disable2FA,
    verify2FALogin
} from '../controllers/twofa.controller.js';

const router = express.Router();

/**
 * @route   POST /api/2fa/generate
 * @desc    Générer un secret 2FA et un QR code
 * @access  Private
 */
router.post('/generate', authMiddleware, generate2FA);

/**
 * @route   POST /api/2fa/enable
 * @desc    Activer le 2FA après vérification du token
 * @access  Private
 */
router.post('/enable', authMiddleware, enable2FA);

/**
 * @route   POST /api/2fa/disable
 * @desc    Désactiver le 2FA
 * @access  Private
 */
router.post('/disable', authMiddleware, disable2FA);

/**
 * @route   POST /api/2fa/verify-login
 * @desc    Vérifier le code 2FA pendant la connexion
 * @access  Public (pendant le processus de login)
 */
router.post('/verify-login', verify2FALogin);

export default router;