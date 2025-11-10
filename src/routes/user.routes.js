import express from 'express';
import { authMiddleware } from '../middleware/auth.middleware.js';
import {
    getProfile,
    getSessions,
    revokeSession,
    getSecurityLogs,
    updateProfile,
    changePassword
} from '../controllers/user.controller.js';
import { validateChangePassword } from '../middleware/validator.middleware.js';

const router = express.Router();

// Toutes les routes nécessitent une authentification
router.use(authMiddleware);

/**
 * @route   GET /api/user/profile
 * @desc    Obtenir le profil de l'utilisateur connecté
 * @access  Private
 */
router.get('/profile', getProfile);

/**
 * @route   PUT /api/user/profile
 * @desc    Mettre à jour le profil
 * @access  Private
 */
router.put('/profile', updateProfile);

/**
 * @route   GET /api/user/sessions
 * @desc    Obtenir toutes les sessions actives
 * @access  Private
 */
router.get('/sessions', getSessions);

/**
 * @route   DELETE /api/user/sessions/:sessionId
 * @desc    Révoquer une session spécifique
 * @access  Private
 */
router.delete('/sessions/:sessionId', revokeSession);

/**
 * @route   GET /api/user/security-logs
 * @desc    Obtenir les logs de sécurité
 * @access  Private
 */
router.get('/security-logs', getSecurityLogs);

/**
 * @route   POST /api/user/change-password
 * @desc    Changer le mot de passe
 * @access  Private
 */
router.post('/change-password', validateChangePassword, changePassword);

export default router;