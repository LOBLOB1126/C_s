import express from 'express';
import * as adminController from '../controllers/admin.controller.js';
import {
    authMiddleware,
    requireRole,
    requireMinPriority
} from '../middleware/auth.middleware.js';

const router = express.Router();

// Toutes les routes admin nécessitent une authentification
router.use(authMiddleware);

/**
 * @route   GET /api/admin/users
 * @desc    Obtenir tous les utilisateurs
 * @access  Admin, Moderator
 */
router.get('/users', requireMinPriority(50), adminController.getAllUsers);

/**
 * @route   GET /api/admin/users/:userId
 * @desc    Obtenir un utilisateur spécifique
 * @access  Admin, Moderator
 */
router.get('/users/:userId', requireMinPriority(50), adminController.getUserById);

/**
 * @route   PUT /api/admin/users/:userId/role
 * @desc    Changer le rôle d'un utilisateur
 * @access  Admin only
 */
router.put('/users/:userId/role', requireRole(['admin']), adminController.changeUserRole);

/**
 * @route   PUT /api/admin/users/:userId/lock
 * @desc    Verrouiller/Déverrouiller un compte
 * @access  Admin, Moderator
 */
router.put('/users/:userId/lock', requireMinPriority(50), adminController.toggleUserLock);

/**
 * @route   DELETE /api/admin/users/:userId
 * @desc    Supprimer un utilisateur
 * @access  Admin only
 */
router.delete('/users/:userId', requireRole(['admin']), adminController.deleteUser);

/**
 * @route   GET /api/admin/stats
 * @desc    Obtenir les statistiques de sécurité
 * @access  Admin, Moderator
 */
router.get('/stats', requireMinPriority(50), adminController.getSecurityStats);

/**
 * @route   GET /api/admin/logs
 * @desc    Obtenir tous les logs de sécurité
 * @access  Admin only
 */
router.get('/logs', requireRole(['admin']), adminController.getAllSecurityLogs);

/**
 * @route   GET /api/admin/roles
 * @desc    Obtenir tous les rôles
 * @access  Admin, Moderator
 */
router.get('/roles', requireMinPriority(50), adminController.getRoles);

/**
 * @route   PUT /api/admin/roles/:roleId
 * @desc    Update permissions for a role
 * @access  Admin only
 */
router.put('/roles/:roleId', requireRole(['admin']), adminController.updateRolePermissions);

export { router as default };
