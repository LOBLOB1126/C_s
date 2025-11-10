import { query } from '../database/db.js';

export const SecurityActions = {
    REGISTER: 'REGISTER',
    LOGIN: 'LOGIN',
    LOGOUT: 'LOGOUT',
    FAILED_LOGIN_ATTEMPT: 'FAILED_LOGIN_ATTEMPT',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    ACCOUNT_UNLOCKED: 'ACCOUNT_UNLOCKED',
    PASSWORD_CHANGE: 'PASSWORD_CHANGE',
    PASSWORD_RESET_REQUEST: 'PASSWORD_RESET_REQUEST',
    PASSWORD_RESET: 'PASSWORD_RESET',
    EMAIL_VERIFICATION: 'EMAIL_VERIFICATION',
    PHONE_VERIFICATION: 'PHONE_VERIFICATION',
    TWO_FA_ENABLED: 'TWO_FA_ENABLED',
    TWO_FA_DISABLED: 'TWO_FA_DISABLED',
    ENABLE_2FA: 'ENABLE_2FA',
    DISABLE_2FA: 'DISABLE_2FA',
    FAILED_2FA: 'FAILED_2FA',
    TWO_FA_LOGIN: 'TWO_FA_LOGIN',
    ROLE_CHANGE: 'ROLE_CHANGE',
    USER_DELETED: 'USER_DELETED',
    SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY'
};

export const logSecurityEvent = async (userId, action, success, details, req = null) => {
    try {
        const ipAddress = req?.ip || null;
        const userAgent = req?.headers?.['user-agent'] || null;

        await query(
            `INSERT INTO security_logs 
            (user_id, action, success, details, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)`,
            [userId, action, success, details, ipAddress, userAgent]
        );
    } catch (error) {
        console.error('Error logging security event:', error);
        // Don't throw - logging should not break the application flow
    }
};