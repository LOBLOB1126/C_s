import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import xss from 'xss-clean';
import hpp from 'hpp';

const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://www.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://www.google.com", "https://www.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:", "https://www.google.com", "https://www.gstatic.com"],
            connectSrc: ["'self'", "https://www.google.com"],
            fontSrc: ["'self'", "https://www.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["https://www.google.com"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            manifestSrc: ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'same-origin' }
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests max per IP
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts max
    message: {
        success: false,
        message: 'Too many login attempts. Please try again in 15 minutes.'
    },
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registrations max per IP per hour
    message: {
        success: false,
        message: 'Too many registration attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const verificationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts max
    message: {
        success: false,
        message: 'Too many verification attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const xssProtection = xss();
const parameterPollutionProtection = hpp();

const sqlInjectionProtection = (req, res, next) => {
    const suspiciousPatterns = [
        /(\-\-)|(\%23)|(#)/i,  // SQL comments
        /union[\s\/\*]+select/i,  // UNION SELECT attacks
        /exec[\s\/\*]+xp/i,  // Stored procedure attacks
        /INFORMATION_SCHEMA/i,  // Information schema attacks
        /\/\*![0-9]*/i,  // MySQL version comments
    ];

    const url = req.url || '';
    const sensitiveFields = ['email', 'password', 'query', 'search'];
    
    // Only check sensitive fields in the body
    for (const field of sensitiveFields) {
        if (req.body && req.body[field]) {
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(req.body[field])) {
                    console.warn(`[SECURITY] SQL injection attempt detected: ${req.ip}`);
                    return res.status(403).json({
                        success: false,
                        message: 'Request blocked for security reasons'
                    });
                }
            }
        }
    }
    
    // Check URL
    if (suspiciousPatterns.some(pattern => pattern.test(url))) {
        console.warn(`[SECURITY] SQL injection attempt detected in URL: ${req.ip}`);
        return res.status(403).json({
            success: false,
            message: 'Request blocked for security reasons'
        });
    }

    next();
};

const suspiciousActivityDetection = (req, res, next) => {
    const userAgent = req.get('user-agent') || '';
    const suspiciousAgents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit'];

    for (const agent of suspiciousAgents) {
        if (userAgent.toLowerCase().includes(agent)) {
            console.warn(`[SECURITY] Scan tool detected: ${agent} from ${req.ip}`);
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
    }

    next();
};

const customSecurityHeaders = (req, res, next) => {
    // Prevent browser from caching sensitive data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    // Allow frames from same origin for reCAPTCHA
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');

    // Disable MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Permissions Policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    next();
};

export {
    securityHeaders,
    generalLimiter,
    authLimiter,
    registerLimiter,
    verificationLimiter,
    xssProtection,
    parameterPollutionProtection,
    sqlInjectionProtection,
    suspiciousActivityDetection,
    customSecurityHeaders
};