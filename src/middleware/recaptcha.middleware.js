import axios from 'axios';
import recaptchaConfig from '../config/recaptcha.js';

export const verifyRecaptcha = async (req, res, next) => {
    try {
        const token = req.body.recaptchaToken;

        if (!token) {
            return res.status(400).json({ 
                error: 'CAPTCHA_REQUIRED',
                message: 'Please complete the CAPTCHA verification'
            });
        }

        const response = await axios.post(recaptchaConfig.verifyUrl, null, {
            params: {
                secret: recaptchaConfig.secretKey,
                response: token
            }
        });

        const { success } = response.data;

        if (!success) {
            return res.status(400).json({
                error: 'INVALID_CAPTCHA',
                message: 'CAPTCHA verification failed'
            });
        }

        next();
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        res.status(500).json({
            error: 'CAPTCHA_ERROR',
            message: 'Error verifying CAPTCHA'
        });
    }
};

// Export is handled by the 'export' keyword above