const recaptchaConfig = {
    siteKey: process.env.RECAPTCHA_SITE_KEY || '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI', // Test key
    secretKey: process.env.RECAPTCHA_SECRET_KEY || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe', // Test key
    verifyUrl: 'https://www.google.com/recaptcha/api/siteverify'
};

export default recaptchaConfig;