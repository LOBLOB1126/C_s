import nodemailer from 'nodemailer';

/**
 * Configuration du transporteur email
 */
const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        },
        tls: {
            rejectUnauthorized: false
        }
    });
};

/**
 * Envoyer un email de vérification
 * @param {string} email - Email du destinataire
 * @param {string} code - Code de vérification
 */
export const sendVerificationEmail = async (email, code) => {
    try {
        const transporter = createTransporter();

        const mailOptions = {
            from: `"SecureApp" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Vérification de votre compte - SecureApp',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background-color: #f9fafb;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 40px auto;
                            background: white;
                            border-radius: 12px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 40px 20px;
                            text-align: center;
                        }
                        .header h1 {
                            margin: 0;
                            font-size: 28px;
                        }
                        .content {
                            padding: 40px 30px;
                        }
                        .content p {
                            color: #4b5563;
                            line-height: 1.6;
                            margin: 0 0 20px;
                        }
                        .code-box {
                            background: #f3f4f6;
                            border: 2px dashed #4f46e5;
                            border-radius: 8px;
                            padding: 20px;
                            text-align: center;
                            margin: 30px 0;
                        }
                        .code {
                            font-size: 32px;
                            font-weight: bold;
                            color: #4f46e5;
                            letter-spacing: 8px;
                            font-family: 'Courier New', monospace;
                        }
                        .footer {
                            background: #f9fafb;
                            padding: 20px;
                            text-align: center;
                            color: #6b7280;
                            font-size: 14px;
                        }
                        .warning {
                            background: #fef3c7;
                            border-left: 4px solid #f59e0b;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 4px;
                        }
                        .warning p {
                            margin: 0;
                            color: #92400e;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔒 SecureApp</h1>
                        </div>
                        <div class="content">
                            <h2 style="color: #111827; margin-top: 0;">Vérification de votre compte</h2>
                            <p>Bonjour,</p>
                            <p>Merci de vous être inscrit sur SecureApp ! Pour activer votre compte, veuillez utiliser le code de vérification ci-dessous :</p>

                            <div class="code-box">
                                <div class="code">${code}</div>
                                <p style="margin: 10px 0 0; font-size: 12px; color: #6b7280;">Ce code expire dans 1 heure</p>
                            </div>

                            <p>Entrez ce code sur la page de vérification pour confirmer votre adresse email.</p>

                            <div class="warning">
                                <p><strong>⚠️ Sécurité :</strong> Si vous n'avez pas créé de compte, ignorez cet email.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Cet email a été envoyé automatiquement, merci de ne pas y répondre.</p>
                            <p>&copy; 2024 SecureApp. Tous droits réservés.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email de vérification envoyé à ${email}`);
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'email de vérification:', error);
        throw error;
    }
};

/**
 * Envoyer un email de réinitialisation de mot de passe
 * @param {string} email - Email du destinataire
 * @param {string} code - Code de réinitialisation
 */
export const sendPasswordResetEmail = async (email, code) => {
    try {
        const transporter = createTransporter();

        const mailOptions = {
            from: `"SecureApp" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Réinitialisation de votre mot de passe - SecureApp',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background-color: #f9fafb;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 40px auto;
                            background: white;
                            border-radius: 12px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 40px 20px;
                            text-align: center;
                        }
                        .header h1 {
                            margin: 0;
                            font-size: 28px;
                        }
                        .content {
                            padding: 40px 30px;
                        }
                        .content p {
                            color: #4b5563;
                            line-height: 1.6;
                            margin: 0 0 20px;
                        }
                        .code-box {
                            background: #f3f4f6;
                            border: 2px dashed #ef4444;
                            border-radius: 8px;
                            padding: 20px;
                            text-align: center;
                            margin: 30px 0;
                        }
                        .code {
                            font-size: 32px;
                            font-weight: bold;
                            color: #ef4444;
                            letter-spacing: 8px;
                            font-family: 'Courier New', monospace;
                        }
                        .footer {
                            background: #f9fafb;
                            padding: 20px;
                            text-align: center;
                            color: #6b7280;
                            font-size: 14px;
                        }
                        .warning {
                            background: #fee2e2;
                            border-left: 4px solid #ef4444;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 4px;
                        }
                        .warning p {
                            margin: 0;
                            color: #991b1b;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔒 SecureApp</h1>
                        </div>
                        <div class="content">
                            <h2 style="color: #111827; margin-top: 0;">Réinitialisation de votre mot de passe</h2>
                            <p>Bonjour,</p>
                            <p>Vous avez demandé à réinitialiser votre mot de passe. Utilisez le code ci-dessous pour créer un nouveau mot de passe :</p>

                            <div class="code-box">
                                <div class="code">${code}</div>
                                <p style="margin: 10px 0 0; font-size: 12px; color: #6b7280;">Ce code expire dans 1 heure</p>
                            </div>

                            <p>Entrez ce code sur la page de réinitialisation pour définir votre nouveau mot de passe.</p>

                            <div class="warning">
                                <p><strong>⚠️ Sécurité :</strong> Si vous n'avez pas demandé cette réinitialisation, ignorez cet email et changez votre mot de passe immédiatement si vous pensez que votre compte a été compromis.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Cet email a été envoyé automatiquement, merci de ne pas y répondre.</p>
                            <p>&copy; 2024 SecureApp. Tous droits réservés.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email de réinitialisation envoyé à ${email}`);
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'email de réinitialisation:', error);
        throw error;
    }
};

/**
 * Envoyer un email de notification de changement de mot de passe
 * @param {string} email - Email du destinataire
 */
export const sendPasswordChangedEmail = async (email) => {
    try {
        const transporter = createTransporter();

        const mailOptions = {
            from: `"SecureApp" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Votre mot de passe a été modifié - SecureApp',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background-color: #f9fafb;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 40px auto;
                            background: white;
                            border-radius: 12px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 40px 20px;
                            text-align: center;
                        }
                        .header h1 {
                            margin: 0;
                            font-size: 28px;
                        }
                        .content {
                            padding: 40px 30px;
                        }
                        .content p {
                            color: #4b5563;
                            line-height: 1.6;
                            margin: 0 0 20px;
                        }
                        .footer {
                            background: #f9fafb;
                            padding: 20px;
                            text-align: center;
                            color: #6b7280;
                            font-size: 14px;
                        }
                        .success {
                            background: #d1fae5;
                            border-left: 4px solid #10b981;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 4px;
                        }
                        .success p {
                            margin: 0;
                            color: #065f46;
                        }
                        .warning {
                            background: #fee2e2;
                            border-left: 4px solid #ef4444;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 4px;
                        }
                        .warning p {
                            margin: 0;
                            color: #991b1b;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔒 SecureApp</h1>
                        </div>
                        <div class="content">
                            <h2 style="color: #111827; margin-top: 0;">Mot de passe modifié</h2>
                            <p>Bonjour,</p>
                            <p>Votre mot de passe a été modifié avec succès.</p>

                            <div class="success">
                                <p><strong>✓ Confirmation :</strong> Votre mot de passe a été changé le ${new Date().toLocaleString('fr-FR')}.</p>
                            </div>

                            <div class="warning">
                                <p><strong>⚠️ Important :</strong> Si vous n'êtes pas à l'origine de ce changement, votre compte a peut-être été compromis. Contactez-nous immédiatement.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Cet email a été envoyé automatiquement, merci de ne pas y répondre.</p>
                            <p>&copy; 2024 SecureApp. Tous droits réservés.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email de confirmation de changement de mot de passe envoyé à ${email}`);
        return true;
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'email de confirmation:', error);
        throw error;
    }
};
