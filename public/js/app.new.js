// Application JavaScript principale
(() => {
    // État global de l'application et constantes
    const app = {
        state: {
            token: null,
            user: null,
            isAdmin: false,
            currentView: null
        },

        // Point d'entrée de l'application
        init() {
            this.attachEventListeners();
            this.checkSession();
        },

        // Gestionnaires d'événements
        attachEventListeners() {
            // Événements de formulaires
            document.getElementById('loginFormElement').addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });

            document.getElementById('registerFormElement').addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });

            document.getElementById('verifyEmailFormElement').addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleVerifyEmail();
            });

            document.getElementById('verify2FAFormElement').addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleVerify2FA();
            });

            document.getElementById('changePasswordFormElement')?.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleChangePassword();
            });

            // Navigation et actions
            document.querySelectorAll('[data-action]').forEach(element => {
                element.addEventListener('click', (e) => {
                    e.preventDefault();
                    const action = element.getAttribute('data-action');
                    if (this[action]) {
                        this[action](e);
                    }
                });
            });
        },

        // Vérification de session
        async checkSession() {
            try {
                const response = await fetch('/api/auth/session', {
                    method: 'GET',
                    credentials: 'include'
                });

                if (response.ok) {
                    const data = await response.json();
                    this.state.token = data.token;
                    this.state.user = data.user;
                    this.state.isAdmin = data.user.isAdmin;
                    this.showDashboard();
                } else {
                    this.showLogin();
                }
            } catch (error) {
                console.error('Erreur lors de la vérification de la session:', error);
                this.showLogin();
            }
        },

        // Gestion de la connexion
        async handleLogin() {
            try {
                const email = document.getElementById('loginEmail').value;
                const password = document.getElementById('loginPassword').value;
                const recaptchaResponse = grecaptcha.getResponse();

                if (!recaptchaResponse) {
                    this.showMessage('loginMessage', 'Veuillez compléter le captcha', 'error');
                    return;
                }

                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, recaptchaResponse })
                });

                const data = await response.json();

                if (response.ok) {
                    if (data.requires2FA) {
                        this.showVerify2FA();
                    } else if (!data.user.emailVerified) {
                        this.showVerifyEmail();
                    } else {
                        this.state.token = data.token;
                        this.state.user = data.user;
                        this.state.isAdmin = data.user.isAdmin;
                        this.showDashboard();
                    }
                } else {
                    this.showMessage('loginMessage', data.message || 'Erreur de connexion', 'error');
                }
            } catch (error) {
                console.error('Erreur lors de la connexion:', error);
                this.showMessage('loginMessage', 'Erreur de connexion', 'error');
            }
        },

        // Gestion de l'inscription
        async handleRegister() {
            try {
                const email = document.getElementById('registerEmail').value;
                const password = document.getElementById('registerPassword').value;
                const phone = document.getElementById('registerPhone').value;

                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, phone })
                });

                const data = await response.json();

                if (response.ok) {
                    this.showMessage('registerMessage', 'Inscription réussie! Vérifiez votre email.', 'success');
                    this.showVerifyEmail();
                } else {
                    this.showMessage('registerMessage', data.message || 'Erreur lors de l\'inscription', 'error');
                }
            } catch (error) {
                console.error('Erreur lors de l\'inscription:', error);
                this.showMessage('registerMessage', 'Erreur lors de l\'inscription', 'error');
            }
        },

        // Gestion de la vérification email
        async handleVerifyEmail() {
            try {
                const code = document.getElementById('verifyCode').value;

                const response = await fetch('/api/auth/verify-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });

                const data = await response.json();

                if (response.ok) {
                    this.state.token = data.token;
                    this.state.user = data.user;
                    this.showDashboard();
                } else {
                    this.showMessage('verifyMessage', data.message || 'Code invalide', 'error');
                }
            } catch (error) {
                console.error('Erreur lors de la vérification:', error);
                this.showMessage('verifyMessage', 'Erreur lors de la vérification', 'error');
            }
        },

        // Gestion de la vérification 2FA
        async handleVerify2FA() {
            try {
                const code = document.getElementById('twoFACode').value;

                const response = await fetch('/api/auth/verify-2fa', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });

                const data = await response.json();

                if (response.ok) {
                    this.state.token = data.token;
                    this.state.user = data.user;
                    this.showDashboard();
                } else {
                    this.showMessage('2faMessage', data.message || 'Code invalide', 'error');
                }
            } catch (error) {
                console.error('Erreur lors de la vérification 2FA:', error);
                this.showMessage('2faMessage', 'Erreur lors de la vérification 2FA', 'error');
            }
        },

        // Gestion du changement de mot de passe
        async handleChangePassword() {
            try {
                const currentPassword = document.getElementById('currentPassword').value;
                const newPassword = document.getElementById('newPassword').value;

                const response = await fetch('/api/user/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.state.token}`
                    },
                    body: JSON.stringify({ currentPassword, newPassword })
                });

                const data = await response.json();

                if (response.ok) {
                    this.showMessage('securityMessage', 'Mot de passe modifié avec succès', 'success');
                    document.getElementById('changePasswordFormElement').reset();
                } else {
                    this.showMessage('securityMessage', data.message || 'Erreur lors du changement de mot de passe', 'error');
                }
            } catch (error) {
                console.error('Erreur lors du changement de mot de passe:', error);
                this.showMessage('securityMessage', 'Erreur lors du changement de mot de passe', 'error');
            }
        },

        // Gestion de la déconnexion
        async logout() {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
            } catch (error) {
                console.error('Erreur lors de la déconnexion:', error);
            } finally {
                this.state.token = null;
                this.state.user = null;
                this.state.isAdmin = false;
                this.showLogin();
            }
        },

        // Gestion de l'affichage des sections
        showLogin() {
            this.hideAllSections();
            document.getElementById('loginForm').style.display = 'flex';
            grecaptcha.reset();
            this.state.currentView = 'login';
        },

        showRegister() {
            this.hideAllSections();
            document.getElementById('registerForm').style.display = 'flex';
            this.state.currentView = 'register';
        },

        showVerifyEmail() {
            this.hideAllSections();
            document.getElementById('verifyEmailForm').style.display = 'flex';
            this.state.currentView = 'verifyEmail';
        },

        showVerify2FA() {
            this.hideAllSections();
            document.getElementById('verify2FAForm').style.display = 'flex';
            this.state.currentView = '2fa';
        },

        showDashboard() {
            this.hideAllSections();
            document.getElementById('navbar').style.display = 'flex';
            document.getElementById('dashboard').style.display = 'block';
            document.getElementById('profileSection').style.display = 'block';
            document.getElementById('securitySection').style.display = 'none';
            document.getElementById('adminSection').style.display = 'none';
            
            if (this.state.isAdmin) {
                document.getElementById('adminLink').style.display = 'block';
            }

            this.loadProfileData();
            this.state.currentView = 'dashboard';
        },

        showProfile() {
            document.getElementById('profileSection').style.display = 'block';
            document.getElementById('securitySection').style.display = 'none';
            document.getElementById('adminSection').style.display = 'none';
            this.loadProfileData();
        },

        showSecurity() {
            document.getElementById('profileSection').style.display = 'none';
            document.getElementById('securitySection').style.display = 'block';
            document.getElementById('adminSection').style.display = 'none';
            this.loadSecurityData();
        },

        showAdmin() {
            if (!this.state.isAdmin) return;
            document.getElementById('profileSection').style.display = 'none';
            document.getElementById('securitySection').style.display = 'none';
            document.getElementById('adminSection').style.display = 'block';
            this.loadAdminData();
        },

        // Chargement des données
        async loadProfileData() {
            try {
                const response = await fetch('/api/user/profile', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    const profileContent = document.getElementById('profileContent');
                    profileContent.innerHTML = `
                        <div class="profile-info">
                            <p><strong>Email:</strong> ${data.email}</p>
                            <p><strong>Email vérifié:</strong> ${data.emailVerified ? '✅' : '❌'}</p>
                            <p><strong>Téléphone:</strong> ${data.phone || 'Non défini'}</p>
                            <p><strong>2FA activé:</strong> ${data.twoFactorEnabled ? '✅' : '❌'}</p>
                            <p><strong>Dernière connexion:</strong> ${new Date(data.lastLogin).toLocaleString()}</p>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Erreur lors du chargement du profil:', error);
            }
        },

        async loadSecurityData() {
            try {
                // Chargement des données de vérification email
                const emailResponse = await fetch('/api/user/email-status', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
                if (emailResponse.ok) {
                    const emailData = await emailResponse.json();
                    const emailContent = document.querySelector('#emailVerificationContent .current-value');
                    emailContent.textContent = `Email actuel: ${emailData.email} (${emailData.verified ? 'Vérifié ✅' : 'Non vérifié ❌'})`;
                }

                // Chargement des données de vérification téléphone
                const phoneResponse = await fetch('/api/user/phone-status', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
                if (phoneResponse.ok) {
                    const phoneData = await phoneResponse.json();
                    document.getElementById('phoneNumber').value = phoneData.phone || '';
                }

                // Chargement des données 2FA
                const twoFAResponse = await fetch('/api/twofa/status', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
                if (twoFAResponse.ok) {
                    const twoFAData = await twoFAResponse.json();
                    const twoFAContent = document.getElementById('2faContent');
                    if (twoFAData.enabled) {
                        twoFAContent.innerHTML = `
                            <p>2FA est activé ✅</p>
                            <button class="btn btn-danger" onclick="app.disable2FA()">Désactiver 2FA</button>
                        `;
                    } else {
                        twoFAContent.innerHTML = `
                            <p>2FA est désactivé ❌</p>
                            <button class="btn btn-primary" onclick="app.setup2FA()">Activer 2FA</button>
                        `;
                    }
                }

                // Chargement des sessions actives
                const sessionsResponse = await fetch('/api/user/sessions', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
                if (sessionsResponse.ok) {
                    const sessionsData = await sessionsResponse.json();
                    const sessionsContent = document.getElementById('sessionsContent');
                    sessionsContent.innerHTML = sessionsData.sessions.map(session => `
                        <div class="session-item">
                            <p><strong>Appareil:</strong> ${session.userAgent}</p>
                            <p><strong>IP:</strong> ${session.ip}</p>
                            <p><strong>Dernière activité:</strong> ${new Date(session.lastActivity).toLocaleString()}</p>
                            ${session.current ? '<span class="current-session">Session courante</span>' : 
                            `<button class="btn btn-danger" onclick="app.terminateSession('${session.id}')">Terminer la session</button>`}
                        </div>
                    `).join('');
                }

                // Chargement des logs de sécurité
                const logsResponse = await fetch('/api/user/security-logs', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });
                if (logsResponse.ok) {
                    const logsData = await logsResponse.json();
                    const logsContent = document.getElementById('logsContent');
                    logsContent.innerHTML = logsData.logs.map(log => `
                        <div class="log-item ${log.type}">
                            <p><strong>${new Date(log.timestamp).toLocaleString()}</strong></p>
                            <p>${log.message}</p>
                            <p><small>IP: ${log.ip}</small></p>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Erreur lors du chargement des données de sécurité:', error);
            }
        },

        async loadAdminData() {
            if (!this.state.isAdmin) return;

            try {
                const response = await fetch('/api/admin/dashboard', {
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    const adminContent = document.getElementById('adminContent');
                    adminContent.innerHTML = `
                        <div class="admin-stats">
                            <div class="stat-card">
                                <h3>Utilisateurs</h3>
                                <p class="stat-number">${data.stats.totalUsers}</p>
                            </div>
                            <div class="stat-card">
                                <h3>Actifs aujourd'hui</h3>
                                <p class="stat-number">${data.stats.activeToday}</p>
                            </div>
                            <div class="stat-card">
                                <h3>2FA activé</h3>
                                <p class="stat-number">${data.stats.twoFactorEnabled}</p>
                            </div>
                        </div>
                        <div class="admin-users">
                            <h3>Utilisateurs récents</h3>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Email</th>
                                        <th>Statut</th>
                                        <th>2FA</th>
                                        <th>Dernière connexion</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.recentUsers.map(user => `
                                        <tr>
                                            <td>${user.email}</td>
                                            <td>${user.status}</td>
                                            <td>${user.twoFactorEnabled ? '✅' : '❌'}</td>
                                            <td>${new Date(user.lastLogin).toLocaleString()}</td>
                                            <td>
                                                <button class="btn btn-small" onclick="app.adminViewUser('${user.id}')">Voir</button>
                                                ${user.status === 'blocked' ?
                                                    `<button class="btn btn-small btn-success" onclick="app.adminUnblockUser('${user.id}')">Débloquer</button>` :
                                                    `<button class="btn btn-small btn-danger" onclick="app.adminBlockUser('${user.id}')">Bloquer</button>`
                                                }
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Erreur lors du chargement des données admin:', error);
            }
        },

        // Fonctions administrateur
        async adminViewUser(userId) {
            // Implémentation à venir
        },

        async adminBlockUser(userId) {
            // Implémentation à venir
        },

        async adminUnblockUser(userId) {
            // Implémentation à venir
        },

        // Fonctions de sécurité
        async setup2FA() {
            try {
                const response = await fetch('/api/twofa/setup', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    const twoFAContent = document.getElementById('2faContent');
                    twoFAContent.innerHTML = `
                        <div class="qr-setup">
                            <p>Scannez ce QR code avec votre application d'authentification:</p>
                            <img src="${data.qrCode}" alt="QR Code 2FA">
                            <p>Ou entrez cette clé manuellement: <code>${data.secret}</code></p>
                            <div class="form-group">
                                <label>Entrez le code pour vérifier:</label>
                                <input type="text" id="setup2FACode" maxlength="6">
                            </div>
                            <button class="btn btn-primary" onclick="app.verify2FASetup()">Vérifier et activer</button>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Erreur lors de la configuration 2FA:', error);
            }
        },

        async verify2FASetup() {
            try {
                const code = document.getElementById('setup2FACode').value;
                const response = await fetch('/api/twofa/verify-setup', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code })
                });

                if (response.ok) {
                    this.showMessage('securityMessage', '2FA activé avec succès', 'success');
                    this.loadSecurityData();
                } else {
                    this.showMessage('securityMessage', 'Code invalide', 'error');
                }
            } catch (error) {
                console.error('Erreur lors de la vérification 2FA:', error);
                this.showMessage('securityMessage', 'Erreur lors de la vérification', 'error');
            }
        },

        async disable2FA() {
            try {
                const response = await fetch('/api/twofa/disable', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });

                if (response.ok) {
                    this.showMessage('securityMessage', '2FA désactivé avec succès', 'success');
                    this.loadSecurityData();
                }
            } catch (error) {
                console.error('Erreur lors de la désactivation 2FA:', error);
                this.showMessage('securityMessage', 'Erreur lors de la désactivation 2FA', 'error');
            }
        },

        async terminateSession(sessionId) {
            try {
                const response = await fetch(`/api/user/sessions/${sessionId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${this.state.token}`
                    }
                });

                if (response.ok) {
                    this.showMessage('securityMessage', 'Session terminée avec succès', 'success');
                    this.loadSecurityData();
                }
            } catch (error) {
                console.error('Erreur lors de la terminaison de la session:', error);
                this.showMessage('securityMessage', 'Erreur lors de la terminaison de la session', 'error');
            }
        },

        // Utilitaires
        hideAllSections() {
            document.getElementById('navbar').style.display = 'none';
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('verifyEmailForm').style.display = 'none';
            document.getElementById('verify2FAForm').style.display = 'none';
            document.getElementById('dashboard').style.display = 'none';
        },

        showMessage(elementId, message, type = 'info') {
            const element = document.getElementById(elementId);
            if (element) {
                element.textContent = message;
                element.className = `message ${type}`;
                setTimeout(() => {
                    element.textContent = '';
                    element.className = 'message';
                }, 5000);
            }
        }
    };

    // Initialisation de l'application
    document.addEventListener('DOMContentLoaded', () => app.init());

    // Exposition globale pour les événements inline
    window.app = app;
})();