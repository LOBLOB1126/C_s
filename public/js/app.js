/**
 * Application JavaScript principale
 * Gestion de l'interface utilisateur et des appels API
 */

const API_URL = window.location.origin;
let currentUser = null;
let tempUserId = null;
let tempEmail = null;
let recaptchaWidgets = {
    login: null,
    register: null
};

// Global click delegation for elements using data-action (CSP-friendly)
function handleDataActionClick(e) {
    const el = e.target.closest && e.target.closest('[data-action]');
    if (!el) return;
    const action = el.dataset.action;
    const id = el.dataset.id;

    switch (action) {
        case 'showProfile': showProfile(); break;
        case 'showSecurity': showSecurity(); break;
        case 'showAdmin': showAdmin(); break;
        case 'logout': logout(); break;
        case 'showRegister': showRegister(); break;
        case 'showLogin': showLogin(); break;
        case 'showPasswordReset': showPasswordReset(); break;
        case 'resendCode': resendCode(); break;
        case 'enable2FA': enable2FA(); break;
        case 'sendEmailVerification': sendEmailVerification(); break;
        case 'verifyEmail': verifyEmailFromProfile(); break;
        case 'updatePhone': updatePhoneNumber(); break;
        case 'verifyPhone': verifyPhoneNumber(); break;
        case 'disable2FA': disable2FA(); break;
        case 'revokeSession': if (id) revokeSession(id); break;
        case 'loadAllUsers': loadAllUsers(); break;
        case 'viewUser': if (id) viewUser(id); break;
        case 'deleteUser': if (id) deleteUserAdmin(id); break;
        case 'toggleLock': if (id) toggleUserLock(id); break;
        case 'showRoles': loadRolesUI(); break;
        default: break;
    }

    e.preventDefault();
}

// Load and display roles with a permission matrix
async function loadRolesUI() {
    try {
        const result = await apiRequest('/api/admin/roles');
        const roles = result.data;

        // Define permission matrix keys and descriptions (keep in sync with server-side checks)
        const permissions = [
            { key: 'users:list', label: 'Lister les utilisateurs' },
            { key: 'users:view', label: 'Voir détails utilisateur' },
            { key: 'users:lock', label: 'Verrouiller/Déverrouiller compte' },
            { key: 'users:role_change', label: 'Changer rôle (admin only)' },
            { key: 'users:delete', label: 'Supprimer utilisateur (admin only)' },
            { key: 'security:logs:view', label: 'Voir logs de sécurité (admin only)' },
            { key: 'stats:view', label: 'Voir statistiques de sécurité' },
            { key: 'roles:list', label: 'Lister les rôles' }
        ];

        // Derive permissions based on role priority/name (reflects current backend enforcement)
        function roleHasPerm(role) {
            const p = { };
            // default: regular users have none of these admin permissions
            p['users:list'] = role.priority >= 50; // moderator+
            p['users:view'] = role.priority >= 50; // moderator+
            p['users:lock'] = role.priority >= 50; // moderator+
            p['stats:view'] = role.priority >= 50; // moderator+
            p['roles:list'] = role.priority >= 50; // moderator+

            // Admin-only actions (requireRole(['admin']))
            p['users:role_change'] = role.name === 'admin';
            p['users:delete'] = role.name === 'admin';
            p['security:logs:view'] = role.name === 'admin';

            return p;
        }

        const headerCols = roles.map(r => `<th>${r.name} <div style="font-size:12px;color:#666">(prio ${r.priority})</div></th>`).join('');
        // Build editable table: permission rows + columns per role
        const rowsHtml = permissions.map(perm => {
            const cols = roles.map(r => {
                // role.permissions may be a JSON object already
                const rp = r.permissions || {};
                const checked = rp[perm.key] ? 'checked' : '';
                return `<td style="text-align:center"><input type="checkbox" data-role-id="${r.id}" data-perm-key="${perm.key}" ${checked} ${currentUser && currentUser.role_name === 'admin' ? '' : 'disabled'}></td>`;
            }).join('');

            return `<tr><td style="padding:8px">${perm.label}</td>${cols}</tr>`;
        }).join('');

        const editNote = currentUser && currentUser.role_name === 'admin'
            ? '<div style="font-size:13px;color:#333;margin-bottom:8px">Vous pouvez modifier les permissions et cliquer sur Sauvegarder.</div>'
            : '<div style="font-size:13px;color:#666;margin-bottom:8px">Connexion en tant que administrateur requise pour modifier les permissions.</div>';

        const tableHtml = `
            <div class="roles-panel">
                <h3>Rôles et permissions</h3>
                ${editNote}
                <table class="roles-table" style="width:100%;border-collapse:collapse">
                    <thead>
                        <tr>
                            <th style="text-align:left">Permission</th>
                            ${headerCols}
                        </tr>
                    </thead>
                    <tbody>
                        ${rowsHtml}
                    </tbody>
                </table>
                <div style="margin-top:12px">
                    <button class="btn btn-sm" data-action="loadAllUsers">Retour</button>
                    ${currentUser && currentUser.role_name === 'admin' ? '<button id="saveRolesBtn" class="btn btn-primary btn-sm" style="margin-left:8px">Sauvegarder</button>' : ''}
                </div>
            </div>
        `;

        document.getElementById('adminContent').innerHTML = tableHtml;

        // Attach save handler if admin
        const saveBtn = document.getElementById('saveRolesBtn');
        if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
                try {
                    // For each role, gather permissions
                    const roleMap = {};
                    const checkboxes = document.querySelectorAll('input[data-role-id]');
                    checkboxes.forEach(cb => {
                        const rid = cb.dataset.roleId;
                        const key = cb.dataset.permKey;
                        roleMap[rid] = roleMap[rid] || {};
                        roleMap[rid][key] = cb.checked;
                    });

                    // Send updates sequentially (small number of roles)
                    for (const rid of Object.keys(roleMap)) {
                        await apiRequest(`/api/admin/roles/${rid}`, 'PUT', { permissions: roleMap[rid] });
                    }

                    alert('Permissions mises à jour');
                    loadRolesUI();
                } catch (err) {
                    alert(err.message || 'Erreur lors de la sauvegarde');
                }
            });
        }
    } catch (error) {
        alert(error.message || 'Impossible de charger les rôles');
    }
}
// Utilitaire pour faire des requêtes API
async function apiRequest(endpoint, method = 'GET', data = null) {
    const token = localStorage.getItem('token');

    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            ...(token && { 'Authorization': `Bearer ${token}` })
        }
    };

    if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, options);
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || 'Une erreur est survenue');
        }

        return result;
    } catch (error) {
        throw error;
    }
}

// Afficher un message
function showMessage(elementId, message, type = 'error') {
    const element = document.getElementById(elementId);
    if (!element) {
        console.error(`Element with ID '${elementId}' not found`);
        alert(message); // Fallback pour afficher le message
        return;
    }
    element.textContent = message;
    element.className = `message ${type}`;
    element.style.display = 'block';

    setTimeout(() => {
        element.style.display = 'none';
    }, 5000);
}

// Inscription
async function register(event) {
    event.preventDefault();

    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const phone = document.getElementById('registerPhone').value;

    // Récupérer la réponse du widget register
    const recaptchaToken = recaptchaWidgets.register !== null
        ? grecaptcha.getResponse(recaptchaWidgets.register)
        : grecaptcha.getResponse();

    if (!recaptchaToken) {
        showMessage('registerMessage', 'Veuillez cocher la case reCAPTCHA', 'error');
        return;
    }

    try {
        const result = await apiRequest('/api/auth/register', 'POST', {
            email,
            password,
            phone: phone || undefined,
            recaptchaToken
        });

        tempEmail = email;
        showMessage('registerMessage', result.message, 'success');

        // Réinitialiser le reCAPTCHA
        if (recaptchaWidgets.register !== null) {
            grecaptcha.reset(recaptchaWidgets.register);
        }

        setTimeout(() => {
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('verifyEmailForm').style.display = 'flex';
        }, 1500);
    } catch (error) {
        showMessage('registerMessage', error.message, 'error');
        // Réinitialiser le reCAPTCHA en cas d'erreur
        if (recaptchaWidgets.register !== null) {
            grecaptcha.reset(recaptchaWidgets.register);
        }
    }
}

// Vérification email
async function verifyEmail(event) {
    event.preventDefault();

    const code = document.getElementById('verifyCode').value;

    try {
        const result = await apiRequest('/api/auth/verify-email', 'POST', {
            email: tempEmail,
            code
        });

        showMessage('verifyMessage', result.message, 'success');

        setTimeout(() => {
            showLogin();
        }, 1500);
    } catch (error) {
        showMessage('verifyMessage', error.message, 'error');
    }
}

// Renvoyer le code
async function resendCode() {
    try {
        const result = await apiRequest('/api/auth/resend-code', 'POST', {
            email: tempEmail
        });

        showMessage('verifyMessage', result.message, 'success');
    } catch (error) {
        showMessage('verifyMessage', error.message, 'error');
    }
}

// Connexion
async function login(event) {
    event.preventDefault();

    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    // Récupérer la réponse du widget login
    const recaptchaToken = recaptchaWidgets.login !== null
        ? grecaptcha.getResponse(recaptchaWidgets.login)
        : grecaptcha.getResponse();

    if (!recaptchaToken) {
        showMessage('loginMessage', 'Veuillez cocher la case reCAPTCHA', 'error');
        return;
    }

    try {
        const result = await apiRequest('/api/auth/login', 'POST', {
            email,
            password,
            recaptchaToken
        });

        // Réinitialiser le reCAPTCHA après succès
        if (recaptchaWidgets.login !== null) {
            grecaptcha.reset(recaptchaWidgets.login);
        }

        if (result.requires2FA) {
            tempUserId = result.tempUserId;
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('verify2FAForm').style.display = 'flex';
            showMessage('2faMessage', result.message, 'info');
        } else {
            localStorage.setItem('token', result.data.token);
            currentUser = result.data.user;
            showDashboard();
        }
    } catch (error) {
        showMessage('loginMessage', error.message, 'error');
        // Réinitialiser le reCAPTCHA en cas d'erreur
        if (recaptchaWidgets.login !== null) {
            grecaptcha.reset(recaptchaWidgets.login);
        }
    }
}

// Vérification 2FA lors de la connexion
async function verify2FALogin(event) {
    event.preventDefault();

    const token = document.getElementById('twoFACode').value;

    try {
        const result = await apiRequest('/api/2fa/verify-login', 'POST', {
            userId: tempUserId,
            token
        });

        localStorage.setItem('token', result.data.token);
        currentUser = result.data.user;
        showDashboard();
    } catch (error) {
        showMessage('2faMessage', error.message, 'error');
    }
}

// Déconnexion
async function logout() {
    try {
        await apiRequest('/api/auth/logout', 'POST');
    } catch (error) {
        console.error('Erreur lors de la déconnexion:', error);
    } finally {
        localStorage.removeItem('token');
        currentUser = null;
        showLogin();
    }
}

// Changer le mot de passe
async function changePassword(event) {
    event.preventDefault();

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;

    try {
        const result = await apiRequest('/api/user/change-password', 'POST', {
            currentPassword,
            newPassword
        });

        alert(result.message);
        event.target.reset();
    } catch (error) {
        alert(error.message);
    }
}

// Afficher le tableau de bord
async function showDashboard() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('verifyEmailForm').style.display = 'none';
    document.getElementById('verify2FAForm').style.display = 'none';
    document.getElementById('navbar').style.display = 'flex';
    document.getElementById('dashboard').style.display = 'block';

    await loadProfile();

    // Vérifier si le profil a été chargé avec succès
    if (!currentUser) {
        // loadProfile a échoué et a déjà redirigé vers la page de connexion
        return;
    }

    showProfile();

    // Afficher le lien admin si l'utilisateur est admin ou moderator
    if (currentUser.role_name === 'admin' || currentUser.role_name === 'moderator') {
        document.getElementById('adminLink').style.display = 'block';
    }
}

// Charger le profil
async function loadProfile() {
    try {
        const result = await apiRequest('/api/user/profile');
        currentUser = result.data;

        const profileHtml = `
            <p><strong>Email:</strong> ${currentUser.email}</p>
            <p><strong>Téléphone:</strong> ${currentUser.phone || 'Non renseigné'}</p>
            <p><strong>Rôle:</strong> ${currentUser.role_name || 'Non défini'}</p>
            <p><strong>2FA:</strong> ${currentUser.is_2fa_enabled ? 'Activé ✅' : 'Désactivé ❌'}</p>
            <p><strong>Dernière connexion:</strong> ${new Date(currentUser.last_login).toLocaleString('fr-FR')}</p>
            <p><strong>Membre depuis:</strong> ${new Date(currentUser.created_at).toLocaleString('fr-FR')}</p>
        `;

        document.getElementById('profileContent').innerHTML = profileHtml;
    } catch (error) {
        console.error('Erreur lors du chargement du profil:', error);
        // Si le token est invalide ou expiré, déconnecter l'utilisateur
        localStorage.removeItem('token');
        currentUser = null;
        showLogin();
    }
}

// Afficher les sections
function showProfile() {
    document.getElementById('profileSection').style.display = 'block';
    document.getElementById('securitySection').style.display = 'none';
    document.getElementById('adminSection').style.display = 'none';
}

function showSecurity() {
    document.getElementById('profileSection').style.display = 'none';
    document.getElementById('securitySection').style.display = 'block';
    document.getElementById('adminSection').style.display = 'none';
    updateVerificationStatus();
    load2FAStatus();
    loadSessions();
    loadSecurityLogs();
}

function showAdmin() {
    document.getElementById('profileSection').style.display = 'none';
    document.getElementById('securitySection').style.display = 'none';
    document.getElementById('adminSection').style.display = 'block';
    loadAdminDashboard();
}

// Mettre à jour le statut des vérifications
async function updateVerificationStatus() {
    // Mettre à jour le statut email
    const emailStatus = document.getElementById('emailVerificationStatus');
    const emailContent = document.getElementById('emailVerificationContent');
    if (currentUser.is_email_verified) {
        emailStatus.innerHTML = '✅';
        emailContent.innerHTML = `<p>Email vérifié: ${currentUser.email}</p>`;
    } else {
        emailStatus.innerHTML = '❌';
        emailContent.innerHTML = `
            <p class="current-value">Email non vérifié: ${currentUser.email}</p>
            <button class="btn btn-primary" data-action="sendEmailVerification">Vérifier l'email</button>
            <div class="verification-form" style="display: none;">
                <div class="form-group">
                    <label>Code de vérification</label>
                    <input type="text" id="emailVerificationCode" maxlength="6">
                </div>
                <button class="btn btn-primary" data-action="verifyEmail">Confirmer</button>
            </div>
        `;
    }

    // Mettre à jour le statut téléphone
    const phoneStatus = document.getElementById('phoneVerificationStatus');
    const phoneContent = document.getElementById('phoneVerificationContent');
    if (currentUser.is_phone_verified) {
        phoneStatus.innerHTML = '✅';
        phoneContent.innerHTML = `<p>Téléphone vérifié: ${currentUser.phone}</p>`;
    } else {
        phoneStatus.innerHTML = '❌';
        phoneContent.innerHTML = `
            <div class="form-group">
                <label>Numéro de téléphone</label>
                <input type="tel" id="phoneNumber" placeholder="+33612345678" value="${currentUser.phone || ''}">
            </div>
            <button class="btn btn-primary" data-action="updatePhone">Mettre à jour</button>
            <div class="verification-form" style="display: none;">
                <div class="form-group">
                    <label>Code de vérification</label>
                    <input type="text" id="phoneVerificationCode" maxlength="6">
                </div>
                <button class="btn btn-primary" data-action="verifyPhone">Vérifier</button>
            </div>
        `;
    }
}

// Charger le statut 2FA
async function load2FAStatus() {
    const content = document.getElementById('2faContent');
    if (currentUser.is_2fa_enabled) {
        content.innerHTML = `
            <p>La 2FA est activée ✅</p>
            <button class="btn btn-danger" data-action="disable2FA">Désactiver la 2FA</button>
        `;
    } else {
        content.innerHTML = `
            <p>La 2FA n'est pas activée ❌</p>
            <button class="btn btn-primary" data-action="enable2FA">Activer la 2FA</button>
        `;
    }
}

// Activer la 2FA
async function enable2FA() {
    try {
        const result = await apiRequest('/api/2fa/generate', 'POST');
        const qrHtml = `
            <p>Scannez ce QR code avec votre application d'authentification (Google Authenticator, Authy, etc.)</p>
            <img src="${result.data.qrCode}" alt="QR Code 2FA" style="max-width: 300px;">
            <p><strong>Secret (si vous ne pouvez pas scanner):</strong> ${result.data.secret}</p>
            <form id="verify2FASetupForm">
                <div class="form-group">
                    <label>Entrez le code généré par votre application:</label>
                    <input type="text" id="verify2FAToken" maxlength="6" required>
                </div>
                <button type="submit" class="btn btn-primary">Vérifier et activer</button>
            </form>
        `;

        document.getElementById('2faContent').innerHTML = qrHtml;
        const setupForm = document.getElementById('verify2FASetupForm');
        if (setupForm) setupForm.addEventListener('submit', verify2FA);
    } catch (error) {
        alert(error.message);
    }
}

// Vérifier et activer la 2FA
async function verify2FA(event) {
    event.preventDefault();

    const token = document.getElementById('verify2FAToken').value;

    try {
        const result = await apiRequest('/api/2fa/enable', 'POST', { token });
        alert(result.message);
        currentUser.is_2fa_enabled = true;
        load2FAStatus();
    } catch (error) {
        alert(error.message);
    }
}

// Désactiver la 2FA
async function disable2FA() {
    const password = prompt('Entrez votre mot de passe pour confirmer:');
    if (!password) return;

    try {
        const result = await apiRequest('/api/2fa/disable', 'POST', { password });
        alert(result.message);
        currentUser.is_2fa_enabled = false;
        load2FAStatus();
    } catch (error) {
        alert(error.message);
    }
}

// Charger les sessions actives
async function loadSessions() {
    try {
        const result = await apiRequest('/api/user/sessions');

        const sessionsHtml = result.data.map(session => `
            <div class="session-item">
                <p><strong>IP:</strong> ${session.ip_address}</p>
                <p><strong>Appareil:</strong> ${session.user_agent}</p>
                <p><strong>Date:</strong> ${new Date(session.created_at).toLocaleString('fr-FR')}</p>
                <button class="btn btn-danger btn-sm" data-action="revokeSession" data-id="${session.id}">Révoquer</button>
            </div>
        `).join('');

        document.getElementById('sessionsContent').innerHTML = sessionsHtml || '<p>Aucune session active</p>';
    } catch (error) {
        console.error('Erreur lors du chargement des sessions:', error);
    }
}

// Révoquer une session
async function revokeSession(sessionId) {
    try {
        await apiRequest(`/api/user/sessions/${sessionId}`, 'DELETE');
        loadSessions();
    } catch (error) {
        alert(error.message);
    }
}

// Charger les logs de sécurité
async function loadSecurityLogs() {
    try {
        const result = await apiRequest('/api/user/security-logs?limit=20');

        const logsHtml = result.data.map(log => `
            <div class="log-item ${log.success ? 'success' : 'failure'}">
                <p><strong>${log.action}</strong> - ${log.success ? '✅' : '❌'}</p>
                <p>IP: ${log.ip_address} | ${new Date(log.created_at).toLocaleString('fr-FR')}</p>
            </div>
        `).join('');

        document.getElementById('logsContent').innerHTML = logsHtml || '<p>Aucun log</p>';
    } catch (error) {
        console.error('Erreur lors du chargement des logs:', error);
    }
}

// Charger le dashboard admin
async function loadAdminDashboard() {
    try {
        const result = await apiRequest('/api/admin/stats');

        const statsHtml = `
            <div class="admin-stats">
                <div class="stat-card">
                    <h3>${result.data.totalUsers}</h3>
                    <p>Utilisateurs totaux</p>
                </div>
                <div class="stat-card">
                    <h3>${result.data.verifiedUsers}</h3>
                    <p>Utilisateurs vérifiés</p>
                </div>
                <div class="stat-card">
                    <h3>${result.data.users2FA}</h3>
                    <p>Utilisateurs avec 2FA</p>
                </div>
                <div class="stat-card">
                    <h3>${result.data.failedLogins24h}</h3>
                    <p>Connexions échouées (24h)</p>
                </div>
                <div class="stat-card">
                    <h3>${result.data.lockedAccounts}</h3>
                    <p>Comptes verrouillés</p>
                </div>
            </div>
                    <button class="btn btn-primary" data-action="loadAllUsers">Voir tous les utilisateurs</button>
                    <button class="btn btn-secondary" style="margin-left:8px;" data-action="showRoles">Rôles et permissions</button>
        `;

        document.getElementById('adminContent').innerHTML = statsHtml;
    } catch (error) {
        console.error('Erreur lors du chargement des stats:', error);
    }
}

// Charger tous les utilisateurs (admin)
async function loadAllUsers() {
    try {
        const result = await apiRequest('/api/admin/users');

        const usersHtml = `
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Rôle</th>
                        <th>Vérifié</th>
                        <th>2FA</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.data.users.map(user => `
                        <tr>
                            <td>${user.email}</td>
                            <td>${user.role}</td>
                            <td>${user.is_email_verified ? '✅' : '❌'}</td>
                            <td>${user.is_2fa_enabled ? '✅' : '❌'}</td>
                            <td>
                                <button class="btn btn-sm" data-action="viewUser" data-id="${user.id}">Voir</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        document.getElementById('adminContent').innerHTML = usersHtml;
    } catch (error) {
        alert(error.message);
    }
}

// View a single user's details in the admin panel
async function viewUser(userId) {
    try {
        const result = await apiRequest(`/api/admin/users/${userId}`);
        const user = result.data;

        const userHtml = `
            <div class="admin-user-detail">
                <h3>Détails utilisateur</h3>
                <p><strong>Email:</strong> ${user.email}</p>
                <p><strong>Rôle:</strong> ${user.role}</p>
                <p><strong>Vérifié:</strong> ${user.is_email_verified ? '✅' : '❌'}</p>
                <p><strong>2FA:</strong> ${user.is_2fa_enabled ? '✅' : '❌'}</p>
                <p><strong>Téléphone:</strong> ${user.phone || '—'}</p>
                <p><strong>Dernière connexion:</strong> ${user.last_login ? new Date(user.last_login).toLocaleString('fr-FR') : '—'}</p>
                <p><strong>Statut du compte:</strong> ${user.locked_until ? `🔒 Verrouillé jusqu'au ${new Date(user.locked_until).toLocaleString('fr-FR')}` : '🔓 Déverrouillé'}</p>
                <div class="admin-actions">
                    <button class="btn btn-sm" data-action="loadAllUsers">Retour</button>
                    ${user.locked_until 
                        ? `<button class="btn btn-success btn-sm" data-action="toggleLock" data-id="${user.id}">Déverrouiller</button>`
                        : `<button class="btn btn-warning btn-sm" data-action="toggleLock" data-id="${user.id}">Verrouiller</button>`
                    }
                    <button class="btn btn-danger btn-sm" data-action="deleteUser" data-id="${user.id}">Supprimer</button>
                </div>
            </div>
        `;

        document.getElementById('adminContent').innerHTML = userHtml;
    } catch (error) {
        alert(error.message || 'Impossible de récupérer l\'utilisateur');
    }
}

// Lock/unlock a user account
async function toggleUserLock(userId) {
    try {
        const result = await apiRequest(`/api/admin/users/${userId}/lock`, 'PUT');
        alert(result.message || 'Statut du compte mis à jour');
        // Refresh user details
        viewUser(userId);
    } catch (error) {
        alert(error.message || 'Erreur lors du changement de statut');
    }
}

// Delete a user (admin action) with confirmation
async function deleteUserAdmin(userId) {
    if (!confirm('Voulez-vous vraiment supprimer cet utilisateur? Cette action est irréversible.')) return;

    try {
        const result = await apiRequest(`/api/admin/users/${userId}`, 'DELETE');
        alert(result.message || 'Utilisateur supprimé');
        // Refresh list
        loadAllUsers();
    } catch (error) {
        alert(error.message || 'Erreur lors de la suppression');
    }
}

// Navigation
function showLogin() {
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('verifyEmailForm').style.display = 'none';
    document.getElementById('verify2FAForm').style.display = 'none';
    document.getElementById('passwordResetRequestForm').style.display = 'none';
    document.getElementById('passwordResetForm').style.display = 'none';
    document.getElementById('navbar').style.display = 'none';
    document.getElementById('dashboard').style.display = 'none';
}

function showRegister() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'flex';
    document.getElementById('verifyEmailForm').style.display = 'none';
    document.getElementById('passwordResetRequestForm').style.display = 'none';
    document.getElementById('passwordResetForm').style.display = 'none';
}

function showPasswordReset() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('verifyEmailForm').style.display = 'none';
    document.getElementById('passwordResetRequestForm').style.display = 'flex';
    document.getElementById('passwordResetForm').style.display = 'none';
}

function showPasswordResetCodeForm() {
    document.getElementById('passwordResetRequestForm').style.display = 'none';
    document.getElementById('passwordResetForm').style.display = 'flex';
}

// Request password reset
async function requestPasswordReset(e) {
    e.preventDefault();

    const email = document.getElementById('resetEmail').value;
    const messageEl = document.getElementById('resetRequestMessage');

    try {
        const response = await fetch('/api/auth/password-reset-request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await response.json();

        if (data.success) {
            messageEl.className = 'message success';
            messageEl.textContent = data.message || 'Code de réinitialisation envoyé par email. Vérifiez votre boîte de réception.';
            messageEl.style.display = 'block';

            // Pré-remplir l'email dans le formulaire de réinitialisation
            document.getElementById('resetPasswordEmail').value = email;

            // Passer au formulaire de réinitialisation après 2 secondes
            setTimeout(() => {
                showPasswordResetCodeForm();
            }, 2000);
        } else {
            messageEl.className = 'message error';
            messageEl.textContent = data.message || 'Erreur lors de la demande de réinitialisation';
            messageEl.style.display = 'block';
        }
    } catch (error) {
        console.error('Password reset request error:', error);
        messageEl.className = 'message error';
        messageEl.textContent = 'Erreur de connexion au serveur';
        messageEl.style.display = 'block';
    }
}

// Reset password with code
async function resetPassword(e) {
    e.preventDefault();

    const email = document.getElementById('resetPasswordEmail').value;
    const code = document.getElementById('resetCode').value;
    const newPassword = document.getElementById('newPasswordReset').value;
    const confirmPassword = document.getElementById('confirmPasswordReset').value;
    const messageEl = document.getElementById('resetMessage');

    // Validate passwords match
    if (newPassword !== confirmPassword) {
        messageEl.className = 'message error';
        messageEl.textContent = 'Les mots de passe ne correspondent pas';
        messageEl.style.display = 'block';
        return;
    }

    // Validate password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        messageEl.className = 'message error';
        messageEl.textContent = 'Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial';
        messageEl.style.display = 'block';
        return;
    }

    try {
        const response = await fetch('/api/auth/password-reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                code,
                newPassword
            })
        });

        const data = await response.json();

        if (data.success) {
            messageEl.className = 'message success';
            messageEl.textContent = data.message || 'Mot de passe réinitialisé avec succès ! Redirection...';
            messageEl.style.display = 'block';

            // Reset form
            document.getElementById('passwordResetFormElement').reset();

            // Redirect to login after 2 seconds
            setTimeout(() => {
                showLogin();
                messageEl.style.display = 'none';
            }, 2000);
        } else {
            messageEl.className = 'message error';
            messageEl.textContent = data.message || 'Code invalide ou expiré';
            messageEl.style.display = 'block';
        }
    } catch (error) {
        console.error('Password reset error:', error);
        messageEl.className = 'message error';
        messageEl.textContent = 'Erreur de connexion au serveur';
        messageEl.style.display = 'block';
    }
}

// Fonction globale appelée quand reCAPTCHA est prêt
window.onGrecaptchaLoad = function() {
    console.log('reCAPTCHA loaded');
    // Initialiser manuellement les widgets reCAPTCHA
    const loginWidget = document.getElementById('recaptcha-login');
    const registerWidget = document.getElementById('recaptcha-register');

    if (loginWidget && typeof grecaptcha !== 'undefined') {
        try {
            recaptchaWidgets.login = grecaptcha.render('recaptcha-login', {
                'sitekey': '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'theme': 'light'
            });
            console.log('Login reCAPTCHA widget initialized');
        } catch (e) {
            console.error('Error initializing login reCAPTCHA:', e);
        }
    }

    if (registerWidget && typeof grecaptcha !== 'undefined') {
        try {
            recaptchaWidgets.register = grecaptcha.render('recaptcha-register', {
                'sitekey': '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'theme': 'light'
            });
            console.log('Register reCAPTCHA widget initialized');
        } catch (e) {
            console.error('Error initializing register reCAPTCHA:', e);
        }
    }
};

// Vérifier si l'utilisateur est déjà connecté au chargement
window.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
    if (token) {
        showDashboard();
    }
});

// Attach global event listeners (CSP-friendly)
document.addEventListener('click', handleDataActionClick);

// Attach submit handlers for the main forms (if present)
const loginFormEl = document.getElementById('loginFormElement');
if (loginFormEl) loginFormEl.addEventListener('submit', login);

const registerFormEl = document.getElementById('registerFormElement');
if (registerFormEl) registerFormEl.addEventListener('submit', register);

const verifyEmailFormEl = document.getElementById('verifyEmailFormElement');
if (verifyEmailFormEl) verifyEmailFormEl.addEventListener('submit', verifyEmail);

const verify2FAFormEl = document.getElementById('verify2FAFormElement');
if (verify2FAFormEl) verify2FAFormEl.addEventListener('submit', verify2FALogin);

const changePasswordFormEl = document.getElementById('changePasswordFormElement');
if (changePasswordFormEl) changePasswordFormEl.addEventListener('submit', changePassword);

const passwordResetRequestFormEl = document.getElementById('passwordResetRequestFormElement');
if (passwordResetRequestFormEl) passwordResetRequestFormEl.addEventListener('submit', requestPasswordReset);

const passwordResetFormEl = document.getElementById('passwordResetFormElement');
if (passwordResetFormEl) passwordResetFormEl.addEventListener('submit', resetPassword);

// Fonctions de vérification du profil
async function sendEmailVerification() {
    try {
        const result = await apiRequest('/api/auth/resend-code', 'POST', {
            email: currentUser.email
        });
        
        document.querySelector('#emailVerificationSection .verification-form').style.display = 'block';
        showMessage('profileMessage', result.message, 'success');
    } catch (error) {
        showMessage('profileMessage', error.message, 'error');
    }
}

async function verifyEmailFromProfile() {
    const code = document.getElementById('emailVerificationCode').value;
    
    try {
        const result = await apiRequest('/api/auth/verify-email', 'POST', {
            email: currentUser.email,
            code
        });
        
        showMessage('profileMessage', result.message, 'success');
        await loadProfile(); // Recharger le profil pour mettre à jour le statut
    } catch (error) {
        showMessage('profileMessage', error.message, 'error');
    }
}

async function updatePhoneNumber() {
    const phone = document.getElementById('phoneNumber').value;
    
    try {
        const result = await apiRequest('/api/user/update-phone', 'POST', {
            phone
        });
        
        document.querySelector('#phoneSection .verification-form').style.display = 'block';
        showMessage('profileMessage', result.message, 'success');
    } catch (error) {
        showMessage('profileMessage', error.message, 'error');
    }
}

async function verifyPhoneNumber() {
    const code = document.getElementById('phoneVerificationCode').value;
    
    try {
        const result = await apiRequest('/api/user/verify-phone', 'POST', {
            code
        });
        
        showMessage('profileMessage', result.message, 'success');
        await loadProfile(); // Recharger le profil pour mettre à jour le statut
    } catch (error) {
        showMessage('profileMessage', error.message, 'error');
    }
}