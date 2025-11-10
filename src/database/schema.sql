-- Sécurisation d'une application web - PostgreSQL Schema
-- Protection contre les injections SQL via requêtes paramétrées

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table des rôles (RBAC - Role-Based Access Control)
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    priority INTEGER NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
-- Insert default roles with permissions JSONB
INSERT INTO roles (name, priority, description, permissions) VALUES
    ('admin', 100, 'Administrator with full access', 
        '{
            "users:list": true,
            "users:view": true,
            "users:lock": true,
            "users:role_change": true,
            "users:delete": true,
            "security:logs:view": true,
            "stats:view": true,
            "roles:list": true
        }'::jsonb),
    ('moderator', 50, 'Moderator with limited administrative access', 
        '{
            "users:list": true,
            "users:view": true,
            "users:lock": true,
            "users:role_change": false,
            "users:delete": false,
            "security:logs:view": false,
            "stats:view": true,
            "roles:list": true
        }'::jsonb),
    ('user', 10, 'Regular user with basic access', 
        '{
            "users:list": false,
            "users:view": false,
            "users:lock": false,
            "users:role_change": false,
            "users:delete": false,
            "security:logs:view": false,
            "stats:view": false,
            "roles:list": false
        }'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role_id INTEGER REFERENCES roles(id) DEFAULT 3,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_phone_verified BOOLEAN DEFAULT FALSE,
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    two_fa_secret VARCHAR(255),
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des codes de vérification (email et téléphone)
CREATE TABLE IF NOT EXISTS verification_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'phone', 'password_reset')),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des sessions/tokens (pour invalider les tokens)
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table de logs de sécurité (audit trail)
CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_verification_codes_user ON verification_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_verification_codes_code ON verification_codes(code);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs(created_at);

-- Trigger pour mettre à jour updated_at automatiquement
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Vue pour les informations utilisateur avec rôle (sans mots de passe)
CREATE OR REPLACE VIEW user_info AS
SELECT
    u.id,
    u.email,
    u.phone,
    u.is_email_verified,
    u.is_phone_verified,
    u.is_2fa_enabled,
    u.last_login,
    u.created_at,
    r.name as role_name,
    r.priority as role_priority
FROM users u
LEFT JOIN roles r ON u.role_id = r.id;
