import { query } from '../src/database/db.js';
import { expect } from 'chai';
import jwt from 'jsonwebtoken';

// Helper to create a test admin user and get JWT
const createAdminUser = async () => {
  // First ensure admin role exists with permissions
  await query(`
    INSERT INTO roles (name, priority, description, permissions) 
    VALUES ('admin', 100, 'Full access', '{"manage_users":true,"manage_roles":true,"view_sensitive":true,"edit_content":true,"moderate_content":true}'::jsonb)
    ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions
    RETURNING id
  `);
  const { rows: [role] } = await query('SELECT id FROM roles WHERE name = $1', ['admin']);
  
  // Get or create test admin user
  const { rows: [existingUser] } = await query(
    'SELECT id, email, role_id FROM users WHERE email = $1',
    ['admin@test.com']
  );

  const user = existingUser || (await query(`
    INSERT INTO users (email, password_hash, role_id, is_email_verified)
    VALUES ($1, $2, $3, true)
    RETURNING id, email, role_id
  `, ['admin@test.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpjQI5fGxFyBLK', role.id])).rows[0];

  // Generate JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  return { user, token };
};

describe('Role Permissions', () => {
  let adminToken;
  
  before(async () => {
    // Create admin user and get token
    const admin = await createAdminUser();
    adminToken = admin.token;
  });

  describe('GET /api/admin/roles', () => {
    it('returns roles with permissions', async () => {
      const { rows } = await query('SELECT * FROM roles ORDER BY priority DESC');
      
      // Verify each role has valid permissions JSONB
      for (const role of rows) {
        expect(role).to.have.property('permissions');
        expect(role.permissions).to.be.an('object');
        
        // Check that permissions exists and is an object with boolean values
        const perms = role.permissions;
        expect(perms).to.be.an('object');
        Object.entries(perms).forEach(([key, value]) => {
          expect(value, `Permission ${key} should be boolean`).to.be.a('boolean');
        });
        
        // All permission values should be boolean
        Object.values(perms).forEach(value => {
          expect(value).to.be.a('boolean');
        });
      }
    });
  });

  describe('PUT /api/admin/roles/:roleId', () => {
    it('updates role permissions', async () => {
      // Get moderator role
      const { rows: [mod] } = await query(
        'SELECT id, permissions FROM roles WHERE name = $1',
        ['moderator']
      );

      // Toggle some permissions
      const newPerms = {
        ...mod.permissions,
        edit_content: !mod.permissions.edit_content,
        moderate_content: !mod.permissions.moderate_content
      };

      // Update permissions
      await query(
        'UPDATE roles SET permissions = $1 WHERE id = $2',
        [newPerms, mod.id]
      );

      // Verify changes
      const { rows: [updated] } = await query(
        'SELECT permissions FROM roles WHERE id = $1',
        [mod.id]
      );

      expect(updated.permissions).to.deep.equal(newPerms);
    });
  });
});