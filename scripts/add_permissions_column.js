#!/usr/bin/env node
import { query } from '../src/database/db.js';

const defaults = [
  {
    name: 'admin',
    permissions: {
      manage_users: true,
      manage_roles: true,
      view_sensitive: true,
      edit_content: true,
      moderate_content: true
    }
  },
  {
    name: 'moderator',
    permissions: {
      manage_users: false,
      manage_roles: false,
      view_sensitive: true,
      edit_content: true,
      moderate_content: true
    }
  },
  {
    name: 'user',
    permissions: {
      manage_users: false,
      manage_roles: false,
      view_sensitive: false,
      edit_content: false,
      moderate_content: false
    }
  }
];

const run = async () => {
  try {
    console.log('Adding permissions column if it does not exist...');
    await query("ALTER TABLE roles ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{}'::jsonb;");

    for (const def of defaults) {
      const permsJson = JSON.stringify(def.permissions);
      console.log(`Setting defaults for role ${def.name}`);
      await query(
        `UPDATE roles SET permissions = $1 WHERE name = $2 AND (permissions IS NULL OR permissions = '{}'::jsonb);`,
        [permsJson, def.name]
      );
    }

    console.log('Permissions column added/updated successfully.');
    process.exit(0);
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
};

run();
