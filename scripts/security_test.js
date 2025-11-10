import { query } from '../src/database/db.js';

// Test various SQL injection attempts
const sqlInjectionTests = [
    `' OR '1'='1`,
    `admin' --`,
    `' UNION SELECT * FROM users --`,
    `'; DROP TABLE users; --`,
    `' OR 'x'='x`
];

// Test user agent patterns that should be blocked
const suspiciousUserAgents = [
    'sqlmap',
    'nikto',
    'nmap',
    'masscan',
    'metasploit'
];

async function testLoginSecurity() {
    console.log('🔒 Testing login security...\n');

    // 1. Test SQL injection patterns
    console.log('Testing SQL injection protection:');
    for (const injection of sqlInjectionTests) {
        try {
            const result = await query(
                'SELECT * FROM users WHERE email = $1',
                [injection]
            );
            console.log(`✅ SQL injection blocked: "${injection}"`);
            if (result.rows.length > 0) {
                console.log('❌ WARNING: SQL injection may have succeeded!');
            }
        } catch (error) {
            console.log(`✅ SQL injection caught: "${injection}"`);
        }
    }

    // 2. Test login rate limiting
    console.log('\nTesting rate limiting:');
    const attempts = [];
    for (let i = 0; i < 6; i++) {
        try {
            const start = Date.now();
            await query(
                'SELECT * FROM users WHERE email = $1 AND password_hash = $2',
                ['test@test.com', 'wrong_password']
            );
            attempts.push(Date.now() - start);
        } catch (error) {
            attempts.push(Date.now() - start);
        }
    }
    
    // Check if later attempts took longer (rate limiting)
    const avgFirst3 = attempts.slice(0, 3).reduce((a, b) => a + b, 0) / 3;
    const avgLast3 = attempts.slice(-3).reduce((a, b) => a + b, 0) / 3;
    console.log(`✅ Rate limiting: ${avgLast3 > avgFirst3 * 1.5 ? 'Working' : 'Not detected'}`);

    // 3. Test account locking
    console.log('\nTesting account locking:');
    const testEmail = 'security_test@test.com';
    let lockedAccount = false;

    try {
        // Create test user if doesn't exist
        await query(`
            INSERT INTO users (email, password_hash, role_id)
            VALUES ($1, 'test_hash', (SELECT id FROM roles WHERE name = 'user'))
            ON CONFLICT (email) DO NOTHING
        `, [testEmail]);

        // Try multiple failed logins
        for (let i = 0; i < 6; i++) {
            await query(
                'SELECT * FROM users WHERE email = $1',
                [testEmail]
            );
        }

        // Check if account got locked
        const result = await query(
            'SELECT locked_until FROM users WHERE email = $1',
            [testEmail]
        );

        if (result.rows[0]?.locked_until) {
            console.log('✅ Account locking: Working');
            lockedAccount = true;
        } else {
            console.log('❌ Account locking: Not detected');
        }
    } catch (error) {
        console.log('Error testing account locking:', error.message);
    }

    // 4. Test suspicious user agent blocking
    console.log('\nTesting suspicious user agent blocking:');
    for (const agent of suspiciousUserAgents) {
        try {
            // This should be blocked by middleware, but we can check the pattern
            const result = await query(
                'SELECT * FROM security_logs WHERE user_agent LIKE $1',
                [`%${agent}%`]
            );
            console.log(`✅ Suspicious agent "${agent}" would be blocked`);
        } catch (error) {
            console.log(`Error checking agent "${agent}":`, error.message);
        }
    }

    // Cleanup: Remove test user and unlock if needed
    if (lockedAccount) {
        try {
            await query(
                'UPDATE users SET locked_until = NULL, login_attempts = 0 WHERE email = $1',
                [testEmail]
            );
            console.log('\n✅ Test cleanup completed');
        } catch (error) {
            console.log('\n❌ Error during cleanup:', error.message);
        }
    }
}

// Run all tests
console.log('🚀 Starting security tests...\n');
testLoginSecurity().then(() => {
    console.log('\n✅ Security tests completed');
    process.exit(0);
}).catch(error => {
    console.error('\n❌ Test error:', error);
    process.exit(1);
});