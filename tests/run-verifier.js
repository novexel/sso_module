/**
 * Standalone Node.js test runner for Novexel_SSO_Module
 */
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

// Resolve compiled dist files
const { NovexelTokenVerifier } = require('../dist/server/verifier.js');
const {
    MissingTokenError,
    MalformedTokenError,
    UnsupportedAlgorithmError,
    AudienceMismatchError,
    TenantMismatchError,
    IssuerMismatchError,
    TokenExpiredError,
    SSODisabledError
} = require('../dist/server/errors.js');

// Helper to manually create JWTs using jsonwebtoken
const jwt = require('jsonwebtoken');

async function runTests() {
    console.log('Running Novexel_SSO_Module Verification Test Suite...\n');
    let passed = 0;
    let failed = 0;

    async function test(name, fn) {
        try {
            await fn();
            console.log(`  ✓ ${name}`);
            passed++;
        } catch (err) {
            console.error(`  ✗ ${name}`);
            console.error(`    ${err.message}`);
            failed++;
        }
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const keyId = 'test-kid-100';
    const validClientId = '00000000-1111-2222-3333-444444444444';
    const validTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    const otherTenantId = '99999999-8888-7777-6666-555555555555';

    const mockJwksClient = {
        getSigningKey: async (kid) => {
            if (kid === keyId) {
                return { getPublicKey: () => publicKey };
            }
            throw new Error(`Signing key '${kid}' not found in mock JWKS.`);
        }
    };

    const validConfig = {
        clientId: validClientId,
        tenantId: validTenantId,
        customJwksClient: mockJwksClient
    };

    function createToken(payloadOverrides = {}, headerOverrides = {}, signKey = privateKey) {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            aud: validClientId,
            iss: `https://login.microsoftonline.com/${validTenantId}/v2.0`,
            tid: validTenantId,
            oid: 'entra-oid-54321',
            preferred_username: 'engineer@novexel.com',
            name: 'Novexel Engineer',
            iat: now - 10,
            nbf: now - 10,
            exp: now + 3600,
            roles: ['User'],
            ...payloadOverrides
        };

        const header = {
            alg: 'RS256',
            kid: keyId,
            ...headerOverrides
        };

        return jwt.sign(payload, signKey, { algorithm: header.alg || 'RS256', header });
    }

    await test('1. Rejects missing or empty token with MissingTokenError', async () => {
        let err;
        try { await NovexelTokenVerifier.verifyIdToken('', validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof MissingTokenError, 'Should throw MissingTokenError');
    });

    await test('2. Rejects malformed token string with MalformedTokenError', async () => {
        let err;
        try { await NovexelTokenVerifier.verifyIdToken('abc.def', validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof MalformedTokenError, 'Should throw MalformedTokenError');
    });

    await test('3. Rejects alg:none attacks with UnsupportedAlgorithmError', async () => {
        const token = jwt.sign({ aud: validClientId }, '', { algorithm: 'none' });
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(token, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof UnsupportedAlgorithmError, 'Should throw UnsupportedAlgorithmError');
    });

    await test('4. Rejects token signed with wrong key', async () => {
        const { privateKey: fakeKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        const fakeToken = createToken({}, {}, fakeKey);
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(fakeToken, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof MalformedTokenError, 'Should reject invalid signature');
    });

    await test('5. Rejects audience mismatch', async () => {
        const wrongAudToken = createToken({ aud: 'wrong-client-id' });
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(wrongAudToken, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof AudienceMismatchError, 'Should throw AudienceMismatchError');
    });

    await test('6. Rejects directory tenant ID (tid) mismatch', async () => {
        const wrongTidToken = createToken({ tid: otherTenantId });
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(wrongTidToken, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof TenantMismatchError, 'Should throw TenantMismatchError');
    });

    await test('7. Rejects issuer (iss) mismatch', async () => {
        const wrongIssToken = createToken({ iss: 'https://attacker.com/v2.0' });
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(wrongIssToken, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof IssuerMismatchError, 'Should throw IssuerMismatchError');
    });

    await test('8. Rejects expired token', async () => {
        const now = Math.floor(Date.now() / 1000);
        const expiredToken = createToken({ exp: now - 3600, iat: now - 7200, nbf: now - 7200 });
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(expiredToken, validConfig); } catch (e) { err = e; }
        assert.ok(err instanceof TokenExpiredError, 'Should throw TokenExpiredError');
    });

    await test('9. Rejects generic multi-tenant discovery strings', async () => {
        const token = createToken();
        let err;
        try { await NovexelTokenVerifier.verifyIdToken(token, { ...validConfig, tenantId: 'common' }); } catch (e) { err = e; }
        assert.ok(err instanceof SSODisabledError, 'Should throw SSODisabledError');
    });

    await test('10. Validates authentic token and extracts authoritative identity claims', async () => {
        const token = createToken();
        const identity = await NovexelTokenVerifier.verifyIdToken(token, validConfig);
        assert.strictEqual(identity.email, 'engineer@novexel.com');
        assert.strictEqual(identity.oid, 'entra-oid-54321');
        assert.strictEqual(identity.name, 'Novexel Engineer');
        assert.strictEqual(identity.tid, validTenantId);
        assert.deepStrictEqual(identity.roles, ['User']);
    });

    console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);
    if (failed > 0) {
        process.exit(1);
    }
}

runTests();
