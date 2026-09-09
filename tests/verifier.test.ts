/**
 * @file tests/verifier.test.ts
 * Cryptographic security test suite for NovexelTokenVerifier.
 * Author: Novexel
 * License: MIT
 */

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { NovexelTokenVerifier } from '../src/server/verifier';
import {
    MissingTokenError,
    MalformedTokenError,
    UnsupportedAlgorithmError,
    AudienceMismatchError,
    TenantMismatchError,
    IssuerMismatchError,
    TokenExpiredError,
    SSODisabledError
} from '../src/server/errors';

describe('NovexelTokenVerifier Cryptographic Security Suite', () => {
    // Generate RSA key pair for cryptographic testing
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const keyId = 'novexel-test-kid-01';
    const validClientId = '00000000-1111-2222-3333-444444444444';
    const validTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    const otherTenantId = '99999999-8888-7777-6666-555555555555';

    const mockJwksClient = {
        getSigningKey: async (kid?: string) => {
            if (kid === keyId) {
                return { getPublicKey: () => publicKey };
            }
            throw new Error(`Signing key '${kid}' not found in test JWKS.`);
        }
    };

    const validOptions = {
        clientId: validClientId,
        tenantId: validTenantId,
        customJwksClient: mockJwksClient
    };

    function createToken(payloadOverrides: any = {}, headerOverrides: any = {}, signKey: string = privateKey): string {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            aud: validClientId,
            iss: `https://login.microsoftonline.com/${validTenantId}/v2.0`,
            tid: validTenantId,
            oid: 'entra-user-oid-12345',
            preferred_username: 'user@example.com',
            name: 'Alice Example',
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

        return jwt.sign(payload, signKey, { algorithm: (header.alg as any) || 'RS256', header });
    }

    it('rejects missing or empty token with MissingTokenError', async () => {
        await expect(NovexelTokenVerifier.verifyIdToken('', validOptions)).rejects.toThrow(MissingTokenError);
        await expect(NovexelTokenVerifier.verifyIdToken(null as any, validOptions)).rejects.toThrow(MissingTokenError);
    });

    it('rejects malformed string token with MalformedTokenError', async () => {
        await expect(NovexelTokenVerifier.verifyIdToken('not-a-valid-jwt', validOptions)).rejects.toThrow(MalformedTokenError);
    });

    it('rejects alg:none token attack with UnsupportedAlgorithmError', async () => {
        const noneToken = jwt.sign({ aud: validClientId }, '', { algorithm: 'none' });
        await expect(NovexelTokenVerifier.verifyIdToken(noneToken, validOptions)).rejects.toThrow(UnsupportedAlgorithmError);
    });

    it('rejects tokens signed with unknown / wrong key', async () => {
        const { privateKey: fakeKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        const fakeSignedToken = createToken({}, {}, fakeKey);
        await expect(NovexelTokenVerifier.verifyIdToken(fakeSignedToken, validOptions)).rejects.toThrow(MalformedTokenError);
    });

    it('rejects audience mismatch', async () => {
        const wrongAudToken = createToken({ aud: 'wrong-client-id' });
        await expect(NovexelTokenVerifier.verifyIdToken(wrongAudToken, validOptions)).rejects.toThrow(AudienceMismatchError);
    });

    it('rejects directory tenant ID (tid) mismatch', async () => {
        const wrongTidToken = createToken({ tid: otherTenantId });
        await expect(NovexelTokenVerifier.verifyIdToken(wrongTidToken, validOptions)).rejects.toThrow(TenantMismatchError);
    });

    it('rejects issuer (iss) mismatch', async () => {
        const wrongIssToken = createToken({ iss: 'https://attacker.example.com/v2.0' });
        await expect(NovexelTokenVerifier.verifyIdToken(wrongIssToken, validOptions)).rejects.toThrow(IssuerMismatchError);
    });

    it('rejects expired tokens with TokenExpiredError', async () => {
        const now = Math.floor(Date.now() / 1000);
        const expiredToken = createToken({ exp: now - 3600, iat: now - 7200, nbf: now - 7200 });
        await expect(NovexelTokenVerifier.verifyIdToken(expiredToken, validOptions)).rejects.toThrow(TokenExpiredError);
    });

    it('rejects generic multi-tenant discovery strings by default', async () => {
        const token = createToken();
        await expect(NovexelTokenVerifier.verifyIdToken(token, {
            ...validOptions,
            tenantId: 'common'
        })).rejects.toThrow(SSODisabledError);
    });

    it('successfully validates legitimate token and extracts authoritative claims', async () => {
        const token = createToken();
        const identity = await NovexelTokenVerifier.verifyIdToken(token, validOptions);

        expect(identity.email).toBe('user@example.com');
        expect(identity.oid).toBe('entra-user-oid-12345');
        expect(identity.name).toBe('Alice Example');
        expect(identity.tid).toBe(validTenantId);
        expect(identity.roles).toEqual(['User']);
    });
});
