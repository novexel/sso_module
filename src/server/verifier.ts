/**
 * @file server/verifier.ts
 * Cryptographic verification engine for Microsoft Entra ID (Azure AD) ID tokens.
 *
 * Security Assertions:
 * 1. Cryptographic Signature Validation via Microsoft's rotating JWKS keys.
 * 2. RS256 algorithm enforcement (blocks alg:none attacks).
 * 3. Exact Audience (`aud`) matching against configured client ID.
 * 4. Exact Tenant ID (`tid`) matching against configured directory ID.
 * 5. Strict Issuer (`iss`) anchoring to the authoritative tenant domain.
 * 6. Temporal validity assertion with configurable clock skew tolerance.
 * 7. Disallowing multi-tenant placeholders ('common', 'organizations') by default.
 *
 * Author: Novexel
 * License: MIT
 */

import jwt, { JwtHeader } from 'jsonwebtoken';
import jwksClient, { JwksClient } from 'jwks-rsa';
import { NovexelUserIdentity } from '../common/types';
import { ServerValidationOptions } from './types';
import {
    MissingTokenError,
    MalformedTokenError,
    UnsupportedAlgorithmError,
    SigningKeyResolutionError,
    TokenExpiredError,
    TokenNotActiveError,
    AudienceMismatchError,
    TenantMismatchError,
    IssuerMismatchError,
    SSODisabledError
} from './errors';

// In-memory cache of JWKS clients keyed by discovery URI
const jwksCache = new Map<string, JwksClient>();

function getOrCreateJwksClient(tenantId: string): JwksClient {
    const jwksUri = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
    let client = jwksCache.get(jwksUri);
    if (!client) {
        client = jwksClient({
            jwksUri,
            cache: true,
            cacheMaxEntries: 10,
            cacheMaxAge: 24 * 60 * 60 * 1000, // 24-hour cache
            rateLimit: true,
            jwksRequestsPerMinute: 10,
            timeout: 10000
        });
        jwksCache.set(jwksUri, client);
    }
    return client;
}

export class NovexelTokenVerifier {
    /**
     * Clear cached JWKS clients (useful for testing or cache eviction)
     */
    public static clearJwksCache(): void {
        jwksCache.clear();
    }

    /**
     * Cryptographically validates a Microsoft Entra ID token and extracts authoritative identity claims.
     */
    public static async verifyIdToken(
        idToken: string,
        options: ServerValidationOptions
    ): Promise<NovexelUserIdentity> {
        if (!idToken || typeof idToken !== 'string' || !idToken.trim()) {
            throw new MissingTokenError();
        }

        const trimmedToken = idToken.trim();

        if (!options.clientId || !options.clientId.trim()) {
            throw new SSODisabledError('SSO misconfigured: client ID is required.');
        }

        if (!options.tenantId || !options.tenantId.trim()) {
            throw new SSODisabledError('SSO misconfigured: directory tenant ID is required.');
        }

        const expectedTenantId = options.tenantId.trim();
        const expectedClientId = options.clientId.trim();

        // Enforce dedicated tenant IDs by default
        const genericTenantStrings = ['common', 'organizations', 'consumers'];
        if (!options.allowGenericTenants && genericTenantStrings.includes(expectedTenantId.toLowerCase())) {
            throw new SSODisabledError(`Generic tenant placeholder '${expectedTenantId}' is not allowed for strict enterprise SSO.`);
        }

        // 1. Decode header to check alg and kid
        const decoded = jwt.decode(trimmedToken, { complete: true });
        if (!decoded || typeof decoded !== 'object' || !decoded.header) {
            throw new MalformedTokenError();
        }

        const header = decoded.header as JwtHeader;
        if (!header.alg || header.alg === 'none' || header.alg !== 'RS256') {
            throw new UnsupportedAlgorithmError(header.alg || 'none');
        }

        if (!header.kid) {
            throw new MalformedTokenError('Token header missing key identifier (kid).');
        }

        // 2. Fetch public key from JWKS
        let signingKey: string;
        try {
            if (options.customJwksClient) {
                const key = await options.customJwksClient.getSigningKey(header.kid);
                signingKey = key.getPublicKey();
            } else {
                const client = getOrCreateJwksClient(expectedTenantId);
                const key = await client.getSigningKey(header.kid);
                signingKey = key.getPublicKey();
            }
        } catch (err: any) {
            throw new SigningKeyResolutionError(err?.message || 'Failed to fetch signing key.');
        }

        // 3. Verify signature, audience, and temporal validity
        let payload: any;
        try {
            payload = jwt.verify(trimmedToken, signingKey, {
                algorithms: ['RS256'],
                audience: expectedClientId,
                clockTolerance: options.clockToleranceSec ?? 30
            });
        } catch (err: any) {
            if (err.name === 'TokenExpiredError') {
                throw new TokenExpiredError();
            }
            if (err.name === 'NotBeforeError') {
                throw new TokenNotActiveError();
            }
            if (err.message && err.message.includes('jwt audience invalid')) {
                throw new AudienceMismatchError(payload?.aud, expectedClientId);
            }
            throw new MalformedTokenError('Cryptographic signature verification failed.');
        }

        // 4. Validate Directory Tenant ID (`tid`)
        const tokenTid = payload.tid;
        if (!tokenTid) {
            throw new MalformedTokenError('Token missing tenant ID (tid) claim.');
        }

        if (expectedTenantId !== tokenTid) {
            throw new TenantMismatchError(tokenTid, expectedTenantId);
        }

        // 5. Validate Issuer (`iss`)
        const validIssuers = [
            `https://login.microsoftonline.com/${expectedTenantId}/v2.0`,
            `https://sts.windows.net/${expectedTenantId}/`
        ];
        if (!payload.iss || !validIssuers.includes(payload.iss)) {
            throw new IssuerMismatchError(payload.iss || 'unknown', expectedTenantId);
        }

        // 6. Extract Authoritative Identity
        const rawEmail = payload.preferred_username || payload.upn || payload.email;
        if (!rawEmail || typeof rawEmail !== 'string') {
            throw new MalformedTokenError('Token missing authoritative user email/UPN identity claim.');
        }

        if (!payload.oid || typeof payload.oid !== 'string') {
            throw new MalformedTokenError('Token missing authoritative user object ID (oid) claim.');
        }

        const normalizedEmail = rawEmail.toLowerCase().trim();
        const normalizedOid = payload.oid.trim();

        return {
            oid: normalizedOid,
            email: normalizedEmail,
            name: payload.name || normalizedEmail.split('@')[0],
            tid: tokenTid,
            roles: Array.isArray(payload.roles) ? payload.roles : [],
            rawClaims: payload
        };
    }
}
