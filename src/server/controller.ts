/**
 * @file server/controller.ts
 * Express-compatible generic SSO exchange route handler factory.
 * Handles token extraction, cryptographic verification, user lookup, account binding,
 * JIT provisioning, and session token issuance.
 *
 * Author: Novexel
 * License: MIT
 */

import { Request, Response } from 'express';
import { NovexelTokenVerifier } from './verifier';
import {
    ServerValidationOptions,
    UserStorageAdapter,
    SessionTokenGenerator,
    AuditLogger,
    ConfigResolver
} from './types';
import {
    NovexelSSOError,
    AccountBindingConflictError,
    AccountDisabledError,
    SSODisabledError
} from './errors';

export interface SSOControllerOptions<TUser = any> {
    /** Static options or dynamic per-request resolver */
    config: ServerValidationOptions | ConfigResolver<Request>;
    /** Database storage adapter */
    storageAdapter: UserStorageAdapter<TUser>;
    /** Application session token generator (JWT, session cookie, etc.) */
    sessionGenerator: SessionTokenGenerator<TUser>;
    /** Optional audit logger for secure evidential trail */
    auditLogger?: AuditLogger;
    /** Header or property where user's existing OID is stored in TUser record. Default: 'entraObjectId' */
    userOidField?: keyof TUser | string;
    /** Client ID or IP extraction callback */
    getClientIp?: (req: Request) => string;
}

export function createSSOExchangeHandler<TUser = any>(options: SSOControllerOptions<TUser>) {
    const {
        config,
        storageAdapter,
        sessionGenerator,
        auditLogger,
        userOidField = 'entraObjectId',
        getClientIp = (req: Request) => (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || ''
    } = options;

    return async (req: Request, res: Response) => {
        const clientIp = getClientIp(req);

        // 1. Resolve SSO Configuration
        let activeConfig: ServerValidationOptions | null = null;
        try {
            if (typeof config === 'function') {
                activeConfig = await config(req);
            } else {
                activeConfig = config;
            }
        } catch (confErr: any) {
            return res.status(500).json({
                error: 'Configuration Error',
                message: 'Failed to resolve SSO configuration.'
            });
        }

        if (!activeConfig || !activeConfig.clientId || !activeConfig.tenantId) {
            return res.status(403).json({
                error: 'SSO Disabled',
                message: 'Single Sign-On is not configured or enabled for this context.'
            });
        }

        // 2. Extract ID token (Body `idToken` or Authorization `Bearer <token>`)
        let idToken = req.body?.idToken;
        if (!idToken && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
            idToken = req.headers.authorization.substring(7);
        }

        if (!idToken || typeof idToken !== 'string' || !idToken.trim()) {
            return res.status(400).json({
                error: 'Authentication Required',
                message: 'A valid identity token is required for SSO exchange.'
            });
        }

        // 3. Cryptographically Verify Token
        let verifiedIdentity;
        try {
            verifiedIdentity = await NovexelTokenVerifier.verifyIdToken(idToken, activeConfig);
        } catch (err: any) {
            const isNovexelError = err instanceof NovexelSSOError;
            const statusCode = isNovexelError ? err.statusCode : 401;
            const code = isNovexelError ? err.code : 'VERIFICATION_FAILED';

            // Evidential audit log (zero raw tokens or sensitive headers)
            if (auditLogger) {
                try {
                    await auditLogger.log({
                        eventType: 'SSO_LOGIN_FAILURE',
                        clientIp,
                        reason: code,
                        severity: statusCode >= 500 ? 'high' : 'medium',
                        context: { statusCode }
                    });
                } catch {}
            }

            return res.status(statusCode).json({
                error: 'Authentication Failed',
                code,
                message: err.message || 'Token could not be verified.'
            });
        }

        // 4. Authoritative Identity Binding & User Lookup
        const { email, oid } = verifiedIdentity;
        let user: TUser | null = null;

        try {
            user = await storageAdapter.findByEmail(email, req);

            if (!user && storageAdapter.findByOid) {
                user = await storageAdapter.findByOid(oid, req);
            }

            let isNewUser = false;

            if (user) {
                // Check for account takeover / binding conflict
                const existingOid = (user as any)[userOidField];
                if (existingOid && existingOid !== oid) {
                    if (auditLogger) {
                        try {
                            await auditLogger.log({
                                eventType: 'ACCOUNT_BINDING_CONFLICT',
                                userEmail: email,
                                clientIp,
                                severity: 'critical',
                                metadata: { attemptedOid: oid }
                            });
                        } catch {}
                    }
                    throw new AccountBindingConflictError();
                }

                // Bind OID if not yet associated
                if (!existingOid) {
                    user = await storageAdapter.bindOid((user as any).id, oid, verifiedIdentity, req);
                } else if (storageAdapter.updateLastLogin) {
                    await storageAdapter.updateLastLogin((user as any).id, req);
                }
            } else {
                // JIT Provisioning
                isNewUser = true;
                user = await storageAdapter.createUser(verifiedIdentity, req);
            }

            // 5. Check if user is disabled
            if (storageAdapter.isUserDisabled && storageAdapter.isUserDisabled(user)) {
                throw new AccountDisabledError();
            }

            // 6. Generate Session Token
            const session = await sessionGenerator.generateSession(user, verifiedIdentity, req);

            // Audit Success
            if (auditLogger) {
                try {
                    await auditLogger.log({
                        eventType: 'SSO_LOGIN_SUCCESS',
                        userEmail: email,
                        clientIp,
                        severity: 'low',
                        metadata: { isNewUser }
                    });
                } catch {}
            }

            return res.json({
                token: session.token,
                expiresIn: session.expiresIn,
                user: session.userPayload || {
                    email: verifiedIdentity.email,
                    name: verifiedIdentity.name,
                    roles: verifiedIdentity.roles
                }
            });

        } catch (err: any) {
            const isNovexelError = err instanceof NovexelSSOError;
            const statusCode = isNovexelError ? err.statusCode : 500;
            const code = isNovexelError ? err.code : 'INTERNAL_AUTH_ERROR';

            return res.status(statusCode).json({
                error: err.name || 'Authentication Error',
                code,
                message: err.message || 'An error occurred while finalizing SSO session.'
            });
        }
    };
}
