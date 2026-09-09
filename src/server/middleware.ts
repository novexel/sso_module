/**
 * @file server/middleware.ts
 * Express middleware utilities for Novexel SSO.
 * Author: Novexel
 * License: MIT
 */

import { Request, Response, NextFunction } from 'express';
import { NovexelTokenVerifier } from './verifier';
import { ServerValidationOptions, ConfigResolver } from './types';
import { NovexelSSOError } from './errors';
import { NovexelUserIdentity } from '../common/types';

// Augment Express Request declaration
declare global {
    namespace Express {
        interface Request {
            novexelIdentity?: NovexelUserIdentity;
        }
    }
}

/**
 * Middleware that strictly verifies an incoming Entra ID token on protected endpoints
 * and attaches `req.novexelIdentity`.
 */
export function requireEntraAuth(config: ServerValidationOptions | ConfigResolver<Request>) {
    return async (req: Request, res: Response, next: NextFunction) => {
        let idToken = req.body?.idToken;
        if (!idToken && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
            idToken = req.headers.authorization.substring(7);
        }

        if (!idToken) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Bearer ID token is required.'
            });
        }

        try {
            const activeConfig = typeof config === 'function' ? await config(req) : config;
            if (!activeConfig) {
                return res.status(403).json({
                    error: 'SSO Disabled',
                    message: 'SSO is not configured for this request context.'
                });
            }

            const identity = await NovexelTokenVerifier.verifyIdToken(idToken, activeConfig);
            req.novexelIdentity = identity;
            return next();
        } catch (err: any) {
            const statusCode = err instanceof NovexelSSOError ? err.statusCode : 401;
            return res.status(statusCode).json({
                error: 'Unauthorized',
                code: err.code || 'TOKEN_INVALID',
                message: err.message || 'Token verification failed.'
            });
        }
    };
}
