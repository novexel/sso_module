/**
 * @file server/errors.ts
 * Standardized error hierarchy for Novexel SSO cryptographic token verification & user exchange.
 * Author: Novexel
 * License: MIT
 */

export class NovexelSSOError extends Error {
    constructor(
        public override message: string,
        public code: string,
        public statusCode: number = 401,
        public details?: any
    ) {
        super(message);
        this.name = 'NovexelSSOError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class MissingTokenError extends NovexelSSOError {
    constructor(message: string = 'Missing or empty identity token.') {
        super(message, 'MISSING_TOKEN', 400);
        this.name = 'MissingTokenError';
    }
}

export class MalformedTokenError extends NovexelSSOError {
    constructor(message: string = 'Malformed or unparseable identity token.') {
        super(message, 'MALFORMED_TOKEN', 401);
        this.name = 'MalformedTokenError';
    }
}

export class UnsupportedAlgorithmError extends NovexelSSOError {
    constructor(alg: string) {
        super(`Unsupported token algorithm '${alg}'. RS256 is strictly required.`, 'UNSUPPORTED_ALGORITHM', 401);
        this.name = 'UnsupportedAlgorithmError';
    }
}

export class SigningKeyResolutionError extends NovexelSSOError {
    constructor(message: string = 'Unable to resolve matching signing key from JWKS metadata.') {
        super(message, 'SIGNING_KEY_RESOLUTION_FAILED', 401);
        this.name = 'SigningKeyResolutionError';
    }
}

export class TokenExpiredError extends NovexelSSOError {
    constructor(message: string = 'Identity token has expired.') {
        super(message, 'TOKEN_EXPIRED', 401);
        this.name = 'TokenExpiredError';
    }
}

export class TokenNotActiveError extends NovexelSSOError {
    constructor(message: string = 'Identity token is not active yet (nbf check failed).') {
        super(message, 'TOKEN_NOT_ACTIVE', 401);
        this.name = 'TokenNotActiveError';
    }
}

export class AudienceMismatchError extends NovexelSSOError {
    constructor(receivedAud: string | string[], expectedAud: string) {
        super(
            `Token audience mismatch. Token was not issued for client ID '${expectedAud}'.`,
            'AUDIENCE_MISMATCH',
            401,
            { receivedAud, expectedAud }
        );
        this.name = 'AudienceMismatchError';
    }
}

export class TenantMismatchError extends NovexelSSOError {
    constructor(receivedTid: string, expectedTid: string) {
        super(
            `Directory tenant mismatch. Token directory '${receivedTid}' does not match expected tenant '${expectedTid}'.`,
            'DIRECTORY_TENANT_MISMATCH',
            401,
            { receivedTid, expectedTid }
        );
        this.name = 'TenantMismatchError';
    }
}

export class IssuerMismatchError extends NovexelSSOError {
    constructor(receivedIss: string, expectedTenantId: string) {
        super(
            `Token issuer invalid: received '${receivedIss}'. Expected authority for tenant '${expectedTenantId}'.`,
            'ISSUER_MISMATCH',
            401,
            { receivedIss, expectedTenantId }
        );
        this.name = 'IssuerMismatchError';
    }
}

export class AccountBindingConflictError extends NovexelSSOError {
    constructor(message: string = 'Existing account identity credentials do not match verified token subject (OID mismatch).') {
        super(message, 'ACCOUNT_BINDING_CONFLICT', 403);
        this.name = 'AccountBindingConflictError';
    }
}

export class AccountDisabledError extends NovexelSSOError {
    constructor(message: string = 'Account is disabled. Please contact an administrator.') {
        super(message, 'ACCOUNT_DISABLED', 403);
        this.name = 'AccountDisabledError';
    }
}

export class SSODisabledError extends NovexelSSOError {
    constructor(message: string = 'Single Sign-On is not configured or enabled for this context.') {
        super(message, 'SSO_DISABLED', 403);
        this.name = 'SSODisabledError';
    }
}
