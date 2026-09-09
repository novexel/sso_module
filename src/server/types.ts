/**
 * @file server/types.ts
 * Server-side interfaces, adapters, and configuration options.
 * Author: Novexel
 * License: MIT
 */

import { NovexelUserIdentity } from '../common/types';

export interface ServerValidationOptions {
    /** Application (Client) ID expected in token `aud` claim */
    clientId: string;
    /** Dedicated Directory (Tenant) ID expected in token `tid` claim */
    tenantId: string;
    /** Allow multi-tenant placeholder discovery strings ('common', 'organizations'). Default false for strict security. */
    allowGenericTenants?: boolean;
    /** Allowed clock skew in seconds. Default 30. */
    clockToleranceSec?: number;
    /** Optional custom JWKS key resolver for offline testing / mock suites */
    customJwksClient?: {
        getSigningKey: (kid?: string) => Promise<{ getPublicKey: () => string }>;
    };
}

/**
 * Storage Adapter interface for decoupled persistence.
 * Implement this interface with your database ORM (Prisma, TypeORM, Drizzle, Mongo, DynamoDB, etc.).
 */
export interface UserStorageAdapter<TUser = any> {
    /** Find an existing user by verified primary email */
    findByEmail: (email: string, context?: any) => Promise<TUser | null>;
    /** Find an existing user by Entra Object ID (handles email renames in directory) */
    findByOid?: (oid: string, context?: any) => Promise<TUser | null>;
    /** Bind an Entra OID to an existing user account */
    bindOid: (userId: string, oid: string, identity: NovexelUserIdentity, context?: any) => Promise<TUser>;
    /** Create a newly provisioned user (JIT Provisioning) */
    createUser: (identity: NovexelUserIdentity, context?: any) => Promise<TUser>;
    /** Update user's last login timestamp */
    updateLastLogin?: (userId: string, context?: any) => Promise<void>;
    /** Check if account is active or disabled */
    isUserDisabled?: (user: TUser) => boolean;
}

/**
 * Session Token Generator interface.
 * Generates an application-level session (JWT, opaque session cookie, etc.).
 */
export interface SessionTokenGenerator<TUser = any> {
    generateSession: (user: TUser, identity: NovexelUserIdentity, context?: any) => Promise<{
        token: string;
        expiresIn?: number | string;
        userPayload?: any;
    }>;
}

/**
 * Pluggable audit logging interface.
 * Zero tokens or sensitive headers are passed to the audit logger.
 */
export interface AuditLogger {
    log: (event: {
        eventType: 'SSO_LOGIN_SUCCESS' | 'SSO_LOGIN_FAILURE' | 'ACCOUNT_BINDING_CONFLICT';
        userEmail?: string;
        clientIp?: string;
        reason?: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        metadata?: Record<string, any>;
        context?: any;
    }) => Promise<void> | void;
}

/**
 * Dynamic configuration resolver for multi-tenant or runtime configuration environments.
 */
export type ConfigResolver<TReq = any> = (req: TReq) => Promise<ServerValidationOptions | null> | ServerValidationOptions | null;
