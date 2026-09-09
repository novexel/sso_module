/**
 * @file examples/express-prisma-backend/server.ts
 * Example implementation of @novexel/sso with Express & Prisma (or any ORM).
 * Author: Novexel
 * License: MIT
 */

import express from 'express';
import jwt from 'jsonwebtoken';
import {
    createSSOExchangeHandler,
    UserStorageAdapter,
    SessionTokenGenerator,
    AuditLogger
} from '../../src/server';

const app = express();
app.use(express.json());

// In-memory mock database for this demonstration
interface AppUser {
    id: string;
    email: string;
    name: string;
    entraObjectId?: string;
    role: string;
    lastLogin?: Date;
    disabled?: boolean;
}

const usersDb = new Map<string, AppUser>();

// 1. Define Storage Adapter
const storageAdapter: UserStorageAdapter<AppUser> = {
    async findByEmail(email: string) {
        return usersDb.get(email.toLowerCase()) || null;
    },
    async findByOid(oid: string) {
        for (const user of usersDb.values()) {
            if (user.entraObjectId === oid) return user;
        }
        return null;
    },
    async bindOid(userId: string, oid: string, identity) {
        const user = Array.from(usersDb.values()).find(u => u.id === userId);
        if (!user) throw new Error('User not found');
        user.entraObjectId = oid;
        user.lastLogin = new Date();
        return user;
    },
    async createUser(identity) {
        const newUser: AppUser = {
            id: `user-${Date.now()}`,
            email: identity.email,
            name: identity.name,
            entraObjectId: identity.oid,
            role: 'User',
            lastLogin: new Date()
        };
        usersDb.set(newUser.email, newUser);
        return newUser;
    },
    async updateLastLogin(userId: string) {
        const user = Array.from(usersDb.values()).find(u => u.id === userId);
        if (user) user.lastLogin = new Date();
    },
    isUserDisabled(user: AppUser) {
        return Boolean(user.disabled);
    }
};

// 2. Define Session Generator
const sessionGenerator: SessionTokenGenerator<AppUser> = {
    async generateSession(user, identity) {
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'super-secret-key',
            { expiresIn: '24h' }
        );
        return {
            token,
            expiresIn: 86400,
            userPayload: { id: user.id, email: user.email, name: user.name, role: user.role }
        };
    }
};

// 3. Define Audit Logger (Optional)
const auditLogger: AuditLogger = {
    async log(event) {
        console.log(`[AUDIT] ${event.eventType} - User: ${event.userEmail || 'unknown'} Severity: ${event.severity}`);
    }
};

// 4. Attach SSO Exchange Endpoint
app.post(
    '/api/auth/sso-exchange',
    createSSOExchangeHandler({
        config: {
            clientId: process.env.AZURE_CLIENT_ID || 'your-client-id',
            tenantId: process.env.AZURE_TENANT_ID || 'your-tenant-id'
        },
        storageAdapter,
        sessionGenerator,
        auditLogger
    })
);

// Start server
const PORT = process.env.PORT || 4000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Novexel SSO example server listening on port ${PORT}`);
    });
}

export default app;
