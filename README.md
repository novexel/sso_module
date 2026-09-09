# @novexel/sso

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Author: Novexel](https://img.shields.io/badge/Author-Novexel-orange.svg)](#)

Enterprise-grade, zero-trust Microsoft Entra ID (Azure AD) and MSAL Single Sign-On (SSO) module designed by **Novexel** for Node.js backends and React frontends.

Released under the **MIT License** for open use, integration, and modification by software engineers and AI coding assistants.

---

## 🔒 Security Architecture & Rationale

1. **Why Frontend Identity Claims Are Never Trusted:**
   Requests sent to login exchange endpoints originate from arbitrary web browsers. Assertions like `{ email, role, entraObjectId }` sent in HTTP bodies can be easily forged. Only Microsoft's cryptographic signature on the raw `idToken` proves identity.
2. **Cryptographic Signature Verification:**
   Tokens are validated against Microsoft's public JSON Web Key Sets (JWKS) using rotating key caches, enforcing `RS256` and blocking `alg: "none"` injections.
3. **Strict Audience and Directory Scoping:**
   Tokens must explicitly match your application's `clientId` and dedicated directory `tenantId`. Generic multi-tenant strings (`common`, `organizations`) are rejected by default.
4. **Account Takeover Prevention:**
   If an existing user is already bound to Entra OID X, an incoming verified token claiming the same email but presenting OID Y triggers an `ACCOUNT_BINDING_CONFLICT` (403), protecting against email collision attacks.
5. **Decoupled Database Storage:**
   The package does not dictate any database schema or ORM. Provide a `UserStorageAdapter` (Prisma, TypeORM, Mongo, Drizzle, etc.) to handle user lookups, binding, and JIT provisioning.

---

## 📦 Installation

```bash
npm install @novexel/sso @azure/msal-browser @azure/msal-react jsonwebtoken jwks-rsa
```

---

## 🚀 Quickstart: Backend (Express / Node.js)

```typescript
import express from 'express';
import jwt from 'jsonwebtoken';
import { createSSOExchangeHandler, UserStorageAdapter } from '@novexel/sso/server';

const app = express();
app.use(express.json());

// 1. Implement storage adapter for your database (e.g. Prisma)
const storageAdapter: UserStorageAdapter = {
  async findByEmail(email) {
    return prisma.user.findUnique({ where: { email } });
  },
  async findByOid(oid) {
    return prisma.user.findUnique({ where: { entraObjectId: oid } });
  },
  async bindOid(userId, oid) {
    return prisma.user.update({
      where: { id: userId },
      data: { entraObjectId: oid, lastLogin: new Date() }
    });
  },
  async createUser(identity) {
    return prisma.user.create({
      data: {
        email: identity.email,
        name: identity.name,
        entraObjectId: identity.oid,
        role: 'User',
        lastLogin: new Date()
      }
    });
  }
};

// 2. Attach SSO exchange endpoint
app.post(
  '/api/auth/sso-exchange',
  createSSOExchangeHandler({
    config: {
      clientId: process.env.AZURE_CLIENT_ID!,
      tenantId: process.env.AZURE_TENANT_ID!
    },
    storageAdapter,
    sessionGenerator: {
      async generateSession(user) {
        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role },
          process.env.JWT_SECRET!,
          { expiresIn: '24h' }
        );
        return { token, userPayload: user };
      }
    }
  })
);
```

---

## 💻 Quickstart: Frontend (React)

Wrap your React root with `<NovexelAuthProvider>` and use `<MicrosoftSignInButton>` or the `useNovexelSSO` hook anywhere in your component tree:

```tsx
import React from 'react';
import {
  NovexelAuthProvider,
  useNovexelSSO,
  MicrosoftSignInButton
} from '@novexel/sso/client';

export function App() {
  return (
    <NovexelAuthProvider
      config={{
        clientId: 'YOUR_AZURE_CLIENT_ID',
        tenantId: 'YOUR_AZURE_TENANT_ID'
      }}
      exchangeEndpoint="/api/auth/sso-exchange"
      onSessionCreated={({ token, user }) => {
        localStorage.setItem('authToken', token);
      }}
    >
      <MainContent />
    </NovexelAuthProvider>
  );
}

function MainContent() {
  const { isAuthenticated, identity, logout, isLoading } = useNovexelSSO();

  if (isLoading) return <div>Authenticating...</div>;

  if (!isAuthenticated) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <h2>Sign in to continue</h2>
        <MicrosoftSignInButton text="Sign in with Microsoft" />
      </div>
    );
  }

  return (
    <div>
      <h2>Hello, {identity?.name}</h2>
      <p>Signed in as: {identity?.email}</p>
      <button onClick={() => logout()}>Sign out</button>
    </div>
  );
}
```

---

## ⚙️ Advanced Configuration

### Multi-Tenant Dynamic Workspaces
Instead of static `clientId` and `tenantId`, pass a `ConfigResolver` function:

```typescript
const handler = createSSOExchangeHandler({
  config: async (req) => {
    const workspace = await lookupWorkspace(req.headers.host);
    return {
      clientId: workspace.ssoClientId,
      tenantId: workspace.ssoTenantId
    };
  },
  storageAdapter,
  sessionGenerator
});
```

### Auditing
Attach an `AuditLogger` to receive sanitized security events without raw tokens:
- `SSO_LOGIN_SUCCESS`
- `SSO_LOGIN_FAILURE`
- `ACCOUNT_BINDING_CONFLICT`

---

## 🧪 Testing

The package includes cryptographic unit tests with in-memory RSA key generation:

```bash
npm test
```

---

## 📄 License

MIT © 2026 **Novexel**
