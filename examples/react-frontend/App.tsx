/**
 * @file examples/react-frontend/App.tsx
 * Example React application using @novexel/sso client.
 * Author: Novexel
 * License: MIT
 */

import React from 'react';
import {
    NovexelAuthProvider,
    useNovexelSSO,
    MicrosoftSignInButton
} from '../../src/client';

const UserProfile: React.FC = () => {
    const { isAuthenticated, identity, logout, isLoading } = useNovexelSSO();

    if (isLoading) {
        return <p>Authenticating...</p>;
    }

    if (!isAuthenticated || !identity) {
        return (
            <div style={{ padding: '24px', textAlign: 'center' }}>
                <h2>Welcome</h2>
                <p>Please sign in with your corporate Microsoft account to continue.</p>
                <div style={{ marginTop: '16px' }}>
                    <MicrosoftSignInButton text="Sign in with Work Account" />
                </div>
            </div>
        );
    }

    return (
        <div style={{ padding: '24px' }}>
            <h2>Welcome back, {identity.name}!</h2>
            <p><strong>Email:</strong> {identity.email}</p>
            <p><strong>Directory Tenant:</strong> {identity.tid}</p>
            <p><strong>Roles:</strong> {identity.roles.join(', ') || 'Standard User'}</p>
            <button
                onClick={() => logout()}
                style={{ marginTop: '16px', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}
            >
                Sign Out
            </button>
        </div>
    );
};

export const App: React.FC = () => {
    return (
        <NovexelAuthProvider
            config={{
                clientId: 'your-client-id-here',
                tenantId: 'your-tenant-id-here'
            }}
            exchangeEndpoint="/api/auth/sso-exchange"
            onSessionCreated={({ token, user }) => {
                console.log('Backend session created!', token, user);
                localStorage.setItem('authToken', token);
            }}
            onError={(err) => {
                console.error('SSO Error:', err);
            }}
        >
            <UserProfile />
        </NovexelAuthProvider>
    );
};

export default App;
