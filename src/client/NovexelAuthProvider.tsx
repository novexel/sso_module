/**
 * @file client/NovexelAuthProvider.tsx
 * React Auth Provider wrapping Azure MSAL with dynamic config resolution,
 * token acquisition, and backend session exchange orchestration.
 *
 * Author: Novexel
 * License: MIT
 */

import React, { createContext, useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { PublicClientApplication, InteractionStatus } from '@azure/msal-browser';
import { MsalProvider, useMsal, useIsAuthenticated } from '@azure/msal-react';
import { NovexelAuthProviderProps, NovexelSSOContextValue, NovexelClientConfig } from './types';
import { createMsalConfig, createLoginRequest } from './msalConfig';
import { NovexelUserIdentity } from '../common/types';

export const NovexelSSOContext = createContext<NovexelSSOContextValue | null>(null);

/**
 * Inner Provider that has access to MSAL hooks
 */
const InnerAuthProvider: React.FC<{
    clientConfig: NovexelClientConfig;
    exchangeEndpoint?: string;
    onSessionCreated?: (sessionData: { token: string; user: any }) => void;
    onError?: (error: Error) => void;
    children: React.ReactNode;
}> = ({ clientConfig, exchangeEndpoint, onSessionCreated, onError, children }) => {
    const { instance, accounts, inProgress } = useMsal();
    const isAuthenticated = useIsAuthenticated();
    const [idToken, setIdToken] = useState<string | null>(null);
    const [identity, setIdentity] = useState<NovexelUserIdentity | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);
    const hasExchangedRef = useRef<boolean>(false);

    // Parse active account
    useEffect(() => {
        if (inProgress !== InteractionStatus.None) return;

        const activeAccount = accounts[0];
        if (isAuthenticated && activeAccount) {
            instance.setActiveAccount(activeAccount);

            const claims = (activeAccount.idTokenClaims as any) || {};
            const email = (activeAccount.username || claims.preferred_username || claims.email || '').toLowerCase();
            const oid = claims.oid || (activeAccount as any).localAccountId || '';
            const tid = claims.tid || '';
            const roles = Array.isArray(claims.roles) ? claims.roles : [];

            const parsedIdentity: NovexelUserIdentity = {
                oid,
                email,
                name: activeAccount.name || email.split('@')[0],
                tid,
                roles,
                rawClaims: claims
            };
            setIdentity(parsedIdentity);

            // Extract raw ID token if present on account object
            const rawIdToken = (activeAccount as any).idToken;
            if (rawIdToken) {
                setIdToken(rawIdToken);
            }

            // Optional automatic exchange with backend endpoint
            if (exchangeEndpoint && !hasExchangedRef.current && (rawIdToken || activeAccount)) {
                hasExchangedRef.current = true;
                performExchange(rawIdToken);
            }
        } else if (!isAuthenticated) {
            setIdentity(null);
            setIdToken(null);
            hasExchangedRef.current = false;
        }
    }, [isAuthenticated, accounts, inProgress, instance, exchangeEndpoint]);

    const performExchange = useCallback(async (tokenToExchange?: string) => {
        if (!exchangeEndpoint) return null;
        setIsLoading(true);
        setError(null);

        try {
            let token = tokenToExchange;
            if (!token) {
                const active = instance.getActiveAccount() || accounts[0];
                if (active) {
                    const response = await instance.acquireTokenSilent({
                        ...createLoginRequest(clientConfig),
                        account: active
                    });
                    token = response.idToken;
                }
            }

            if (!token) {
                throw new Error('No valid Microsoft ID token available for exchange.');
            }

            const res = await fetch(exchangeEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ idToken: token })
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.message || data.error || 'SSO Exchange Failed');
            }

            if (onSessionCreated) {
                onSessionCreated(data);
            }
            return data;
        } catch (err: any) {
            const msg = err.message || 'Token exchange failed';
            setError(msg);
            if (onError) onError(err);
            throw err;
        } finally {
            setIsLoading(false);
        }
    }, [exchangeEndpoint, instance, accounts, clientConfig, onSessionCreated, onError]);

    const loginWithPopup = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const res = await instance.loginPopup(createLoginRequest(clientConfig));
            instance.setActiveAccount(res.account);
            if (res.idToken) {
                setIdToken(res.idToken);
                if (exchangeEndpoint) {
                    await performExchange(res.idToken);
                }
            }
        } catch (err: any) {
            setError(err.message || 'Popup login failed');
            if (onError) onError(err);
        } finally {
            setIsLoading(false);
        }
    }, [instance, clientConfig, exchangeEndpoint, performExchange, onError]);

    const loginWithRedirect = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            await instance.loginRedirect(createLoginRequest(clientConfig));
        } catch (err: any) {
            setError(err.message || 'Redirect login failed');
            setIsLoading(false);
            if (onError) onError(err);
        }
    }, [instance, clientConfig, onError]);

    const logout = useCallback(async (options?: { postLogoutRedirectUri?: string; usePopup?: boolean }) => {
        setIsLoading(true);
        try {
            const redirectUri = options?.postLogoutRedirectUri || window.location.origin;
            if (options?.usePopup) {
                await instance.logoutPopup({ postLogoutRedirectUri: redirectUri });
            } else {
                await instance.logoutRedirect({ postLogoutRedirectUri: redirectUri });
            }
            setIdentity(null);
            setIdToken(null);
        } catch (err: any) {
            setError(err.message || 'Logout failed');
            if (onError) onError(err);
        } finally {
            setIsLoading(false);
        }
    }, [instance, onError]);

    const contextValue: NovexelSSOContextValue = useMemo(() => ({
        isAuthenticated,
        identity,
        idToken,
        loginWithPopup,
        loginWithRedirect,
        logout,
        exchangeToken: performExchange,
        isLoading: isLoading || inProgress !== InteractionStatus.None,
        error
    }), [isAuthenticated, identity, idToken, loginWithPopup, loginWithRedirect, logout, performExchange, isLoading, inProgress, error]);

    return (
        <NovexelSSOContext.Provider value={contextValue}>
            {children}
        </NovexelSSOContext.Provider>
    );
};

/**
 * Top-level Provider for applications
 */
export const NovexelAuthProvider: React.FC<NovexelAuthProviderProps> = ({
    children,
    config,
    loadingFallback,
    exchangeEndpoint,
    onSessionCreated,
    onError
}) => {
    const [msalInstance, setMsalInstance] = useState<PublicClientApplication | null>(null);
    const [resolvedConfig, setResolvedConfig] = useState<NovexelClientConfig | null>(null);
    const [initError, setInitError] = useState<Error | null>(null);

    useEffect(() => {
        let isMounted = true;

        async function init() {
            try {
                let resolved: NovexelClientConfig;
                if (typeof config === 'function') {
                    resolved = await config();
                } else if (config) {
                    resolved = config;
                } else {
                    throw new Error('NovexelAuthProvider: configuration or async config loader must be provided.');
                }

                if (!resolved.clientId) {
                    throw new Error('NovexelAuthProvider: clientId is required in configuration.');
                }

                const msalConf = createMsalConfig(resolved);
                const pca = new PublicClientApplication(msalConf);
                await pca.initialize();

                if (isMounted) {
                    setResolvedConfig(resolved);
                    setMsalInstance(pca);
                }
            } catch (err: any) {
                if (isMounted) {
                    setInitError(err);
                    if (onError) onError(err);
                }
            }
        }

        init();

        return () => {
            isMounted = false;
        };
    }, [config, onError]);

    if (initError) {
        return (
            <div style={{ padding: '16px', color: '#b91c1c', background: '#fef2f2', borderRadius: '8px' }}>
                <strong>SSO Initialization Error:</strong> {initError.message}
            </div>
        );
    }

    if (!msalInstance || !resolvedConfig) {
        return loadingFallback ? <>{loadingFallback}</> : null;
    }

    return (
        <MsalProvider instance={msalInstance}>
            <InnerAuthProvider
                clientConfig={resolvedConfig}
                exchangeEndpoint={exchangeEndpoint}
                onSessionCreated={onSessionCreated}
                onError={onError}
            >
                {children}
            </InnerAuthProvider>
        </MsalProvider>
    );
};
