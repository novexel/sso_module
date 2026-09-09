/**
 * @file client/types.ts
 * Client-side React types and options for @novexel/sso.
 * Author: Novexel
 * License: MIT
 */

import { ReactNode } from 'react';
import { NovexelSSOConfig, NovexelUserIdentity } from '../common/types';

export interface NovexelClientConfig extends NovexelSSOConfig {
    /** Token scopes requested during login. Defaults to ['User.Read', 'openid', 'profile', 'email'] */
    scopes?: string[];
    /** Cache location: 'sessionStorage' | 'localStorage'. Defaults to 'sessionStorage' */
    cacheLocation?: 'sessionStorage' | 'localStorage';
}

export interface NovexelAuthProviderProps {
    children: ReactNode;
    /** Static config OR async config loader (e.g. dynamic fetch from /api/auth/sso/config) */
    config?: NovexelClientConfig | (() => Promise<NovexelClientConfig>);
    /** Optional custom loading component rendered while MSAL is initializing */
    loadingFallback?: ReactNode;
    /** Backend SSO exchange URL (e.g. '/api/auth/sso-exchange'). If set, automatically calls exchange on login */
    exchangeEndpoint?: string;
    /** Callback fired when a backend session token is issued following successful SSO exchange */
    onSessionCreated?: (sessionData: { token: string; user: any }) => void;
    /** Callback fired when an SSO authentication or exchange error occurs */
    onError?: (error: Error) => void;
}

export interface NovexelSSOContextValue {
    /** True if user has authenticated via Microsoft MSAL */
    isAuthenticated: boolean;
    /** Current authenticated Microsoft account information */
    identity: NovexelUserIdentity | null;
    /** Active ID token string */
    idToken: string | null;
    /** Trigger interactive popup login */
    loginWithPopup: () => Promise<void>;
    /** Trigger redirect login */
    loginWithRedirect: () => Promise<void>;
    /** Logout of Microsoft account */
    logout: (options?: { postLogoutRedirectUri?: string; usePopup?: boolean }) => Promise<void>;
    /** Manually trigger token exchange with backend */
    exchangeToken: (idTokenOverride?: string) => Promise<any>;
    /** Is an auth action currently in progress */
    isLoading: boolean;
    /** Last error message if any */
    error: string | null;
}
