/**
 * @file client/msalConfig.ts
 * Factory for creating MSAL Configuration and Login requests.
 * Author: Novexel
 * License: MIT
 */

import { Configuration, PopupRequest, RedirectRequest } from '@azure/msal-browser';
import { NovexelClientConfig } from './types';

export const DEFAULT_SCOPES = ['User.Read', 'openid', 'profile', 'email'];

export function createMsalConfig(config: NovexelClientConfig): Configuration {
    const authority = config.authority || `https://login.microsoftonline.com/${config.tenantId || 'common'}`;
    const redirectUri = config.redirectUri || (typeof window !== 'undefined' ? window.location.origin : '/');

    return {
        auth: {
            clientId: config.clientId,
            authority,
            redirectUri
        },
        cache: {
            cacheLocation: config.cacheLocation || 'sessionStorage'
        }
    };
}

export function createLoginRequest(config?: NovexelClientConfig): PopupRequest & RedirectRequest {
    return {
        scopes: config?.scopes || DEFAULT_SCOPES,
        prompt: 'select_account'
    };
}
