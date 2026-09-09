/**
 * @file common/types.ts
 * Shared identity, claim, and configuration types for Novexel SSO.
 * Author: Novexel
 * License: MIT
 */

export interface NovexelUserIdentity {
    /** Unique immutable Object ID in Microsoft Entra / Azure AD directory */
    oid: string;
    /** Normalised lower-case user email or UserPrincipalName */
    email: string;
    /** Full display name if available */
    name: string;
    /** Azure AD directory / Tenant ID */
    tid: string;
    /** App roles assigned to this identity in Microsoft Entra */
    roles: string[];
    /** Raw verified claims present on the token */
    rawClaims?: Record<string, any>;
}

export interface NovexelSSOConfig {
    /** Microsoft Entra Application (Client) ID */
    clientId: string;
    /** Microsoft Entra Directory (Tenant) ID */
    tenantId: string;
    /** Optional authority override. Defaults to https://login.microsoftonline.com/{tenantId} */
    authority?: string;
    /** Optional redirect URI. Defaults to window.location.origin on client */
    redirectUri?: string;
    /** Whether SSO is active */
    ssoEnabled?: boolean;
}
