/**
 * @file client/components/MicrosoftSignInButton.tsx
 * Accessible, styled Microsoft Single Sign-On Button.
 * Author: Novexel
 * License: MIT
 */

import React from 'react';
import { useNovexelSSO } from '../useNovexelSSO';

export interface MicrosoftSignInButtonProps extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'onError'> {
    /** Button text. Default: "Sign in with Microsoft" */
    text?: string;
    /** Theme mode. Default: 'light' */
    theme?: 'light' | 'dark';
    /** Login mode: 'popup' or 'redirect'. Default: 'popup' */
    mode?: 'popup' | 'redirect';
    /** Optional custom callback after successful login */
    onSuccess?: () => void;
    /** Optional custom callback on error */
    onError?: (err: Error) => void;
}

export const MicrosoftSignInButton: React.FC<MicrosoftSignInButtonProps> = ({
    text = 'Sign in with Microsoft',
    theme = 'light',
    mode = 'popup',
    onSuccess,
    onError,
    className = '',
    style = {},
    disabled = false,
    ...rest
}) => {
    const { loginWithPopup, loginWithRedirect, isLoading } = useNovexelSSO();

    const handleClick = async (e: React.MouseEvent<HTMLButtonElement>) => {
        if (rest.onClick) {
            rest.onClick(e);
        }
        if (e.defaultPrevented) return;

        try {
            if (mode === 'redirect') {
                await loginWithRedirect();
            } else {
                await loginWithPopup();
                if (onSuccess) onSuccess();
            }
        } catch (err: any) {
            if (onError) onError(err);
        }
    };

    const isDark = theme === 'dark';

    const defaultStyle: React.CSSProperties = {
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        padding: '10px 18px',
        fontSize: '14px',
        fontWeight: 600,
        fontFamily: '"Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", sans-serif',
        borderRadius: '6px',
        border: isDark ? '1px solid #374151' : '1px solid #d1d5db',
        backgroundColor: isDark ? '#1f2937' : '#ffffff',
        color: isDark ? '#f9fafb' : '#374151',
        boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
        opacity: disabled || isLoading ? 0.6 : 1,
        transition: 'all 0.15s ease-in-out',
        ...style
    };

    return (
        <button
            type="button"
            disabled={disabled || isLoading}
            onClick={handleClick}
            style={defaultStyle}
            className={`novexel-sso-btn ${className}`}
            {...rest}
        >
            {/* Microsoft 4-square logo */}
            <svg width="20" height="20" viewBox="0 0 21 21" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ flexShrink: 0 }}>
                <path d="M10 0H0V10H10V0Z" fill="#F25022" />
                <path d="M21 0H11V10H21V0Z" fill="#7FBA00" />
                <path d="M10 11H0V21H10V11Z" fill="#00A4EF" />
                <path d="M21 11H11V21H21V11Z" fill="#FFB900" />
            </svg>
            <span>{isLoading ? 'Signing in...' : text}</span>
        </button>
    );
};
