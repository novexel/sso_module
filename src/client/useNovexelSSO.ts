/**
 * @file client/useNovexelSSO.ts
 * React hook to interact with Novexel SSO context.
 * Author: Novexel
 * License: MIT
 */

import { useContext } from 'react';
import { NovexelSSOContext } from './NovexelAuthProvider';
import { NovexelSSOContextValue } from './types';

export function useNovexelSSO(): NovexelSSOContextValue {
    const context = useContext(NovexelSSOContext);
    if (!context) {
        throw new Error('useNovexelSSO must be used within a <NovexelAuthProvider>');
    }
    return context;
}
