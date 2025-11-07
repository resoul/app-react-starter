import { createContext, useContext, type CSSProperties } from 'react';

interface LayoutState {
    style: CSSProperties;
    bodyClassName: string;
}

export const LayoutContext = createContext<LayoutState | undefined>(undefined);

export const useLayout = () => {
    const context = useContext(LayoutContext);
    if (!context) {
        throw new Error('useLayout must be used within a LayoutProvider');
    }
    return context;
};