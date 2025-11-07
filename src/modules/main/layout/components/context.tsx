import { type ReactNode, type CSSProperties, useEffect, useMemo } from 'react';
import { LayoutContext } from "@/modules/main/layout/components/use-layout";

// Provider component
interface LayoutProviderProps {
    children: ReactNode;
    style?: CSSProperties;
    bodyClassName?: string;
}

export function LayoutProvider({ children, style: customStyle, bodyClassName = ''}: LayoutProviderProps) {
    const defaultCssVariables = {
        '--sidebar-width': '240px',
        '--aside-width': '80px',
    };

    const cssVariables = useMemo(() => ({
        ...defaultCssVariables,
        ...customStyle,
    }), [customStyle]);

    const style: CSSProperties = cssVariables;
    // Apply CSS variables to HTML root and body className
    useEffect(() => {
        const html = document.documentElement;
        const body = document.body;

        // Store original values for cleanup
        const originalHtmlStyle = html.style.cssText;
        const originalBodyClasses = body.className;

        // Apply CSS variables to HTML root element
        Object.entries(cssVariables).forEach(([property, value]) => {
            html.style.setProperty(property, String(value));
        });

        // Apply body className if provided
        if (bodyClassName) {
            body.className = `${originalBodyClasses} ${bodyClassName}`.trim();
        }

        // Cleanup function
        return () => {
            html.style.cssText = originalHtmlStyle;
            body.className = originalBodyClasses;
        };
    }, [cssVariables, bodyClassName]);

    return (
        <LayoutContext.Provider
            value={{
                bodyClassName,
                style,
            }}
        >
            <div
                data-slot="layout-wrapper"
                className="flex grow"
            >
                {children}
            </div>
        </LayoutContext.Provider>
    );
}
