import { Helmet } from '@packages/react-helmet-async';
import { Wrapper } from './components/wrapper';
import { LayoutProvider } from './components/context';
import type { CSSProperties } from "react";

export function Layout() {
    return (
        <>
            <Helmet>
                <title>Layout</title>
            </Helmet>

            <LayoutProvider
                bodyClassName="bg-zinc-100 dark:bg-zinc-900 lg:overflow-hidden"
                style={{
                    '--sidebar-width': '240px',
                    '--aside-width': '50px',
                } as CSSProperties}
            >
                <Wrapper />
            </LayoutProvider>
        </>
    );
}
