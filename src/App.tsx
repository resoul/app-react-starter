import { ThemeProvider } from 'next-themes';
import { HelmetProvider } from '@packages/react-helmet-async';
import { BrowserRouter } from 'react-router-dom';
import { ModuleProvider } from "./providers/module-provider/module-provider";

const { BASE_URL } = import.meta.env;

export default function App() {
    return (
        <ThemeProvider
            attribute="class"
            defaultTheme="light"
            storageKey="vite-theme"
            enableSystem
            disableTransitionOnChange
            enableColorScheme
        >
            <HelmetProvider>
                <BrowserRouter basename={BASE_URL}>
                    <ModuleProvider />
                </BrowserRouter>
            </HelmetProvider>
        </ThemeProvider>
    )
}
