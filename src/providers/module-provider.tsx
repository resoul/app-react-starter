import { lazy, Suspense } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { ScreenLoader } from '../components/screen-loader';

const MainModule = lazy(() => import('@/modules/main'));

export function ModuleProvider() {
    const location = useLocation();
    const path = location.pathname;

    const isIam = path.startsWith('/main');

    if (isIam) {
        return (
            <Routes>
                <Route
                    path="/main/*"
                    element={
                        <Suspense fallback={<ScreenLoader />}>
                            <MainModule />
                        </Suspense>
                    }
                />
            </Routes>
        );
    }

    return (
        <Routes>
            <Route
                path="/*"
                element={
                    <h1>Vite + React</h1>
                }
            />
        </Routes>
    );
}