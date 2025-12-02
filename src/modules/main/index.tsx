import { Routes, Route, Navigate } from 'react-router-dom';
import { MainPage } from "./pages/main/page";
import { Layout } from "./layout";

export default function MainModule() {
    return (
        <Routes>
            <Route element={<Layout />}>
                <Route index element={<Navigate to="main" replace />} />
                <Route path="main" element={<MainPage />} />
            </Route>
        </Routes>
    )
}