import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
    plugins: [react(), tailwindcss()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
            '@packages': fileURLToPath(new URL('./packages', import.meta.url)),
        },
    },
    build: {
        chunkSizeWarningLimit: 3000,
    },
})
