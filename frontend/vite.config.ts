import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';

export default defineConfig({
  plugins: [react()],
  css: { postcss: './postcss.config.mjs' },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:18080',
    },
  },
});
