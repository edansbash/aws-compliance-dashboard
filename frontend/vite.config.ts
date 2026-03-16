import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
  },
  define: {
    'import.meta.env.VITE_DISPLAY_TIMEZONE': JSON.stringify(process.env.VITE_DISPLAY_TIMEZONE || ''),
  },
})
