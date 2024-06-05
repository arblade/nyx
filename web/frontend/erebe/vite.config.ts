import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 8001, // Set the port to 8001
    proxy: {
      '/api': {
        target: 'http://backend:8002',  // Your backend server
        changeOrigin: true,
        
      }
    }
  },
})
