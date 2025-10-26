import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  root: 'src',
  base: './',  // Use relative paths for file:// compatibility
  build: {
    outDir: '../dist-vite',
    emptyOutDir: true,
    minify: false,           // ❌ No minificar - código legible
    sourcemap: false,
    rollupOptions: {
      input: resolve(__dirname, 'src/index.html'),
      output: {
        format: 'es',
        inlineDynamicImports: true,
        entryFileNames: 'personal-2fa.js',
        chunkFileNames: '[name].js',  
        assetFileNames: '[name].[ext]',
        compact: false,      // Mantener espaciado
        indent: '  '         // Indentación legible
      }
    },
    target: 'es2020'
  },
  server: {
    port: 3000,
    open: true
  },
  preview: {
    port: 3000
  }
})