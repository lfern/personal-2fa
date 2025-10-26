/**
 * Custom Build Script for Personal 2FA
 * Creates readable, non-minified output compatible with older Node versions
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class PersonalBuildScript {
  constructor() {
    this.srcDir = path.join(__dirname, 'src');
    this.distDir = path.join(__dirname, 'dist');
    this.jsModules = [
      'js/crypto.js',
      'js/storage.js',
      'js/totp.js', 
      'js/qr.js',
      'js/googleAuth.js',
      'js/main.js'
    ];
  }

  /**
   * Main build process
   */
  async build() {
    console.log('🏗️ Starting Personal 2FA build...');
    
    try {
      // Clean and create dist directory
      this.cleanDist();
      this.createDist();
      
      // Process HTML
      await this.processHTML();
      
      // Process JavaScript
      await this.processJavaScript();
      
      // Copy CSS
      await this.processCSS();
      
      console.log('✅ Build completed successfully!');
      this.showBuildInfo();
      
    } catch (error) {
      console.error('❌ Build failed:', error);
      process.exit(1);
    }
  }

  /**
   * Clean dist directory
   */
  cleanDist() {
    if (fs.existsSync(this.distDir)) {
      this.removeDir(this.distDir);
    }
  }

  /**
   * Create dist directory
   */
  createDist() {
    fs.mkdirSync(this.distDir, { recursive: true });
  }

  /**
   * Process HTML file
   */
  async processHTML() {
    console.log('📄 Processing HTML...');
    
    const htmlPath = path.join(this.srcDir, 'index.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    
    // Update script src to point to bundled JS
    html = html.replace(
      '<script type="module" src="./js/main.js"></script>',
      '<script src="./personal-2fa.js"></script>'
    );
    
    // Update CSS path
    html = html.replace(
      '<link rel="stylesheet" href="./styles/app.css">',
      '<link rel="stylesheet" href="./app.css">'
    );
    
    // Add build info comment
    const buildInfo = `
<!-- 
  Personal 2FA - Secure Local Authenticator
  Build: ${new Date().toISOString()}
  Version: 1.0.0
  
  Security Notice:
  - This app works 100% offline
  - All data is encrypted locally
  - No external connections
  - Code is readable and inspectable
-->`;
    
    html = html.replace('<head>', '<head>' + buildInfo);
    
    fs.writeFileSync(path.join(this.distDir, 'index.html'), html);
    console.log('✅ HTML processed');
  }

  /**
   * Process JavaScript modules
   */
  async processJavaScript() {
    console.log('📦 Processing JavaScript...');
    
    let bundledJS = `
/* ====================================
   Personal 2FA - Secure Local 2FA App
   Generated: ${new Date().toISOString()}
   
   Security Features:
   - AES-256-GCM encryption
   - PBKDF2 key derivation
   - IndexedDB local storage
   - Web Crypto API
   - Offline operation
   ==================================== */

`;

    // Process each module
    for (const module of this.jsModules) {
      const modulePath = path.join(this.srcDir, module);
      console.log(`  Processing ${module}...`);
      
      let content = fs.readFileSync(modulePath, 'utf8');
      
      // Remove ES module imports/exports for browser compatibility
      content = this.convertESModulesToIIFE(content, module);
      
      bundledJS += `
/* ============= ${path.basename(module)} ============= */
${content}

`;
    }

    // Add initialization script
    bundledJS += `
/* ============= Initialization ============= */
// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('🚀 Personal 2FA starting...');
  
  // App will be initialized by main.js
  if (typeof Personal2FAApp !== 'undefined') {
    const app = new Personal2FAApp();
    app.init();
    window.Personal2FA = app;
  }
});
`;

    fs.writeFileSync(path.join(this.distDir, 'personal-2fa.js'), bundledJS);
    console.log('✅ JavaScript bundled');
  }

  /**
   * Convert ES modules to browser-compatible IIFE format
   */
  convertESModulesToIIFE(content, moduleName) {
    const exportedNames = [];
    
    // Remove import statements
    content = content.replace(/import\s+.*?from\s+['"].*?['"];?\s*\n?/g, '');
    
    // Handle export class/function declarations
    content = content.replace(/export\s+(class|function)\s+(\w+)/g, (match, type, name) => {
      exportedNames.push(name);
      return `${type} ${name}`;
    });
    
    // Handle export const/let/var
    content = content.replace(/export\s+(const|let|var)\s+(\w+)/g, (match, type, name) => {
      exportedNames.push(name);
      return `${type} ${name}`;
    });
    
    // Handle export { ... } statements
    content = content.replace(/export\s*\{\s*([^}]+)\s*\};?/g, (match, exports) => {
      const exportList = exports.split(',').map(e => e.trim());
      exportedNames.push(...exportList);
      return ''; // Remove the export statement
    });
    
    // Create global assignments for all exported names
    const globalAssignments = exportedNames.length > 0 
      ? '\n  // Export to global scope\n' + exportedNames.map(name => `  window.${name} = ${name};`).join('\n')
      : '';
    
    // Wrap in IIFE
    return `(function() {
  'use strict';
  
${content}${globalAssignments}

})();`;
  }

  /**
   * Process CSS files
   */
  async processCSS() {
    console.log('🎨 Processing CSS...');
    
    const cssPath = path.join(this.srcDir, 'styles', 'app.css');
    const css = fs.readFileSync(cssPath, 'utf8');
    
    // Add build info comment
    const buildComment = `/**
 * Personal 2FA - Styles
 * Build: ${new Date().toISOString()}
 * Mobile-first responsive design
 */

`;
    
    fs.writeFileSync(path.join(this.distDir, 'app.css'), buildComment + css);
    console.log('✅ CSS processed');
  }

  /**
   * Remove directory recursively
   */
  removeDir(dir) {
    if (fs.existsSync(dir)) {
      fs.readdirSync(dir).forEach((file) => {
        const curPath = path.join(dir, file);
        if (fs.lstatSync(curPath).isDirectory()) {
          this.removeDir(curPath);
        } else {
          fs.unlinkSync(curPath);
        }
      });
      fs.rmdirSync(dir);
    }
  }

  /**
   * Show build information
   */
  showBuildInfo() {
    const files = fs.readdirSync(this.distDir);
    
    console.log('\n📦 Build Output:');
    files.forEach(file => {
      const filePath = path.join(this.distDir, file);
      const stats = fs.statSync(filePath);
      const size = (stats.size / 1024).toFixed(2);
      console.log(`  ${file} (${size} KB)`);
    });
    
    console.log('\n🚀 Usage:');
    console.log('  1. Open dist/index.html in a modern browser');
    console.log('  2. Or serve with: npx http-server dist -p 3000');
    console.log('  3. Access via: http://localhost:3000');
    
    console.log('\n🔒 Security:');
    console.log('  ✅ Code is readable and inspectable');
    console.log('  ✅ No external dependencies in output');
    console.log('  ✅ Works offline');
    console.log('  ✅ Uses Web Crypto API');
  }
}

// Run build
const builder = new PersonalBuildScript();
builder.build();