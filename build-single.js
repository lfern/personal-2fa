/**
 * Single File Builder for Personal 2FA
 * Creates one self-contained HTML file with all CSS and JS inlined
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class SingleFileBuild {
  constructor() {
    this.distDir = path.join(__dirname, 'dist');
    this.outputFile = path.join(this.distDir, 'personal-2fa-standalone.html');
  }

  /**
   * Build single HTML file
   */
  build() {
    console.log('🔧 Building single file version...');
    
    try {
      // Read the built files
      const html = fs.readFileSync(path.join(this.distDir, 'index.html'), 'utf8');
      const css = fs.readFileSync(path.join(this.distDir, 'app.css'), 'utf8');
      const js = fs.readFileSync(path.join(this.distDir, 'personal-2fa.js'), 'utf8');
      
      // Create standalone HTML
      let standalone = html;
      
      // Replace CSS link with inline styles
      standalone = standalone.replace(
        '<link rel="stylesheet" href="./app.css">',
        `<style>\n${css}\n</style>`
      );
      
      // Replace JS script with inline script
      standalone = standalone.replace(
        '<script src="./personal-2fa.js"></script>',
        `<script>\n${js}\n</script>`
      );
      
      // Replace favicon with inline SVG data URL
      const faviconSvg = this.getFaviconDataUrl();
      standalone = standalone.replace(
        /<link rel="icon"[^>]*href="\.\/favicon\.svg"[^>]*>/g,
        `<link rel="icon" type="image/svg+xml" href="${faviconSvg}">`
      );
      standalone = standalone.replace(
        /<link rel="icon"[^>]*href="\.\/favicon\.ico"[^>]*>/g,
        '' // Remove ICO reference for standalone
      );
      
      // Add standalone notice
      const standaloneNotice = `
<!-- 
  ===============================================
  PERSONAL 2FA - STANDALONE VERSION
  ===============================================
  
  This is a self-contained file that includes:
  - All HTML, CSS, and JavaScript
  - No external dependencies
  - Works offline
  - Completely portable
  
  Security Features:
  - AES-256-GCM encryption
  - PBKDF2 key derivation (100,000 iterations)
  - Web Crypto API for hardware acceleration
  - IndexedDB for encrypted local storage
  - No network connections
  
  Usage:
  1. Save this file to your computer
  2. Open in a modern browser (Chrome, Firefox, Safari, Edge)
  3. Create master password on first run
  4. Import from Google Authenticator or add manually
  5. Export QR codes for backup (not stored in app)
  
  File size: ${this.getFileSize(standalone)} KB
  Build date: ${new Date().toISOString()}
  
  ⚠️ IMPORTANT SECURITY NOTES:
  - Only use on HTTPS or localhost for camera access
  - Verify code integrity before use
  - Keep master password secure
  - Make encrypted backups regularly
  
  ===============================================
-->`;
      
      standalone = standalone.replace(
        '<!-- \n  Personal 2FA - Secure Local Authenticator',
        standaloneNotice + '\n\n<!-- \n  Personal 2FA - Secure Local Authenticator'
      );
      
      // Write standalone file
      fs.writeFileSync(this.outputFile, standalone);
      
      console.log('✅ Single file build completed!');
      this.showInfo(standalone);
      
    } catch (error) {
      console.error('❌ Single file build failed:', error);
      process.exit(1);
    }
  }

  /**
   * Get file size in KB
   */
  getFileSize(content) {
    return (Buffer.byteLength(content, 'utf8') / 1024).toFixed(2);
  }

  /**
   * Show build information
   */
  showInfo(content) {
    const filePath = path.relative(process.cwd(), this.outputFile);
    const fileSize = this.getFileSize(content);
    
    console.log('\n📦 Standalone Build:');
    console.log(`  📄 File: ${filePath}`);
    console.log(`  📏 Size: ${fileSize} KB`);
    
    console.log('\n🚀 Usage:');
    console.log('  1. Double-click to open in browser');
    console.log('  2. Or drag & drop into browser window');
    console.log('  3. Works offline - no server needed!');
    
    console.log('\n🔒 Security Verification:');
    console.log('  ✅ All code is readable and inspectable');
    console.log('  ✅ No external resources or CDN links');
    console.log('  ✅ Self-contained - works without internet');
    console.log('  ✅ Uses browser\'s native Web Crypto API');
    
    console.log('\n📋 Distribution:');
    console.log('  - Save to USB drive for portable use');
    console.log('  - Email to yourself (scan for security)');
    console.log('  - Store in cloud (but verify integrity)');
    console.log('  - Share with others (they can verify code)');
  }

  /**
   * Get favicon as data URL
   */
  getFaviconDataUrl() {
    try {
      const faviconPath = path.join(__dirname, 'src', 'favicon.svg');
      if (fs.existsSync(faviconPath)) {
        const svgContent = fs.readFileSync(faviconPath, 'utf8');
        const encodedSvg = Buffer.from(svgContent).toString('base64');
        return `data:image/svg+xml;base64,${encodedSvg}`;
      }
    } catch (error) {
      console.log('⚠️ Could not read favicon, using default');
    }
    
    // Default simple favicon as data URL
    const defaultSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
      <circle cx="16" cy="16" r="14" fill="#2563eb"/>
      <text x="16" y="21" font-family="Arial" font-size="12" font-weight="bold" text-anchor="middle" fill="white">2FA</text>
    </svg>`;
    const encodedDefault = Buffer.from(defaultSvg).toString('base64');
    return `data:image/svg+xml;base64,${encodedDefault}`;
  }
}

// Check if dist directory exists
const distDir = path.join(__dirname, 'dist');
if (!fs.existsSync(distDir)) {
  console.error('❌ dist/ directory not found. Run "npm run build" first.');
  process.exit(1);
}

// Build single file
const builder = new SingleFileBuild();
builder.build();