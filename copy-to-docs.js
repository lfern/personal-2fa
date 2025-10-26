/**
 * Copy /dist files to /docs for GitHub Pages
 * Maintains /dist for development, /docs for GitHub Pages publishing
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync, copyFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const distDir = join(__dirname, 'dist');
const docsDir = join(__dirname, 'docs');

/**
 * Recursively copy directory
 */
function copyDir(src, dest) {
  if (!existsSync(dest)) {
    mkdirSync(dest, { recursive: true });
  }

  const entries = readdirSync(src);

  for (const entry of entries) {
    const srcPath = join(src, entry);
    const destPath = join(dest, entry);

    if (statSync(srcPath).isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
      console.log(`📄 Copied: ${entry}`);
    }
  }
}

/**
 * Main execution
 */
function main() {
  console.log('📂 Copying /dist to /docs for GitHub Pages...\n');

  if (!existsSync(distDir)) {
    console.error('❌ /dist directory not found. Run "npm run build:single" first.');
    process.exit(1);
  }

  // Create docs directory if it doesn't exist
  if (!existsSync(docsDir)) {
    mkdirSync(docsDir, { recursive: true });
    console.log('📁 Created /docs directory');
  }

  try {
    // Copy all files from dist to docs
    copyDir(distDir, docsDir);
    
    console.log('\n✅ Successfully copied /dist to /docs');
    console.log('🚀 Ready for GitHub Pages!');
    console.log('');
    console.log('📋 Next steps:');
    console.log('1. Commit changes: git add . && git commit -m "Update docs for GitHub Pages"');
    console.log('2. Push to GitHub: git push');
    console.log('3. Configure GitHub Pages to use /docs folder');
    console.log('4. Access at: https://[username].github.io/personal-2fa/');

  } catch (error) {
    console.error('❌ Error copying files:', error.message);
    process.exit(1);
  }
}

main();