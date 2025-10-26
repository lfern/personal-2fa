/**
 * Google Authenticator Import/Export Module
 * Handles bidirectional sync with Google Authenticator
 * Import: Parse migration QR codes from Google Auth
 * Export: Generate QR codes for backup (NOT for storing in this app)
 */

import { qrManager } from './qr.js';
import { totpGenerator } from './totp.js';

export class GoogleAuthManager {
  constructor() {
    this.exportedSecrets = []; // Temporary storage for export-only mode
  }

  /**
   * Import TOTP secrets from Google Authenticator migration QR
   * @param {string} migrationUri - Migration URI from QR scan
   * @returns {Promise<Array>} Array of imported TOTP configurations
   */
  async importFromGoogleAuth(migrationUri) {
    try {
      console.log('🔄 Importing from Google Authenticator...');
      console.log('🔄 Migration URI:', migrationUri);
      
      // Parse the migration QR data
      const secrets = qrManager.parseMigrationQR(migrationUri);
      console.log('🔄 Parsed secrets from QR manager:', secrets);
      
      if (!secrets || secrets.length === 0) {
        console.error('❌ No secrets found - parsed result:', secrets);
        throw new Error('No TOTP secrets found in migration data');
      }
      
      console.log(`✅ Found ${secrets.length} TOTP secrets to import`);
      
      // Validate and normalize each secret
      const validatedSecrets = [];
      for (const secret of secrets) {
        try {
          console.log('🔄 Validating secret:', secret);
          const validated = await this.validateTOTPSecret(secret);
          validatedSecrets.push(validated);
          console.log('✅ Validated secret:', validated);
        } catch (error) {
          console.warn(`⚠️ Skipping invalid secret for ${secret.issuer}:${secret.label}:`, error.message);
        }
      }
      
      console.log('🔄 Final validated secrets:', validatedSecrets);
      return validatedSecrets;
    } catch (error) {
      console.error('❌ Import error:', error);
      throw new Error(`Import failed: ${error.message}`);
    }
  }

  /**
   * Generate export QRs for backup (NOT for storing in app)
   * This creates QR codes that can be imported into other authenticator apps
   * @param {Array} secrets - TOTP secrets to export
   * @param {string} format - Export format ('individual' | 'migration')
   * @returns {Promise<Array>} Array of QR code data URLs
   */
  async generateExportQRs(secrets, format = 'individual') {
    try {
      console.log(`📤 Generating ${format} export QRs for ${secrets.length} secrets...`);
      
      if (format === 'individual') {
        return await this.generateIndividualQRs(secrets);
      } else if (format === 'migration') {
        return await this.generateMigrationQRs(secrets);
      } else {
        throw new Error(`Unsupported export format: ${format}`);
      }
    } catch (error) {
      throw new Error(`Export failed: ${error.message}`);
    }
  }

  /**
   * Generate individual QR codes (one per TOTP secret)
   * @param {Array} secrets - TOTP secrets
   * @returns {Promise<Array>} Array of QR data objects
   */
  async generateIndividualQRs(secrets) {
    const qrCodes = [];
    
    for (const secret of secrets) {
      try {
        // Generate otpauth:// URI
        const otpauthUri = totpGenerator.generateOTPAuthURI({
          type: 'totp',
          issuer: secret.issuer,
          label: secret.label,
          secret: secret.secret,
          algorithm: secret.algorithm,
          digits: secret.digits,
          period: secret.period
        });
        
        // Generate QR code
        const qrDataUrl = await qrManager.generateQRCode(otpauthUri);
        
        qrCodes.push({
          type: 'individual',
          issuer: secret.issuer,
          label: secret.label,
          qrCode: qrDataUrl,
          otpauthUri: otpauthUri
        });
        
        console.log(`✅ Generated QR for ${secret.issuer}:${secret.label}`);
      } catch (error) {
        console.error(`❌ Failed to generate QR for ${secret.issuer}:${secret.label}:`, error);
      }
    }
    
    return qrCodes;
  }

  /**
   * Generate migration QR codes (Google Authenticator format)
   * @param {Array} secrets - TOTP secrets
   * @returns {Promise<Array>} Array of migration QR data
   */
  async generateMigrationQRs(secrets) {
    const batchSize = 10; // Max secrets per QR (Google Auth limit)
    const qrCodes = [];
    
    // Split secrets into batches
    for (let i = 0; i < secrets.length; i += batchSize) {
      const batch = secrets.slice(i, i + batchSize);
      
      try {
        // Generate migration QR for this batch
        const qrDataUrl = await qrManager.generateMigrationQR(batch);
        
        qrCodes.push({
          type: 'migration',
          secretCount: batch.length,
          batchNumber: Math.floor(i / batchSize) + 1,
          totalBatches: Math.ceil(secrets.length / batchSize),
          qrCode: qrDataUrl,
          secrets: batch.map(s => ({ issuer: s.issuer, label: s.label }))
        });
        
        console.log(`✅ Generated migration QR batch ${qrCodes.length} (${batch.length} secrets)`);
      } catch (error) {
        console.error(`❌ Failed to generate migration QR batch ${i}:`, error);
      }
    }
    
    return qrCodes;
  }

  /**
   * Export to JSON backup format (encrypted)
   * @param {Array} secrets - TOTP secrets
   * @param {string} password - Export password
   * @returns {Promise<string>} JSON backup data
   */
  async exportToJSON(secrets, password) {
    try {
      const exportData = {
        version: '1.0',
        type: 'personal-2fa-backup',
        timestamp: new Date().toISOString(),
        secretCount: secrets.length,
        secrets: secrets.map(secret => ({
          issuer: secret.issuer,
          label: secret.label,
          secret: secret.secret,
          algorithm: secret.algorithm,
          digits: secret.digits,
          period: secret.period
        }))
      };
      
      // If password provided, encrypt the backup
      if (password) {
        // This would use the crypto module to encrypt the JSON
        // For now, return plain JSON (in production, encrypt this)
        console.log('🔐 TODO: Encrypt backup with password');
      }
      
      return JSON.stringify(exportData, null, 2);
    } catch (error) {
      throw new Error(`JSON export failed: ${error.message}`);
    }
  }

  /**
   * Import from JSON backup format
   * @param {string} jsonData - JSON backup data
   * @param {string} password - Decryption password (if encrypted)
   * @returns {Promise<Array>} Array of TOTP secrets
   */
  async importFromJSON(jsonData, password) {
    try {
      // If password provided, decrypt the backup
      if (password) {
        console.log('🔓 TODO: Decrypt backup with password');
        // This would use the crypto module to decrypt
      }
      
      const backupData = JSON.parse(jsonData);
      
      if (backupData.type !== 'personal-2fa-backup') {
        throw new Error('Invalid backup format');
      }
      
      if (!backupData.secrets || !Array.isArray(backupData.secrets)) {
        throw new Error('No secrets found in backup');
      }
      
      // Validate each secret
      const validatedSecrets = [];
      for (const secret of backupData.secrets) {
        try {
          const validated = await this.validateTOTPSecret(secret);
          validatedSecrets.push(validated);
        } catch (error) {
          console.warn(`⚠️ Skipping invalid secret in backup:`, error.message);
        }
      }
      
      console.log(`✅ Imported ${validatedSecrets.length} secrets from JSON backup`);
      return validatedSecrets;
    } catch (error) {
      throw new Error(`JSON import failed: ${error.message}`);
    }
  }

  /**
   * Validate TOTP secret configuration
   * @param {Object} secret - TOTP secret to validate
   * @returns {Promise<Object>} Validated and normalized secret
   */
  async validateTOTPSecret(secret) {
    const { issuer, label, secret: secretKey, algorithm, digits, period } = secret;
    
    // Required fields
    if (!secretKey || !label) {
      throw new Error('Secret and label are required');
    }
    
    // Validate Base32 secret
    if (!totpGenerator.isValidBase32(secretKey)) {
      throw new Error('Invalid Base32 secret');
    }
    
    // Normalize and validate algorithm
    const normalizedAlgorithm = (algorithm || 'SHA1').toUpperCase();
    if (!['SHA1', 'SHA256', 'SHA512'].includes(normalizedAlgorithm)) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    // Validate digits
    const normalizedDigits = parseInt(digits) || 6;
    if (![6, 8].includes(normalizedDigits)) {
      throw new Error(`Invalid digits count: ${digits}`);
    }
    
    // Validate period
    const normalizedPeriod = parseInt(period) || 30;
    if (normalizedPeriod < 15 || normalizedPeriod > 300) {
      throw new Error(`Invalid period: ${period}`);
    }
    
    // Test secret by generating a TOTP code
    try {
      await totpGenerator.generateTOTP(secretKey, {
        algorithm: normalizedAlgorithm,
        digits: normalizedDigits,
        period: normalizedPeriod
      });
    } catch (error) {
      throw new Error(`Secret validation failed: ${error.message}`);
    }
    
    return {
      issuer: issuer || 'Unknown',
      label: label.trim(),
      secret: secretKey.toUpperCase().replace(/\s/g, ''),
      algorithm: normalizedAlgorithm,
      digits: normalizedDigits,
      period: normalizedPeriod
    };
  }

  /**
   * Add secret for export-only mode (temporary storage)
   * These secrets are NOT stored permanently, only held for export
   * @param {Object} secret - TOTP secret configuration
   */
  addSecretForExport(secret) {
    console.log('📝 Adding secret for export-only mode (not storing permanently)');
    
    // Add to temporary export list
    this.exportedSecrets.push({
      ...secret,
      addedAt: new Date().toISOString()
    });
    
    console.log(`📤 Export queue now has ${this.exportedSecrets.length} secrets`);
  }

  /**
   * Get secrets in export-only mode
   * @returns {Array} Current export-only secrets
   */
  getExportOnlySecrets() {
    return [...this.exportedSecrets];
  }

  /**
   * Clear export-only secrets
   */
  clearExportOnlySecrets() {
    console.log('🗑️ Clearing export-only secrets queue');
    this.exportedSecrets = [];
  }

  /**
   * Check compatibility with different authenticator apps
   * @param {Object} secret - TOTP secret
   * @returns {Object} Compatibility information
   */
  checkCompatibility(secret) {
    const compatibility = {
      googleAuth: true, // Always compatible
      microsoftAuth: true,
      authy: false, // Authy doesn't support standard imports
      aegis: true,
      andOTP: true,
      lastpass: secret.algorithm === 'SHA1' && secret.digits === 6, // Limited support
      bitwarden: true
    };
    
    // Check specific limitations
    if (secret.algorithm !== 'SHA1') {
      compatibility.lastpass = false;
    }
    
    if (secret.digits !== 6) {
      compatibility.lastpass = false;
    }
    
    if (secret.period !== 30) {
      compatibility.lastpass = false;
      compatibility.microsoftAuth = false;
    }
    
    return {
      compatible: compatibility,
      warnings: this.getCompatibilityWarnings(secret, compatibility)
    };
  }

  /**
   * Get compatibility warnings for a secret
   * @param {Object} secret - TOTP secret
   * @param {Object} compatibility - Compatibility info
   * @returns {Array} Array of warning messages
   */
  getCompatibilityWarnings(secret, compatibility) {
    const warnings = [];
    
    if (secret.algorithm !== 'SHA1') {
      warnings.push('Non-SHA1 algorithms may not work with all authenticator apps');
    }
    
    if (secret.digits !== 6) {
      warnings.push('8-digit codes may not be supported by all apps');
    }
    
    if (secret.period !== 30) {
      warnings.push('Non-standard periods may not work with all apps');
    }
    
    const incompatibleApps = Object.entries(compatibility)
      .filter(([app, isCompatible]) => !isCompatible)
      .map(([app]) => app);
    
    if (incompatibleApps.length > 0) {
      warnings.push(`Not compatible with: ${incompatibleApps.join(', ')}`);
    }
    
    return warnings;
  }
}

// Export singleton instance
export const googleAuthManager = new GoogleAuthManager();