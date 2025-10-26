/**
 * Secure Cryptography Module
 * Uses Web Crypto API for hardware-accelerated AES-256-GCM encryption
 * All sensitive data is encrypted before storage
 */

export class SecureCrypto {
  constructor() {
    this.algorithm = 'AES-GCM';
    this.keyLength = 256;
    this.ivLength = 12; // 96 bits for GCM
    this.tagLength = 128; // 128 bits authentication tag
    this.iterations = 100000; // PBKDF2 iterations
  }

  /**
   * Derive encryption key from password using PBKDF2
   * @param {string} password - Master password
   * @param {Uint8Array} salt - Random salt
   * @returns {Promise<CryptoKey>} Derived key
   */
  async deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Import password as base key
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    // Derive AES key using PBKDF2
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.iterations,
        hash: 'SHA-256'
      },
      baseKey,
      {
        name: this.algorithm,
        length: this.keyLength
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generate cryptographically secure random bytes
   * @param {number} length - Number of bytes
   * @returns {Uint8Array} Random bytes
   */
  generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param {string} plaintext - Data to encrypt
   * @param {CryptoKey} key - Encryption key
   * @returns {Promise<Object>} Encrypted data with IV
   */
  async encrypt(plaintext, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Generate random IV for each encryption
    const iv = this.generateRandomBytes(this.ivLength);
    
    // Encrypt data
    const encrypted = await crypto.subtle.encrypt(
      {
        name: this.algorithm,
        iv: iv,
        tagLength: this.tagLength
      },
      key,
      data
    );
    
    return {
      ciphertext: new Uint8Array(encrypted),
      iv: iv
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {Uint8Array} ciphertext - Encrypted data
   * @param {Uint8Array} iv - Initialization vector
   * @param {CryptoKey} key - Decryption key
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decrypt(ciphertext, iv, key) {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: this.algorithm,
        iv: iv,
        tagLength: this.tagLength
      },
      key,
      ciphertext
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Hash data using SHA-256
   * @param {string} data - Data to hash
   * @returns {Promise<string>} Hex-encoded hash
   */
  async hash(data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Convert Uint8Array to Base64 string
   * @param {Uint8Array} bytes - Byte array
   * @returns {string} Base64 string
   */
  bytesToBase64(bytes) {
    const binary = String.fromCharCode.apply(null, bytes);
    return btoa(binary);
  }

  /**
   * Convert Base64 string to Uint8Array
   * @param {string} base64 - Base64 string
   * @returns {Uint8Array} Byte array
   */
  base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Securely clear sensitive data from memory
   * @param {string|Uint8Array|Array} sensitiveData - Data to clear
   */
  secureClear(sensitiveData) {
    if (typeof sensitiveData === 'string') {
      // Can't directly clear string in JS, but can overwrite reference
      sensitiveData = null;
    } else if (sensitiveData instanceof Uint8Array || Array.isArray(sensitiveData)) {
      // Overwrite array contents with random data
      crypto.getRandomValues(sensitiveData);
    }
  }

  /**
   * Verify that Web Crypto API is available and secure
   * @returns {Object} Security status
   */
  getSecurityStatus() {
    const status = {
      webCryptoAvailable: !!window.crypto?.subtle,
      secureContext: window.isSecureContext,
      httpsOrLocalhost: window.location.protocol === 'https:' || 
                       window.location.hostname === 'localhost' ||
                       window.location.hostname === '127.0.0.1',
      randomAvailable: !!window.crypto?.getRandomValues
    };
    
    status.isSecure = status.webCryptoAvailable && 
                     status.secureContext && 
                     status.randomAvailable;
    
    return status;
  }

  /**
   * Get current master password (for export purposes)
   * Note: This is a simplified version - in real implementation 
   * you'd want to securely retrieve this
   */
  getMasterPassword() {
    // Return the current session password if available
    return this.currentMasterPassword || null;
  }

  /**
   * Set master password for session (called during authentication)
   */
  setMasterPassword(password) {
    this.currentMasterPassword = password;
  }

  /**
   * Encrypt data for export (OpenSSL AES-256-CBC compatible)
   * @param {string} plaintext - Data to encrypt
   * @param {string} password - Encryption password
   * @returns {Promise<ArrayBuffer>} Encrypted data in OpenSSL format
   */
  async encryptForExport(plaintext, password) {
    // Generate random salt (8 bytes)
    const salt = this.generateRandomBytes(8);
    
    // Derive key and IV using OpenSSL's EVP_BytesToKey equivalent
    const keyIv = await this.deriveKeyIvOpenSSL(password, salt);
    
    // Create cipher using AES-256-CBC
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Pad data to 16-byte boundary (PKCS#7 padding)
    const paddedData = this.addPKCS7Padding(data, 16);
    
    // Import key for AES-CBC
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyIv.key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );
    
    // Encrypt data
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: keyIv.iv
      },
      cryptoKey,
      paddedData
    );
    
    // Create OpenSSL format: "Salted__" + salt + encrypted_data
    const salted = new TextEncoder().encode('Salted__');
    const result = new Uint8Array(salted.length + salt.length + encrypted.byteLength);
    result.set(salted, 0);
    result.set(salt, salted.length);
    result.set(new Uint8Array(encrypted), salted.length + salt.length);
    
    return result.buffer;
  }

  /**
   * Decrypt data from import (OpenSSL AES-256-CBC compatible)
   * @param {ArrayBuffer} encryptedData - Encrypted data
   * @param {string} password - Decryption password
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decryptFromImport(encryptedData, password) {
    const data = new Uint8Array(encryptedData);
    
    // Check for OpenSSL "Salted__" header
    const salted = new TextEncoder().encode('Salted__');
    const header = data.slice(0, 8);
    
    if (!this.arraysEqual(header, salted)) {
      throw new Error('Invalid file format - not OpenSSL encrypted');
    }
    
    // Extract salt and encrypted data
    const salt = data.slice(8, 16);
    const ciphertext = data.slice(16);
    
    // Derive key and IV using OpenSSL's EVP_BytesToKey equivalent
    const keyIv = await this.deriveKeyIvOpenSSL(password, salt);
    
    // Import key for AES-CBC
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyIv.key,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );
    
    // Decrypt data
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: keyIv.iv
      },
      cryptoKey,
      ciphertext
    );
    
    // Remove PKCS#7 padding
    const unpaddedData = this.removePKCS7Padding(new Uint8Array(decrypted));
    
    // Convert to string
    const decoder = new TextDecoder();
    return decoder.decode(unpaddedData);
  }

  /**
   * Derive key and IV using OpenSSL's EVP_BytesToKey method
   * Compatible with: openssl enc -aes-256-cbc -pbkdf2 -iter 1
   */
  async deriveKeyIvOpenSSL(password, salt) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    // Concatenate password and salt
    const combined = new Uint8Array(passwordBytes.length + salt.length);
    combined.set(passwordBytes, 0);
    combined.set(salt, passwordBytes.length);
    
    // Hash to get first 32 bytes (key) + 16 bytes (IV)
    let hash = await crypto.subtle.digest('SHA-256', combined);
    let hashBytes = new Uint8Array(hash);
    
    // We need 32 bytes for key + 16 bytes for IV = 48 bytes total
    // SHA-256 gives us 32 bytes, so we need to hash again
    const secondInput = new Uint8Array(hashBytes.length + passwordBytes.length + salt.length);
    secondInput.set(hashBytes, 0);
    secondInput.set(passwordBytes, hashBytes.length);
    secondInput.set(salt, hashBytes.length + passwordBytes.length);
    
    const secondHash = await crypto.subtle.digest('SHA-256', secondInput);
    const secondHashBytes = new Uint8Array(secondHash);
    
    // Combine hashes to get 64 bytes total
    const keyIvBytes = new Uint8Array(48);
    keyIvBytes.set(hashBytes.slice(0, 32), 0); // 32 bytes for key
    keyIvBytes.set(secondHashBytes.slice(0, 16), 32); // 16 bytes for IV
    
    return {
      key: keyIvBytes.slice(0, 32),
      iv: keyIvBytes.slice(32, 48)
    };
  }

  /**
   * Add PKCS#7 padding
   */
  addPKCS7Padding(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const paddedData = new Uint8Array(data.length + padding);
    paddedData.set(data, 0);
    for (let i = data.length; i < paddedData.length; i++) {
      paddedData[i] = padding;
    }
    return paddedData;
  }

  /**
   * Remove PKCS#7 padding
   */
  removePKCS7Padding(data) {
    const padding = data[data.length - 1];
    return data.slice(0, data.length - padding);
  }

  /**
   * Check if two arrays are equal
   */
  arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

// Export singleton instance
export const cryptoManager = new SecureCrypto();