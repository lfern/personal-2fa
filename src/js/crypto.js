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
}

// Export singleton instance
export const cryptoManager = new SecureCrypto();