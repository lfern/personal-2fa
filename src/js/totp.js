/**
 * TOTP (Time-based One-Time Password) Generator
 * Implements RFC 6238 TOTP algorithm
 * Supports SHA1, SHA256, SHA512 algorithms
 */

export class TOTPGenerator {
  constructor() {
    this.defaultAlgorithm = 'SHA1';
    this.defaultDigits = 6;
    this.defaultPeriod = 30;
  }

  /**
   * Generate TOTP code from secret
   * @param {string} secret - Base32 encoded secret
   * @param {Object} options - TOTP configuration
   * @returns {Promise<Object>} TOTP code and timing info
   */
  async generateTOTP(secret, options = {}) {
    const {
      algorithm = this.defaultAlgorithm,
      digits = this.defaultDigits,
      period = this.defaultPeriod,
      timestamp = Date.now()
    } = options;

    // Calculate time counter
    const timeCounter = Math.floor(timestamp / 1000 / period);
    
    // Generate HOTP
    const code = await this.generateHOTP(secret, timeCounter, { algorithm, digits });
    
    // Calculate timing information
    const currentPeriodStart = timeCounter * period * 1000;
    const nextPeriodStart = currentPeriodStart + (period * 1000);
    const timeRemaining = Math.ceil((nextPeriodStart - timestamp) / 1000);
    const progress = ((timestamp - currentPeriodStart) / (period * 1000)) * 100;
    
    return {
      code,
      timeRemaining,
      progress,
      period,
      algorithm,
      digits
    };
  }

  /**
   * Generate HOTP code (RFC 4226)
   * @param {string} secret - Base32 encoded secret
   * @param {number} counter - Counter value
   * @param {Object} options - HOTP configuration
   * @returns {Promise<string>} HOTP code
   */
  async generateHOTP(secret, counter, options = {}) {
    const {
      algorithm = this.defaultAlgorithm,
      digits = this.defaultDigits
    } = options;

    // Decode Base32 secret to bytes
    const secretBytes = this.base32Decode(secret);
    
    // Convert counter to 8-byte big-endian format
    const counterBytes = new ArrayBuffer(8);
    const counterView = new DataView(counterBytes);
    counterView.setUint32(4, counter, false); // Big-endian
    
    // Import secret key for HMAC
    const key = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'HMAC', hash: `SHA-${this.getHashSize(algorithm)}` },
      false,
      ['sign']
    );
    
    // Generate HMAC
    const signature = await crypto.subtle.sign('HMAC', key, counterBytes);
    const hmac = new Uint8Array(signature);
    
    // Dynamic truncation (RFC 4226 Section 5.4)
    const offset = hmac[hmac.length - 1] & 0x0f;
    const truncated = (
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)
    ) >>> 0; // Unsigned 32-bit
    
    // Generate final code
    const code = (truncated % Math.pow(10, digits)).toString().padStart(digits, '0');
    
    return code;
  }

  /**
   * Validate TOTP code
   * @param {string} code - Code to validate
   * @param {string} secret - Base32 encoded secret
   * @param {Object} options - Validation options
   * @returns {Promise<boolean>} True if code is valid
   */
  async validateTOTP(code, secret, options = {}) {
    const {
      algorithm = this.defaultAlgorithm,
      digits = this.defaultDigits,
      period = this.defaultPeriod,
      window = 1, // Allow 1 period before/after current
      timestamp = Date.now()
    } = options;

    const currentCounter = Math.floor(timestamp / 1000 / period);
    
    // Check current period and adjacent periods (for clock drift)
    for (let i = -window; i <= window; i++) {
      const testCounter = currentCounter + i;
      const testCode = await this.generateHOTP(secret, testCounter, { algorithm, digits });
      
      if (code === testCode) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Parse otpauth:// URI
   * @param {string} uri - otpauth:// URI
   * @returns {Object} Parsed TOTP configuration
   */
  parseOTPAuthURI(uri) {
    try {
      const url = new URL(uri);
      
      if (url.protocol !== 'otpauth:') {
        throw new Error('Invalid protocol. Expected otpauth://');
      }
      
      const type = url.hostname.toLowerCase();
      if (type !== 'totp' && type !== 'hotp') {
        throw new Error('Unsupported OTP type. Expected totp or hotp');
      }
      
      // Parse label (issuer:account or just account)
      const label = decodeURIComponent(url.pathname.substring(1));
      let issuer = '';
      let account = label;
      
      const colonIndex = label.indexOf(':');
      if (colonIndex !== -1) {
        issuer = label.substring(0, colonIndex);
        account = label.substring(colonIndex + 1);
      }
      
      // Parse query parameters
      const params = new URLSearchParams(url.search);
      const secret = params.get('secret');
      const issuerParam = params.get('issuer');
      const algorithm = params.get('algorithm') || 'SHA1';
      const digits = parseInt(params.get('digits')) || 6;
      const period = parseInt(params.get('period')) || 30;
      const counter = params.get('counter');
      
      if (!secret) {
        throw new Error('Secret parameter is required');
      }
      
      // Validate Base32 secret
      if (!this.isValidBase32(secret)) {
        throw new Error('Invalid Base32 secret');
      }
      
      return {
        type,
        issuer: issuerParam || issuer,
        label: account,
        secret: secret.toUpperCase().replace(/\s/g, ''), // Normalize
        algorithm: algorithm.toUpperCase(),
        digits,
        period: type === 'totp' ? period : undefined,
        counter: type === 'hotp' ? parseInt(counter) || 0 : undefined
      };
    } catch (error) {
      throw new Error(`Invalid otpauth URI: ${error.message}`);
    }
  }

  /**
   * Generate otpauth:// URI
   * @param {Object} config - TOTP configuration
   * @returns {string} otpauth:// URI
   */
  generateOTPAuthURI(config) {
    const {
      issuer,
      label,
      secret,
      algorithm = 'SHA1',
      digits = 6,
      period = 30,
      type = 'totp'
    } = config;
    
    if (!secret || !label) {
      throw new Error('Secret and label are required');
    }
    
    // Construct label with issuer
    const fullLabel = issuer ? `${issuer}:${label}` : label;
    
    // Build URI
    const uri = new URL(`otpauth://${type}/${encodeURIComponent(fullLabel)}`);
    
    uri.searchParams.set('secret', secret.toUpperCase().replace(/\s/g, ''));
    
    if (issuer) {
      uri.searchParams.set('issuer', issuer);
    }
    
    if (algorithm !== 'SHA1') {
      uri.searchParams.set('algorithm', algorithm);
    }
    
    if (digits !== 6) {
      uri.searchParams.set('digits', digits.toString());
    }
    
    if (type === 'totp' && period !== 30) {
      uri.searchParams.set('period', period.toString());
    }
    
    return uri.toString();
  }

  /**
   * Decode Base32 string to bytes
   * @param {string} base32 - Base32 encoded string
   * @returns {Uint8Array} Decoded bytes
   */
  base32Decode(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleanInput = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
    
    let bits = '';
    for (const char of cleanInput) {
      const index = alphabet.indexOf(char);
      if (index === -1) {
        throw new Error(`Invalid Base32 character: ${char}`);
      }
      bits += index.toString(2).padStart(5, '0');
    }
    
    // Convert bits to bytes
    const bytes = [];
    for (let i = 0; i < bits.length - 4; i += 8) {
      const byte = bits.substring(i, i + 8);
      if (byte.length === 8) {
        bytes.push(parseInt(byte, 2));
      }
    }
    
    return new Uint8Array(bytes);
  }

  /**
   * Encode bytes to Base32 string
   * @param {Uint8Array} bytes - Bytes to encode
   * @returns {string} Base32 encoded string
   */
  base32Encode(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    
    // Convert bytes to bits
    for (const byte of bytes) {
      bits += byte.toString(2).padStart(8, '0');
    }
    
    // Pad to multiple of 5 bits
    while (bits.length % 5 !== 0) {
      bits += '0';
    }
    
    // Convert to Base32
    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.substring(i, i + 5);
      result += alphabet[parseInt(chunk, 2)];
    }
    
    return result;
  }

  /**
   * Validate Base32 string
   * @param {string} base32 - Base32 string to validate
   * @returns {boolean} True if valid Base32
   */
  isValidBase32(base32) {
    const cleanInput = base32.toUpperCase().replace(/\s/g, '');
    return /^[A-Z2-7]*$/.test(cleanInput);
  }

  /**
   * Get hash size for algorithm
   * @param {string} algorithm - Hash algorithm
   * @returns {number} Hash size
   */
  getHashSize(algorithm) {
    switch (algorithm.toUpperCase()) {
      case 'SHA1': return 1;
      case 'SHA256': return 256;
      case 'SHA512': return 512;
      default: throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * Generate random Base32 secret
   * @param {number} length - Length in bytes (default: 20 for 160-bit)
   * @returns {string} Base32 encoded secret
   */
  generateSecret(length = 20) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return this.base32Encode(bytes);
  }
}

// Export singleton instance
export const totpGenerator = new TOTPGenerator();