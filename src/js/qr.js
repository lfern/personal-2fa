/**
 * QR Code Scanner and Generator Module
 * Handles QR code scanning via camera and generation for export
 * Supports Google Authenticator migration format
 */

// Import QR generation library
import QRCode from 'qrcode';
import logger from './logger.js';

export class QRManager {
  constructor() {
    this.video = null;
    this.canvas = null;
    this.context = null;
    this.scanning = false;
    this.onQRDetected = null;
    this.scanInterval = null;
  }

  /**
   * Initialize QR scanner with video element
   * @param {HTMLVideoElement} videoElement - Video element for camera stream
   * @param {HTMLCanvasElement} canvasElement - Canvas for image processing
   */
  init(videoElement, canvasElement) {
    this.video = videoElement;
    this.canvas = canvasElement;
    this.context = canvasElement.getContext('2d');
  }

  /**
   * Start camera and begin QR code scanning
   * @param {Function} onDetected - Callback function when QR is detected
   * @returns {Promise<void>}
   */
  async startScanning(onDetected) {
    try {
      this.onQRDetected = onDetected;
      
      // Request camera access
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 640 },
          height: { ideal: 480 },
          facingMode: 'environment' // Use back camera on mobile
        }
      });
      
      this.video.srcObject = stream;
      this.video.play();
      
      // Wait for video to be ready
      await new Promise((resolve) => {
        this.video.onloadedmetadata = () => {
          // Set canvas size to match video
          this.canvas.width = this.video.videoWidth;
          this.canvas.height = this.video.videoHeight;
          resolve();
        };
      });
      
      this.scanning = true;
      this.startQRDetection();
      
    } catch (error) {
      throw new Error(`Failed to start camera: ${error.message}`);
    }
  }

  /**
   * Stop camera and QR scanning
   */
  stopScanning() {
    this.scanning = false;
    
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
    
    if (this.video && this.video.srcObject) {
      const tracks = this.video.srcObject.getTracks();
      tracks.forEach(track => track.stop());
      this.video.srcObject = null;
    }
  }

  /**
   * Start continuous QR detection from video stream
   */
  startQRDetection() {
    this.scanInterval = setInterval(() => {
      if (!this.scanning || !this.video || this.video.readyState !== 4) {
        return;
      }
      
      // Capture frame from video
      this.context.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
      
      // Get image data for QR detection
      const imageData = this.context.getImageData(0, 0, this.canvas.width, this.canvas.height);
      
      try {
        const qrData = this.detectQRCode(imageData);
        if (qrData && this.onQRDetected) {
          this.onQRDetected(qrData);
        }
      } catch (error) {
        // QR detection failed, continue scanning
      }
    }, 250); // Scan every 250ms
  }

  /**
   * Detect QR code in image data (basic implementation)
   * In a real implementation, you would use a library like jsQR or zxing
   * @param {ImageData} imageData - Image data from canvas
   * @returns {string|null} QR code data or null if not found
   */
  detectQRCode(imageData) {
    try {
      // Import jsQR dynamically
      if (!window.jsQR) {
        logger.log('📱 Loading jsQR library...');
        // For now, return null if jsQR is not loaded
        // This will be handled by the camera detection loop
        return null;
      }
      
      logger.log('📱 Scanning for QR code...');
      const code = window.jsQR(imageData.data, imageData.width, imageData.height);
      
      if (code) {
        logger.log('📱 QR Code detected:', code.data);
        return code.data;
      }
      
      return null;
    } catch (error) {
      logger.error('📱 QR detection error:', error);
      return null;
    }
  }

  /**
   * Mock QR detection for development
   * Replace this with actual QR detection library
   * @returns {string|null} Mock QR data
   */
  mockQRDetection() {
    // Mock QR detection disabled - using real jsQR library now
    if (false) { // Completely disabled
      // Create a realistic mock migration payload
      const mockSecret = {
        secret: 'JBSWY3DPEHPK3PXP',
        name: 'test@example.com',
        issuer: 'Google',
        algorithm: 1, // SHA1
        digits: 6,
        type: 2 // TOTP
      };
      
      // Create a simple protobuf-like structure
      const secretBytes = this.base32ToBytes(mockSecret.secret);
      const nameBytes = new TextEncoder().encode(mockSecret.name);
      const issuerBytes = new TextEncoder().encode(mockSecret.issuer);
      
      // Simple protobuf encoding (field 1)
      let payload = new Uint8Array([
        0x0A, // Field 1, wire type 2 (length-delimited)
        30 + secretBytes.length + nameBytes.length + issuerBytes.length, // Length
        
        // Secret (field 1)
        0x0A, secretBytes.length, ...secretBytes,
        
        // Name (field 2) 
        0x12, nameBytes.length, ...nameBytes,
        
        // Issuer (field 3)
        0x1A, issuerBytes.length, ...issuerBytes,
        
        // Algorithm (field 4)
        0x20, mockSecret.algorithm,
        
        // Digits (field 5)
        0x28, mockSecret.digits,
        
        // Type (field 6)
        0x30, mockSecret.type
      ]);
      
      // Convert to string for base64 encoding
      const payloadString = String.fromCharCode.apply(null, payload);
      const base64Data = btoa(payloadString);
      
      return `otpauth-migration://offline?data=${base64Data}`;
    }
    return null;
  }

  /**
   * Convert Base32 to bytes (helper for mock)
   * @param {string} base32 - Base32 string
   * @returns {Uint8Array} Decoded bytes
   */
  base32ToBytes(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    
    for (const char of base32.toUpperCase()) {
      const index = alphabet.indexOf(char);
      if (index !== -1) {
        bits += index.toString(2).padStart(5, '0');
      }
    }
    
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
   * Generate QR code for otpauth:// URI
   * @param {string} otpauthUri - otpauth:// URI
   * @param {Object} options - QR generation options
   * @returns {Promise<string>} Data URL of QR code image
   */
  async generateQRCode(otpauthUri, options = {}) {
    const {
      errorCorrectionLevel = 'M',
      type = 'image/png',
      quality = 0.92,
      margin = 1,
      color = {
        dark: '#000000',
        light: '#FFFFFF'
      },
      width = 256
    } = options;

    try {
      const qrDataUrl = await QRCode.toDataURL(otpauthUri, {
        errorCorrectionLevel,
        type,
        quality,
        margin,
        color,
        width
      });
      
      return qrDataUrl;
    } catch (error) {
      throw new Error(`Failed to generate QR code: ${error.message}`);
    }
  }

  /**
   * Generate QR code for Google Authenticator migration
   * @param {Array} totpSecrets - Array of TOTP configurations
   * @returns {Promise<string>} Data URL of migration QR code
   */
  async generateMigrationQR(totpSecrets) {
    try {
      // Create migration payload (simplified version)
      const migrationData = this.createMigrationPayload(totpSecrets);
      
      // Encode to Base64
      const base64Data = btoa(migrationData);
      
      // Create migration URI
      const migrationUri = `otpauth-migration://offline?data=${base64Data}`;
      
      // Generate QR code
      return await this.generateQRCode(migrationUri, {
        errorCorrectionLevel: 'L', // Lower correction for larger data
        width: 400 // Larger size for migration QR
      });
    } catch (error) {
      throw new Error(`Failed to generate migration QR: ${error.message}`);
    }
  }

  /**
   * Create Google Authenticator migration payload
   * @param {Array} totpSecrets - Array of TOTP configurations
   * @returns {string} Binary migration data
   */
  createMigrationPayload(totpSecrets) {
    logger.log('📤 Creating migration payload for', totpSecrets.length, 'secrets');
    
    // Create proper protobuf payload compatible with Google Authenticator
    const payloadBytes = [];
    
    for (const secret of totpSecrets) {
      logger.log('📤 Processing secret:', secret.issuer, secret.label);
      
      // Convert secret from Base32 to bytes
      const secretBytes = this.base32ToBytes(secret.secret);
      
      // Encode strings to UTF-8 bytes
      const nameBytes = new TextEncoder().encode(secret.label);
      const issuerBytes = new TextEncoder().encode(secret.issuer || '');
      
      // Convert digits to Google format: 6→1, 8→2
      let digitsValue;
      if (secret.digits === 8) {
        digitsValue = 2;
      } else {
        digitsValue = 1; // Default to 6 digits
      }
      
      const algorithmValue = this.algorithmToNumber(secret.algorithm);
      
      // Create OtpParameters message (Field 1)
      const otpParams = [];
      
      // Field 1: secret (wire type 2 - length-delimited)
      otpParams.push(0x0A, secretBytes.length, ...secretBytes);
      
      // Field 2: name/label (wire type 2 - length-delimited)
      otpParams.push(0x12, nameBytes.length, ...nameBytes);
      
      // Field 3: issuer (wire type 2 - length-delimited)
      if (issuerBytes.length > 0) {
        otpParams.push(0x1A, issuerBytes.length, ...issuerBytes);
      }
      
      // Field 4: algorithm (wire type 0 - varint)
      otpParams.push(0x20, algorithmValue);
      
      // Field 5: digits (wire type 0 - varint)
      otpParams.push(0x28, digitsValue);
      
      // Field 6: type (wire type 0 - varint) - 2 for TOTP
      otpParams.push(0x30, 2);
      
      // Add this OtpParameters as Field 1 of main message
      payloadBytes.push(0x0A, otpParams.length, ...otpParams);
      
      logger.log('📤 Encoded secret with digits:', secret.digits, '→', digitsValue);
    }
    
    // Add version field (Field 2) - value 1
    payloadBytes.push(0x10, 1);
    
    // Add batch size (Field 3)
    payloadBytes.push(0x18, totpSecrets.length);
    
    // Add batch index (Field 4) - value 0 for single batch
    payloadBytes.push(0x20, 0);
    
    // Convert to string for Base64 encoding
    const payloadString = String.fromCharCode.apply(null, payloadBytes);
    
    logger.log('📤 Generated migration payload:', payloadBytes.length, 'bytes');
    return payloadString;
  }

  /**
   * Parse Google Authenticator migration QR data
   * @param {string} migrationUri - Migration URI from QR code
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationQR(migrationUri) {
    try {
      logger.log('📱 Parsing migration QR URI:', migrationUri);
      
      const url = new URL(migrationUri);
      logger.log('🔗 URL protocol:', url.protocol);
      
      if (url.protocol !== 'otpauth-migration:') {
        throw new Error('Invalid migration URI protocol');
      }
      
      const dataParam = url.searchParams.get('data');
      logger.log('📊 Data parameter length:', dataParam ? dataParam.length : 'null');
      logger.log('📊 Data parameter (first 100 chars):', dataParam ? dataParam.substring(0, 100) : 'null');
      
      if (!dataParam) {
        throw new Error('Missing data parameter in migration URI');
      }
      
      // Decode Base64 data
      const decodedData = atob(dataParam);
      logger.log('🔓 Decoded data length:', decodedData.length);
      logger.log('🔓 Decoded data (ALL bytes as hex):', 
        Array.from(decodedData).map(b => b.toString(16).padStart(2, '0')).join(' '));
      logger.log('🔓 Data parameter was:', dataParam);
      
      // Parse migration data (simplified - would use protobuf in production)
      return this.parseMigrationData(decodedData);
    } catch (error) {
      logger.error('❌ Migration QR parsing failed:', error);
      throw new Error(`Failed to parse migration QR: ${error.message}`);
    }
  }

  /**
   * Read a varint from bytes array
   * @param {Uint8Array} bytes - Bytes array
   * @param {number} offset - Starting offset
   * @returns {Object} {value, newOffset}
   */
  readVarint(bytes, offset) {
    let value = 0;
    let shift = 0;
    let currentOffset = offset;
    
    while (currentOffset < bytes.length) {
      const byte = bytes[currentOffset++];
      value |= (byte & 0x7F) << shift;
      
      if ((byte & 0x80) === 0) {
        return { value, newOffset: currentOffset };
      }
      
      shift += 7;
      if (shift >= 32) {
        throw new Error('Varint too long');
      }
    }
    
    throw new Error('Incomplete varint');
  }

  /**
   * Parse migration data payload
   * @param {string} data - Decoded migration data
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationData(data) {
    try {
      logger.log('🔍 Parsing migration data, length:', data.length);
      
      // Simple protobuf-like parsing for Google Authenticator format
      // This is a basic implementation that handles the most common case
      
      const secrets = [];
      const bytes = new Uint8Array([...data].map(char => char.charCodeAt(0)));
      
      logger.log('🔍 Bytes array length:', bytes.length);
      logger.log('🔍 ALL bytes:', Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' '));
      
      // Analyze protobuf structure
      logger.log('🔍 Analyzing structure:');
      for (let j = 0; j < Math.min(bytes.length, 10); j++) {
        const byte = bytes[j];
        if ((byte & 0x7) === 2) { // Wire type 2 (length-delimited)
          const field = byte >> 3;
          logger.log(`  Position ${j}: Field ${field}, wire type 2 (length-delimited)`);
        }
      }
      
      // Google Authenticator Migration format parsing
      let i = 0;
      
      while (i < bytes.length) {
        const tag = bytes[i++];
        const field = tag >> 3;
        const wireType = tag & 0x07;
        
        logger.log(`🔍 Processing field ${field}, wire type ${wireType} at position ${i-1}`);
        
        if (field === 1 && wireType === 2) { // Field 1 (OtpParameters)
          // Read length
          let length;
          if (bytes[i] < 0x80) {
            length = bytes[i++];
          } else {
            const lengthResult = this.readVarint(bytes, i);
            length = lengthResult.value;
            i = lengthResult.newOffset;
          }
          
          logger.log(`🔍 OtpParameters length: ${length}, remaining bytes: ${bytes.length - i}`);
          logger.log(`🔍 Available bytes for OtpParameters: ${Math.min(length, bytes.length - i)}`);
          
          // Use all available bytes, even if less than declared length
          const actualLength = Math.min(length, bytes.length - i);
          
          if (actualLength > 0) {
            const otpData = bytes.slice(i, i + actualLength);
            logger.log(`🔍 OtpParameters data (${actualLength} bytes):`, Array.from(otpData).map(b => b.toString(16).padStart(2, '0')).join(' '));
            
            const secret = this.parseOtpParameters(otpData);
            logger.log(`🔍 Parsed OtpParameters result:`, secret);
            
            if (secret && secret.secret && secret.label) {
              secrets.push(secret);
              logger.log(`✅ Successfully parsed secret: ${secret.issuer}:${secret.label}`);
            } else {
              logger.log(`❌ Failed to parse valid OtpParameters - missing secret or label`);
            }
            
            i += actualLength;
          } else {
            logger.log(`❌ No bytes available for OtpParameters`);
            break;
          }
        } else {
          // Skip unknown or other fields
          logger.log(`🔍 Skipping field ${field}, wire type ${wireType}`);
          if (wireType === 0) {
            // Varint - skip
            while (i < bytes.length && bytes[i] >= 0x80) {
              i++;
            }
            if (i < bytes.length) i++; // Final byte
          } else if (wireType === 2) {
            // Length-delimited - skip
            const length = bytes[i++];
            i += length;
          } else {
            i++; // Skip other wire types
          }
        }
      }
      
      logger.log(`🔍 Successfully parsed ${secrets.length} secrets from migration data`);
      
      // If no secrets found, try fallback parsing
      if (secrets.length === 0) {
        logger.log('🔄 No secrets found, trying fallback parsing...');
        return this.parseMigrationDataFallback(data);
      }
      
      return secrets;
    } catch (error) {
      logger.warn('❌ Migration parsing failed, trying fallback:', error);
      return this.parseMigrationDataFallback(data);
    }
  }

  /**
   * Parse OTP parameters from protobuf data
   * @param {Uint8Array} data - OTP parameters data
   * @returns {Object|null} Parsed TOTP configuration
   */
  parseOtpParameters(data) {
    try {
      logger.log('🔧 Parsing OTP parameters, data length:', data.length);
      logger.log('🔧 OTP data (hex):', Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' '));
      
      const params = {
        secret: '',
        label: '',
        issuer: '',
        algorithm: 'SHA1',
        digits: 6,
        period: 30
      };
      
      let i = 0;
      while (i < data.length) {
        const tag = data[i++];
        const field = tag >> 3;
        const wireType = tag & 0x07;
        
        logger.log(`🔧 Field ${field}, wireType ${wireType} at position ${i-1}`);
        
        switch (field) {
          case 1: // secret
            if (wireType === 2) { // Length-delimited
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              logger.log(`🔧 Secret length (varint): ${length}`);
              if (i + length <= data.length) {
                // Convert bytes to Base32
                const secretBytes = data.slice(i, i + length);
                logger.log('🔧 Secret bytes:', Array.from(secretBytes).map(b => b.toString(16).padStart(2, '0')).join(' '));
                params.secret = this.bytesToBase32(secretBytes);
                logger.log('🔧 Converted secret:', params.secret);
                i += length;
              }
            }
            break;
          case 2: // name/label
            if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              logger.log(`🔧 Label length (varint): ${length}`);
              if (i + length <= data.length) {
                params.label = new TextDecoder().decode(data.slice(i, i + length));
                logger.log('🔧 Label:', params.label);
                i += length;
              }
            }
            break;
          case 3: // issuer
            if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              logger.log(`🔧 Issuer length (varint): ${length}`);
              if (i + length <= data.length) {
                params.issuer = new TextDecoder().decode(data.slice(i, i + length));
                logger.log('🔧 Issuer:', params.issuer);
                i += length;
              }
            }
            break;
          case 4: // algorithm
            if (wireType === 0) { // Varint
              const algorithmResult = this.readVarint(data, i);
              const algorithm = algorithmResult.value;
              i = algorithmResult.newOffset;
              params.algorithm = this.numberToAlgorithm(algorithm);
              logger.log('🔧 Algorithm (varint):', algorithm, '→', params.algorithm);
            }
            break;
          case 5: // digits
            if (wireType === 0) { // Varint
              logger.log('🔧 PARSING DIGITS - Position before:', i, 'Byte at position:', data[i].toString(16));
              const digitsResult = this.readVarint(data, i);
              const rawDigitsValue = digitsResult.value;
              
              // Google Authenticator digits encoding:
              // 0 or 1 = 6 digits, 2 = 8 digits
              if (rawDigitsValue <= 1) {
                params.digits = 6;
              } else if (rawDigitsValue === 2) {
                params.digits = 8;
              } else {
                params.digits = 6; // Default fallback
              }
              
              i = digitsResult.newOffset;
              logger.log('🔧 DIGITS RESULT - Raw value:', rawDigitsValue, '→ Interpreted as:', params.digits, 'digits');
              logger.log('🔧 Position after digits:', i);
            } else {
              logger.log('🔧 DIGITS FIELD - Wrong wire type:', wireType, 'expected 0');
            }
            break;
          default:
            // Skip unknown fields
            logger.log(`🔧 Skipping unknown field ${field}, wire type ${wireType}`);
            if (wireType === 0) {
              // Skip varint properly
              const skipResult = this.readVarint(data, i);
              i = skipResult.newOffset;
            } else if (wireType === 2) {
              // Skip length-delimited properly
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset + length;
            } else {
              i++; // Skip other wire types
            }
        }
      }
      
      logger.log('🔧 === FINAL PARSED PARAMS ===');
      logger.log('🔧 Secret:', params.secret);
      logger.log('🔧 Label:', params.label); 
      logger.log('🔧 Issuer:', params.issuer);
      logger.log('🔧 Algorithm:', params.algorithm);
      logger.log('🔧 Digits:', params.digits, typeof params.digits);
      logger.log('🔧 Period:', params.period);
      
      const result = params.secret && params.label ? params : null;
      logger.log('🔧 Returning result:', result);
      return result;
    } catch (error) {
      logger.error('🔧 Error parsing OTP parameters:', error);
      return null;
    }
  }

  /**
   * Fallback parser for migration data
   * @param {string} data - Migration data
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationDataFallback(data) {
    logger.log('🔄 Using fallback parser for migration data');
    
    // Extract readable strings from the binary data
    const strings = data.match(/[a-zA-Z0-9@._-]{3,}/g) || [];
    logger.log('🔄 Extracted strings:', strings);
    
    // Try to identify patterns
    const secrets = [];
    let currentSecret = null;
    
    for (const str of strings) {
      // Check if it looks like a Base32 secret (only uppercase letters and digits 2-7)
      if (/^[A-Z2-7]{16,}$/.test(str) && str.length >= 16) {
        if (currentSecret) {
          secrets.push(currentSecret);
        }
        currentSecret = {
          secret: str,
          label: '',
          issuer: '',
          algorithm: 'SHA1',
          digits: 6,
          period: 30
        };
      }
      // Check if it looks like an email or account name
      else if (str.includes('@') || str.includes('.')) {
        if (currentSecret && !currentSecret.label) {
          currentSecret.label = str;
        }
      }
      // Check if it looks like a service name
      else if (str.length > 2 && str.length < 20 && /^[A-Za-z]/.test(str)) {
        if (currentSecret && !currentSecret.issuer) {
          currentSecret.issuer = str;
        }
      }
    }
    
    if (currentSecret) {
      secrets.push(currentSecret);
    }
    
    return secrets.filter(s => s.secret && (s.label || s.issuer));
  }

  /**
   * Convert bytes to Base32 (for secret encoding)
   * @param {Uint8Array} bytes - Bytes to encode
   * @returns {string} Base32 string
   */
  bytesToBase32(bytes) {
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
   * Convert algorithm name to number (Google's format)
   * @param {string} algorithm - Algorithm name
   * @returns {number} Algorithm number
   */
  algorithmToNumber(algorithm) {
    switch (algorithm?.toUpperCase()) {
      case 'SHA1': return 1;
      case 'SHA256': return 2;
      case 'SHA512': return 3;
      default: return 1; // Default to SHA1
    }
  }

  /**
   * Convert algorithm number to name (Google's format)
   * @param {number} algorithmNumber - Algorithm number
   * @returns {string} Algorithm name
   */
  numberToAlgorithm(algorithmNumber) {
    switch (algorithmNumber) {
      case 1: return 'SHA1';
      case 2: return 'SHA256';
      case 3: return 'SHA512';
      default: return 'SHA1';
    }
  }

  /**
   * Check if camera is available
   * @returns {Promise<boolean>} True if camera is available
   */
  async isCameraAvailable() {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.some(device => device.kind === 'videoinput');
    } catch (error) {
      return false;
    }
  }

  /**
   * Check camera permissions
   * @returns {Promise<string>} Permission state
   */
  async checkCameraPermission() {
    try {
      const permission = await navigator.permissions.query({ name: 'camera' });
      return permission.state; // 'granted', 'denied', 'prompt'
    } catch (error) {
      return 'unknown';
    }
  }
}

// Export singleton instance
export const qrManager = new QRManager();