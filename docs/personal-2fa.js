
/* ====================================
   Personal 2FA - Secure Local 2FA App
   Generated: 2025-10-26T11:20:32.595Z
   
   Security Features:
   - AES-256-GCM encryption
   - PBKDF2 key derivation
   - IndexedDB local storage
   - Web Crypto API
   - Offline operation
   ==================================== */


/* ============= logger.js ============= */
(function() {
  'use strict';
  
/**
 * Personal 2FA - Logger Configuration
 * Centralized logging system with configurable output
 */

class Logger {
  constructor() {
    // Default to disabled logs for end users, but check localStorage for user preference
    // Developers can enable logs via the UI toggle in Data Management section
    this.logsEnabled = this.getLogPreference();
  }

  /**
   * Get log preference from localStorage
   * @returns {boolean}
   */
  getLogPreference() {
    try {
      const saved = localStorage.getItem('personal-2fa-logs-enabled');
      // Default to false (logs disabled for end users)
      return saved !== null ? JSON.parse(saved) : false;
    } catch (error) {
      // If localStorage fails, default to false
      return false;
    }
  }

  /**
   * Set log preference and save to localStorage
   * @param {boolean} enabled
   */
  setLogPreference(enabled) {
    this.logsEnabled = enabled;
    try {
      localStorage.setItem('personal-2fa-logs-enabled', JSON.stringify(enabled));
    } catch (error) {
      // If localStorage fails, just continue
      console.warn('Failed to save log preference:', error);
    }
  }

  /**
   * Check if logs are enabled
   * @returns {boolean}
   */
  isEnabled() {
    return this.logsEnabled;
  }

  /**
   * Log information message
   * @param {...any} args
   */
  log(...args) {
    if (this.logsEnabled) {
      console.log(...args);
    }
  }

  /**
   * Log error message (always shown, even when logs disabled)
   * @param {...any} args
   */
  error(...args) {
    // Errors should always be shown for debugging
    console.error(...args);
  }

  /**
   * Log warning message
   * @param {...any} args
   */
  warn(...args) {
    if (this.logsEnabled) {
      console.warn(...args);
    }
  }

  /**
   * Log info message (same as log, but semantically different)
   * @param {...any} args
   */
  info(...args) {
    if (this.logsEnabled) {
      console.info(...args);
    }
  }

  /**
   * Log debug message
   * @param {...any} args
   */
  debug(...args) {
    if (this.logsEnabled) {
      console.debug(...args);
    }
  }

  /**
   * Group logs together
   * @param {string} label
   */
  group(label) {
    if (this.logsEnabled) {
      console.group(label);
    }
  }

  /**
   * End log group
   */
  groupEnd() {
    if (this.logsEnabled) {
      console.groupEnd();
    }
  }
}

// Create global logger instance
const logger = new Logger();

// Export for use in other modules
export default logger;

})();


/* ============= notification.js ============= */
(function() {
  'use strict';
  
class NotificationSystem {
    constructor() {
        this.container = document.getElementById('notification-container');
        if (!this.container) {
            logger.log('⚠️ Warning: Notification container not found in DOM');
        }
    }

    /**
     * Show a notification message
     * @param {string} message - The message to display
     * @param {string} type - The type of notification ('info', 'success', 'warning', 'error', 'progress')
     * @param {number} duration - Duration in milliseconds (0 for persistent)
     * @returns {string} - The notification ID for future reference
     */
    showNotification(message, type = 'info', duration = 3000) {
        const notificationId = `notification-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        const notification = document.createElement('div');
        notification.id = notificationId;
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-icon">${this.getIcon(type)}</span>
                <span class="notification-message">${message}</span>
                ${type !== 'progress' ? '<button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>' : ''}
            </div>
            ${type === 'progress' ? '<div class="progress-bar"><div class="progress-fill"></div></div>' : ''}
        `;

        // Add to container
        if (this.container) {
            this.container.appendChild(notification);
        } else {
            // Fallback: append to body
            document.body.appendChild(notification);
        }

        // Animate in
        requestAnimationFrame(() => {
            notification.classList.add('notification-show');
        });

        // Auto-remove if duration is set
        if (duration > 0 && type !== 'progress') {
            setTimeout(() => {
                this.removeNotification(notificationId);
            }, duration);
        }

        logger.log(`📢 Notification shown: ${type} - ${message}`);
        return notificationId;
    }

    /**
     * Remove a notification by ID
     * @param {string} notificationId - The notification ID to remove
     */
    removeNotification(notificationId) {
        const notification = document.getElementById(notificationId);
        if (notification) {
            notification.classList.add('notification-hide');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300); // Match CSS transition duration
            
            logger.log(`📢 Notification removed: ${notificationId}`);
        }
    }

    /**
     * Update a progress notification
     * @param {string} notificationId - The notification ID to update
     * @param {string} message - New message
     * @param {number} progress - Progress percentage (0-100)
     */
    updateProgress(notificationId, message, progress = null) {
        const notification = document.getElementById(notificationId);
        if (notification) {
            const messageEl = notification.querySelector('.notification-message');
            if (messageEl) {
                messageEl.textContent = message;
            }
            
            if (progress !== null) {
                const progressFill = notification.querySelector('.progress-fill');
                if (progressFill) {
                    progressFill.style.width = `${Math.min(100, Math.max(0, progress))}%`;
                }
            }
        }
    }

    /**
     * Show a confirmation dialog (non-blocking)
     * @param {string} title - Dialog title
     * @param {string} message - Dialog message
     * @param {function} onConfirm - Callback for confirm action
     * @param {function} onCancel - Callback for cancel action
     * @param {string} confirmText - Text for confirm button
     * @param {string} cancelText - Text for cancel button
     */
    showConfirm(title, message, onConfirm, onCancel = null, confirmText = 'Confirmar', cancelText = 'Cancelar') {
        const confirmId = `confirm-${Date.now()}`;
        
        const confirmDialog = document.createElement('div');
        confirmDialog.id = confirmId;
        confirmDialog.className = 'notification notification-confirm';
        confirmDialog.innerHTML = `
            <div class="notification-content confirm-content">
                <div class="confirm-header">
                    <span class="notification-icon">⚠️</span>
                    <strong class="confirm-title">${title}</strong>
                </div>
                <div class="confirm-message">${message}</div>
                <div class="confirm-buttons">
                    <button class="btn-confirm-cancel">${cancelText}</button>
                    <button class="btn-confirm-ok">${confirmText}</button>
                </div>
            </div>
        `;

        // Add event listeners
        const cancelBtn = confirmDialog.querySelector('.btn-confirm-cancel');
        const confirmBtn = confirmDialog.querySelector('.btn-confirm-ok');
        
        cancelBtn.addEventListener('click', () => {
            this.removeNotification(confirmId);
            if (onCancel) onCancel();
        });

        confirmBtn.addEventListener('click', () => {
            this.removeNotification(confirmId);
            if (onConfirm) onConfirm();
        });

        // Add to container
        if (this.container) {
            this.container.appendChild(confirmDialog);
        } else {
            document.body.appendChild(confirmDialog);
        }

        // Animate in
        requestAnimationFrame(() => {
            confirmDialog.classList.add('notification-show');
        });

        logger.log(`❓ Confirmation dialog shown: ${title}`);
        return confirmId;
    }

    /**
     * Clear all notifications
     */
    clearAll() {
        if (this.container) {
            this.container.innerHTML = '';
        }
        logger.log('📢 All notifications cleared');
    }

    /**
     * Get icon for notification type
     * @param {string} type - Notification type
     * @returns {string} - Icon emoji
     */
    getIcon(type) {
        const icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            error: '❌',
            progress: '⏳'
        };
        return icons[type] || 'ℹ️';
    }
}

// Create singleton instance
const notificationSystem = new NotificationSystem();

// Export singleton instance as default
export default notificationSystem;
  // Export to global scope
  window.NotificationSystem = NotificationSystem;

})();


/* ============= crypto.js ============= */
(function() {
  'use strict';
  
/**
 * Secure Cryptography Module
 * Uses Web Crypto API for hardware-accelerated AES-256-GCM encryption
 * All sensitive data is encrypted before storage
 */

class SecureCrypto {
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
const cryptoManager = new SecureCrypto();
  // Export to global scope
  window.SecureCrypto = SecureCrypto;
  window.cryptoManager = cryptoManager;

})();


/* ============= storage.js ============= */
(function() {
  'use strict';
  
/**
 * Secure Local Storage Module
 * Uses IndexedDB for persistent encrypted storage
 * All TOTP secrets and configuration are encrypted before storage
 */

class SecureStorage {
  constructor() {
    this.dbName = 'Personal2FA';
    this.dbVersion = 1;
    this.storeName = 'secrets';
    this.configStore = 'config';
    this.db = null;
    this.isInitialized = false;
    this.encryptionKey = null;
  }

  /**
   * Initialize IndexedDB database
   * @returns {Promise<void>}
   */
  async init() {
    if (this.isInitialized) return;
    
    return new Promise((resolve, reject) => {
      if (!indexedDB) {
        logger.error('IndexedDB not available, using localStorage fallback');
        this.isInitialized = true;
        resolve();
        return;
      }
      
      // Add timeout to prevent hanging
      const timeout = setTimeout(() => {
        logger.log('IndexedDB timeout - falling back to localStorage');
        this.isInitialized = true; // Mark as initialized to continue
        resolve(); // Resolve anyway to allow app to continue
      }, 3000);
      
      const request = indexedDB.open(this.dbName, this.dbVersion);
      
      request.onerror = (event) => {
        clearTimeout(timeout);
        logger.error('IndexedDB open error, falling back to localStorage');
        this.isInitialized = true;
        resolve(); // Continue with localStorage fallback
      };
      
      request.onsuccess = (event) => {
        clearTimeout(timeout);
        logger.log('IndexedDB opened successfully');
        this.db = event.target.result;
        this.isInitialized = true;
        resolve();
      };
      
      request.onupgradeneeded = (event) => {
        clearTimeout(timeout);
        const db = event.target.result;
        
        // Create secrets store for encrypted TOTP data
        if (!db.objectStoreNames.contains(this.storeName)) {
          const secretsStore = db.createObjectStore(this.storeName, {
            keyPath: 'id',
            autoIncrement: true
          });
          secretsStore.createIndex('issuer', 'issuer', { unique: false });
          secretsStore.createIndex('label', 'label', { unique: false });
        }
        
        // Create config store for app configuration
        if (!db.objectStoreNames.contains(this.configStore)) {
          db.createObjectStore(this.configStore, { keyPath: 'key' });
        }
      };
    });
  }

  /**
   * Setup master password and derive encryption key
   * @param {string} password - Master password
   * @returns {Promise<void>}
   */
  async setupMasterPassword(password) {
    // Generate random salt for this installation
    const salt = cryptoManager.generateRandomBytes(32);
    
    // Store salt (unencrypted, needed for key derivation)
    await this.setConfig('salt', cryptoManager.bytesToBase64(salt));
    
    // Derive encryption key from password
    this.encryptionKey = await cryptoManager.deriveKey(password, salt);
    
    // Store password verification hash
    const passwordHash = await cryptoManager.hash(password);
    await this.setConfig('passwordHash', passwordHash);
    
    // Mark as setup complete
    await this.setConfig('isSetup', true);
  }

  /**
   * Unlock storage with master password
   * @param {string} password - Master password
   * @returns {Promise<boolean>} True if password is correct
   */
  async unlock(password) {
    const storedHash = await this.getConfig('passwordHash');
    const passwordHash = await cryptoManager.hash(password);
    
    if (storedHash !== passwordHash) {
      return false;
    }
    
    // Derive encryption key
    const saltBase64 = await this.getConfig('salt');
    const salt = cryptoManager.base64ToBytes(saltBase64);
    this.encryptionKey = await cryptoManager.deriveKey(password, salt);
    
    return true;
  }

  /**
   * Check if storage is already setup
   * @returns {Promise<boolean>}
   */
  async isSetup() {
    const setup = await this.getConfig('isSetup');
    return setup === true;
  }

  /**
   * Lock storage (clear encryption key from memory)
   */
  lock() {
    this.encryptionKey = null;
  }

  /**
   * Check if storage is currently unlocked
   * @returns {boolean}
   */
  isUnlocked() {
    return this.encryptionKey !== null;
  }

  /**
   * Store encrypted TOTP secret
   * @param {Object} totpData - TOTP configuration
   * @returns {Promise<number>} Generated ID
   */
  async storeTOTPSecret(totpData) {
    if (!this.isUnlocked()) {
      throw new Error('Storage is locked. Unlock with master password first.');
    }
    
    // Encrypt the sensitive secret
    const secretJson = JSON.stringify({
      secret: totpData.secret,
      algorithm: totpData.algorithm || 'SHA1',
      digits: totpData.digits || 6,
      period: totpData.period || 30
    });
    
    const encrypted = await cryptoManager.encrypt(secretJson, this.encryptionKey);
    
    // Store encrypted data with unencrypted metadata
    const record = {
      issuer: totpData.issuer,
      label: totpData.label,
      encryptedSecret: cryptoManager.bytesToBase64(encrypted.ciphertext),
      iv: cryptoManager.bytesToBase64(encrypted.iv),
      createdAt: new Date().toISOString(),
      lastUsed: null
    };
    
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        // Get existing records
        const existing = localStorage.getItem('personal-2fa-secrets');
        const records = existing ? JSON.parse(existing) : [];
        
        // Generate simple ID
        const id = records.length > 0 ? Math.max(...records.map(r => r.id || 0)) + 1 : 1;
        record.id = id;
        
        // Add new record
        records.push(record);
        
        // Save back to localStorage
        localStorage.setItem('personal-2fa-secrets', JSON.stringify(records));
        return Promise.resolve(id);
      } catch (error) {
        return Promise.reject(new Error('Failed to store TOTP secret in localStorage'));
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.add(record);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Failed to store TOTP secret'));
    });
  }

  /**
   * Retrieve all TOTP secrets (decrypted)
   * @returns {Promise<Array>} Array of TOTP configurations
   */
  async getAllTOTPSecrets() {
    if (!this.isUnlocked()) {
      throw new Error('Storage is locked. Unlock with master password first.');
    }
    
    if (!this.encryptionKey) {
      throw new Error('Encryption key not available. Please unlock storage first.');
    }
    
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        const stored = localStorage.getItem('personal-2fa-secrets');
        if (!stored) return [];
        
        const records = JSON.parse(stored);
        const decryptedSecrets = [];
        
        for (const record of records) {
          try {
            // Reconstruct encrypted data for decryption
            const ciphertext = cryptoManager.base64ToBytes(record.encryptedSecret);
            const iv = cryptoManager.base64ToBytes(record.iv);
            
            // Decrypt the secret
            const decryptedJson = await cryptoManager.decrypt(ciphertext, iv, this.encryptionKey);
            const decryptedData = JSON.parse(decryptedJson);
            decryptedSecrets.push({
              id: record.id,
              issuer: record.issuer,
              label: record.label,
              secret: decryptedData.secret,
              algorithm: decryptedData.algorithm || 'SHA1',
              digits: decryptedData.digits || 6,
              period: decryptedData.period || 30
            });
          } catch (decryptError) {
            logger.error('Failed to decrypt TOTP secret:', decryptError);
          }
        }
        
        return decryptedSecrets;
      } catch (error) {
        return [];
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.getAll();
      
      request.onsuccess = async () => {
        const records = request.result;
        const decryptedSecrets = [];
        
        for (const record of records) {
          try {
            // Decrypt the secret
            const ciphertext = cryptoManager.base64ToBytes(record.encryptedSecret);
            const iv = cryptoManager.base64ToBytes(record.iv);
            const decryptedJson = await cryptoManager.decrypt(ciphertext, iv, this.encryptionKey);
            const secretData = JSON.parse(decryptedJson);
            
            decryptedSecrets.push({
              id: record.id,
              issuer: record.issuer,
              label: record.label,
              secret: secretData.secret,
              algorithm: secretData.algorithm,
              digits: secretData.digits,
              period: secretData.period,
              createdAt: record.createdAt,
              lastUsed: record.lastUsed
            });
          } catch (error) {
            logger.error('Failed to decrypt TOTP secret:', error);
            // Skip corrupted records
          }
        }
        
        resolve(decryptedSecrets);
      };
      
      request.onerror = () => reject(new Error('Failed to retrieve TOTP secrets'));
    });
  }

  /**
   * Delete TOTP secret by ID
   * @param {number} id - Secret ID
   * @returns {Promise<void>}
   */
  async deleteTOTPSecret(id) {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        const stored = localStorage.getItem('personal-2fa-secrets');
        if (!stored) return Promise.resolve();
        
        const records = JSON.parse(stored);
        const filteredRecords = records.filter(record => record.id !== id);
        
        localStorage.setItem('personal-2fa-secrets', JSON.stringify(filteredRecords));
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(new Error('Failed to delete TOTP secret from localStorage'));
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(id);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to delete TOTP secret'));
    });
  }

  /**
   * Update last used timestamp for TOTP secret
   * @param {number} id - Secret ID
   * @returns {Promise<void>}
   */
  async updateLastUsed(id) {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        const stored = localStorage.getItem('personal-2fa-secrets');
        if (!stored) return Promise.resolve();
        
        const records = JSON.parse(stored);
        const record = records.find(r => r.id === id);
        if (record) {
          record.lastUsed = new Date().toISOString();
          localStorage.setItem('personal-2fa-secrets', JSON.stringify(records));
        }
        
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(new Error('Failed to update timestamp in localStorage'));
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const getRequest = store.get(id);
      
      getRequest.onsuccess = () => {
        const record = getRequest.result;
        if (record) {
          record.lastUsed = new Date().toISOString();
          const putRequest = store.put(record);
          putRequest.onsuccess = () => resolve();
          putRequest.onerror = () => reject(new Error('Failed to update last used'));
        } else {
          reject(new Error('TOTP secret not found'));
        }
      };
      
      getRequest.onerror = () => reject(new Error('Failed to find TOTP secret'));
    });
  }

  /**
   * Store configuration value
   * @param {string} key - Config key
   * @param {any} value - Config value
   * @returns {Promise<void>}
   */
  async setConfig(key, value) {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        localStorage.setItem(`personal-2fa-config-${key}`, JSON.stringify(value));
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(new Error(`Failed to store config in localStorage: ${key}`));
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.configStore], 'readwrite');
      const store = transaction.objectStore(this.configStore);
      const request = store.put({ key, value });
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error(`Failed to store config: ${key}`));
    });
  }

  /**
   * Get configuration value
   * @param {string} key - Config key
   * @returns {Promise<any>} Config value
   */
  async getConfig(key) {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        const value = localStorage.getItem(`personal-2fa-config-${key}`);
        return value ? JSON.parse(value) : null;
      } catch (error) {
        return null;
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.configStore], 'readonly');
      const store = transaction.objectStore(this.configStore);
      const request = store.get(key);
      
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.value : null);
      };
      
      request.onerror = () => reject(new Error(`Failed to get config: ${key}`));
    });
  }

  /**
   * Clear all data (factory reset)
   * @returns {Promise<void>}
   */
  async clearAllData() {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        // Clear localStorage data
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && key.startsWith('personal-2fa-')) {
            keysToRemove.push(key);
          }
        }
        
        keysToRemove.forEach(key => localStorage.removeItem(key));
        
        // Clear memory
        this.encryptionKey = null;
        this.isInitialized = false;
        
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(new Error('Failed to clear localStorage data'));
      }
    }
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName, this.configStore], 'readwrite');
      
      const secretsStore = transaction.objectStore(this.storeName);
      const configStore = transaction.objectStore(this.configStore);
      
      const clearSecrets = secretsStore.clear();
      const clearConfig = configStore.clear();
      
      let completed = 0;
      const complete = () => {
        completed++;
        if (completed === 2) {
          this.encryptionKey = null;
          resolve();
        }
      };
      
      clearSecrets.onsuccess = complete;
      clearConfig.onsuccess = complete;
      
      clearSecrets.onerror = clearConfig.onerror = () => {
        reject(new Error('Failed to clear data'));
      };
    });
  }

  /**
   * Get storage statistics
   * @returns {Promise<Object>} Storage stats
   */
  async getStats() {
    const secretCount = await new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.count();
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Failed to count secrets'));
    });
    
    return {
      totalSecrets: secretCount,
      isSetup: await this.isSetup(),
      isUnlocked: this.isUnlocked(),
      dbSize: await this.estimateDbSize()
    };
  }

  /**
   * Estimate database size (approximate)
   * @returns {Promise<number>} Estimated size in bytes
   */
  async estimateDbSize() {
    if ('estimate' in navigator.storage) {
      const estimate = await navigator.storage.estimate();
      return estimate.usage || 0;
    }
    return 0; // Cannot estimate
  }
}

// Export singleton instance
const storageManager = new SecureStorage();
  // Export to global scope
  window.SecureStorage = SecureStorage;
  window.storageManager = storageManager;

})();


/* ============= totp.js ============= */
(function() {
  'use strict';
  
/**
 * TOTP (Time-based One-Time Password) Generator
 * Implements RFC 6238 TOTP algorithm
 * Supports SHA1, SHA256, SHA512 algorithms
 */

class TOTPGenerator {
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
const totpGenerator = new TOTPGenerator();
  // Export to global scope
  window.TOTPGenerator = TOTPGenerator;
  window.totpGenerator = totpGenerator;

})();


/* ============= qr.js ============= */
(function() {
  'use strict';
  
/**
 * QR Code Scanner and Generator Module
 * Handles QR code scanning via camera and generation for export
 * Supports Google Authenticator migration format
 */

// Import QR generation library
class QRManager {
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
    this.context = canvasElement.getContext('2d', { willReadFrequently: true });
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
const qrManager = new QRManager();
  // Export to global scope
  window.QRManager = QRManager;
  window.qrManager = qrManager;

})();


/* ============= googleAuth.js ============= */
(function() {
  'use strict';
  
/**
 * Google Authenticator Import/Export Module
 * Handles bidirectional sync with Google Authenticator
 * Import: Parse migration QR codes from Google Auth
 * Export: Generate QR codes for backup (NOT for storing in this app)
 */

class GoogleAuthManager {
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
      logger.log('🔄 Importing from Google Authenticator...');
      logger.log('🔄 Migration URI:', migrationUri);
      
      // Parse the migration QR data
      const secrets = qrManager.parseMigrationQR(migrationUri);
      logger.log('🔄 Parsed secrets from QR manager:', secrets);
      
      if (!secrets || secrets.length === 0) {
        logger.error('❌ No secrets found - parsed result:', secrets);
        throw new Error('No TOTP secrets found in migration data');
      }
      
      logger.log(`✅ Found ${secrets.length} TOTP secrets to import`);
      
      // Validate and normalize each secret
      const validatedSecrets = [];
      for (const secret of secrets) {
        try {
          logger.log('🔄 Validating secret:', secret);
          const validated = await this.validateTOTPSecret(secret);
          validatedSecrets.push(validated);
          logger.log('✅ Validated secret:', validated);
        } catch (error) {
          logger.warn(`⚠️ Skipping invalid secret for ${secret.issuer}:${secret.label}:`, error.message);
        }
      }
      
      logger.log('🔄 Final validated secrets:', validatedSecrets);
      return validatedSecrets;
    } catch (error) {
      logger.error('❌ Import error:', error);
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
      logger.log(`📤 Generating ${format} export QRs for ${secrets.length} secrets...`);
      
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
        
        logger.log(`✅ Generated QR for ${secret.issuer}:${secret.label}`);
      } catch (error) {
        logger.error(`❌ Failed to generate QR for ${secret.issuer}:${secret.label}:`, error);
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
        
        logger.log(`✅ Generated migration QR batch ${qrCodes.length} (${batch.length} secrets)`);
      } catch (error) {
        logger.error(`❌ Failed to generate migration QR batch ${i}:`, error);
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
        logger.log('🔐 TODO: Encrypt backup with password');
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
        logger.log('🔓 TODO: Decrypt backup with password');
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
          logger.warn(`⚠️ Skipping invalid secret in backup:`, error.message);
        }
      }
      
      logger.log(`✅ Imported ${validatedSecrets.length} secrets from JSON backup`);
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
    logger.log('📝 Adding secret for export-only mode (not storing permanently)');
    
    // Add to temporary export list
    this.exportedSecrets.push({
      ...secret,
      addedAt: new Date().toISOString()
    });
    
    logger.log(`📤 Export queue now has ${this.exportedSecrets.length} secrets`);
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
    logger.log('🗑️ Clearing export-only secrets queue');
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
const googleAuthManager = new GoogleAuthManager();
  // Export to global scope
  window.GoogleAuthManager = GoogleAuthManager;
  window.googleAuthManager = googleAuthManager;

})();


/* ============= main.js ============= */
(function() {
  'use strict';
  
/**
 * Main Application Controller
 * Coordinates all modules and manages application state
 */



class Personal2FAApp {
  constructor() {
    this.currentScreen = 'setup';
    this.isUnlocked = false;
    this.totpTimers = new Map();
    this.refreshInterval = null;
    this.securityCheckInterval = null;
    
    // DOM elements will be initialized in init()
    this.elements = {};
  }

  /**
   * Initialize the application
   */
  async init() {
    logger.log('🚀 Initializing Personal 2FA App...');
    
    try {
      // Initialize storage
      await storageManager.init();
      
      // Cache DOM elements
      this.initDOMElements();
      
      // Setup event listeners
      this.setupEventListeners();
      
      // Initialize QR manager
      qrManager.init(this.elements.qrVideo, this.elements.qrCanvas);
      
      // Check security status
      this.performSecurityChecks();
      
      // Show loading screen while checking setup status
      this.showScreen('loading');
      
      // Determine initial screen with a small delay for UX
      setTimeout(async () => {
        try {
          const isSetup = await storageManager.isSetup();
          if (isSetup) {
            this.showScreen('login');
          } else {
            this.showScreen('setup');
          }
        } catch (error) {
          logger.error('Error checking setup status:', error);
          this.showScreen('setup'); // Default to setup if error
        }
      }, 800); // 800ms delay for smooth UX
      
      logger.log('✅ App initialization complete');
      
    } catch (error) {
      logger.error('❌ App initialization failed:', error);
      this.showError('Failed to initialize app: ' + error.message);
    }
  }

  /**
   * Cache DOM elements for performance
   */
  initDOMElements() {
    this.elements = {
      // Screens
      loadingScreen: document.getElementById('loading-screen'),
      setupScreen: document.getElementById('setup-screen'),
      loginScreen: document.getElementById('login-screen'),
      mainScreen: document.getElementById('main-screen'),
      
      // Setup elements
      masterPassword: document.getElementById('master-password'),
      confirmPassword: document.getElementById('confirm-password'),
      setupComplete: document.getElementById('setup-complete'),
      
      // Login elements
      loginPassword: document.getElementById('login-password'),
      loginBtn: document.getElementById('login-btn'),
      loginError: document.getElementById('login-error'),
      
      // Main app elements
      importBtn: document.getElementById('import-btn'),
      exportBtn: document.getElementById('export-btn'),
      addManualBtn: document.getElementById('add-manual-btn'),
      manageDataBtn: document.getElementById('manage-data-btn'),
      lockBtn: document.getElementById('lock-btn'),
      
      // Sections
      importSection: document.getElementById('import-section'),
      exportSection: document.getElementById('export-section'),
      codesSection: document.getElementById('codes-section'),
      manualAddSection: document.getElementById('manual-add-section'),
      dataManagementSection: document.getElementById('data-management-section'),
      
      // QR Scanner
      qrVideo: document.getElementById('qr-video'),
      qrCanvas: document.getElementById('qr-canvas'),
      startCamera: document.getElementById('start-camera'),
      stopCamera: document.getElementById('stop-camera'),
      scanResult: document.getElementById('scan-result'),
      
      // Export
      exportGoogleFormat: document.getElementById('export-google-format'),
      exportIndividualQR: document.getElementById('export-individual-qr'),
      exportJSONBackup: document.getElementById('export-json-backup'),
      exportResult: document.getElementById('export-result'),
      
      // TOTP Display
      totpList: document.getElementById('totp-list'),
      emptyState: document.getElementById('empty-state'),
      
      // Manual Add Form
      manualAddForm: document.getElementById('manual-add-form'),
      manualIssuer: document.getElementById('manual-issuer'),
      manualLabel: document.getElementById('manual-label'),
      manualSecret: document.getElementById('manual-secret'),
      manualAlgorithm: document.getElementById('manual-algorithm'),
      manualDigits: document.getElementById('manual-digits'),
      manualPeriod: document.getElementById('manual-period'),
      cancelManual: document.getElementById('cancel-manual'),
      
      // Data Management
      clearAllData: document.getElementById('clear-all-data'),
      factoryReset: document.getElementById('factory-reset'),
      logsEnabledToggle: document.getElementById('logs-enabled-toggle'),
      
      // Security indicators
      cryptoStatus: document.getElementById('crypto-status'),
      storageStatus: document.getElementById('storage-status'),
      networkStatus: document.getElementById('network-status'),
      securityChecks: document.getElementById('security-checks')
    };
    

  }

  /**
   * Setup all event listeners
   */
  setupEventListeners() {
    // Setup screen
    this.elements.setupComplete.addEventListener('click', () => this.handleSetup());
    
    // Add Enter key support for passwords
    this.elements.confirmPassword.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.handleSetup();
      }
    });
    
    // Login screen
    this.elements.loginBtn.addEventListener('click', () => this.handleLogin());
    this.elements.loginPassword.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleLogin();
    });
    
    // Main navigation
    this.elements.importBtn.addEventListener('click', () => this.showImportSection());
    this.elements.exportBtn.addEventListener('click', () => this.showExportSection());
    this.elements.addManualBtn.addEventListener('click', () => this.showManualAddSection());
    this.elements.manageDataBtn.addEventListener('click', () => this.showDataManagementSection());
    this.elements.lockBtn.addEventListener('click', () => this.lockApp());
    
    // QR Scanner
    this.elements.startCamera.addEventListener('click', () => this.startQRScanning());
    this.elements.stopCamera.addEventListener('click', () => this.stopQRScanning());
    
    // Export buttons
    this.elements.exportGoogleFormat.addEventListener('click', () => this.exportGoogleFormat());
    this.elements.exportIndividualQR.addEventListener('click', () => this.exportIndividualQR());
    this.elements.exportJSONBackup.addEventListener('click', () => this.exportJSONBackup());
    
    // Manual add form
    this.elements.manualAddForm.addEventListener('submit', (e) => this.handleManualAdd(e));
    this.elements.cancelManual.addEventListener('click', () => {
      this.hideAllSections();
      this.updateActiveButton(null); // Clear active button state
    });
    
    // Data management
    this.elements.clearAllData.addEventListener('click', () => this.handleClearAllData());
    this.elements.factoryReset.addEventListener('click', () => this.handleFactoryReset());
    this.elements.logsEnabledToggle.addEventListener('change', (e) => this.handleLogsToggle(e));
    
    // Network status monitoring
    window.addEventListener('online', () => this.updateNetworkStatus());
    window.addEventListener('offline', () => this.updateNetworkStatus());
    
    // Security monitoring
    this.startSecurityMonitoring();
  }

  /**
   * Handle master password setup
   */
  async handleSetup() {
    try {
      const password = this.elements.masterPassword.value;
      const confirmPassword = this.elements.confirmPassword.value;
      
      if (!password || password.length < 8) {
        this.showError('La contraseña debe tener al menos 8 caracteres');
        return;
      }
      
      if (password !== confirmPassword) {
        this.showError('Las contraseñas no coinciden');
        return;
      }
      
      logger.log('🔐 Setting up master password...');
      
      // Show progress notification
      const progressId = notificationSystem.showNotification(
        '🔐 Configurando contraseña maestra...',
        'progress',
        0
      );
      
      await storageManager.setupMasterPassword(password);
      
      // Remove progress notification
      notificationSystem.removeNotification(progressId);
      
      this.isUnlocked = true;
      this.showScreen('main');
      this.refreshTOTPCodes();
      
      logger.log('✅ Master password setup complete');
      this.showSuccess('✅ Contraseña maestra configurada correctamente');
      
    } catch (error) {
      logger.error('❌ Setup failed:', error);
      this.showError('Error en la configuración: ' + error.message);
    }
  }

  /**
   * Handle login with master password
   */
  async handleLogin() {
    const password = this.elements.loginPassword.value;
    
    if (!password) {
      this.showLoginError('Please enter your master password');
      return;
    }
    
    try {
      logger.log('🔓 Attempting to unlock storage...');
      const success = await storageManager.unlock(password);
      
      if (success) {
        this.isUnlocked = true;
        this.showScreen('main');
        this.refreshTOTPCodes();
        logger.log('✅ Storage unlocked successfully');
      } else {
        this.showLoginError('Invalid password');
      }
    } catch (error) {
      logger.error('❌ Login failed:', error);
      this.showLoginError('Login failed: ' + error.message);
    }
  }

  /**
   * Update active button state
   */
  updateActiveButton(activeButton) {
    // Remove active class from all navigation buttons
    const navButtons = [
      this.elements.importBtn,
      this.elements.exportBtn,
      this.elements.addManualBtn,
      this.elements.manageDataBtn
    ];
    
    navButtons.forEach(btn => btn.classList.remove('active'));
    
    // Add active class to the current button
    if (activeButton) {
      activeButton.classList.add('active');
    }
  }

  /**
   * Show import section and hide others
   */
  showImportSection() {
    this.hideAllSections();
    this.updateActiveButton(this.elements.importBtn);
    this.elements.importSection.classList.remove('hidden');
    
    // Scroll to the section
    setTimeout(() => {
      this.elements.importSection.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'start' 
      });
    }, 100);
  }

  /**
   * Show export section and hide others
   */
  showExportSection() {
    this.hideAllSections();
    this.updateActiveButton(this.elements.exportBtn);
    this.elements.exportSection.classList.remove('hidden');
    
    // Scroll to the section
    setTimeout(() => {
      this.elements.exportSection.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'start' 
      });
    }, 100);
  }

  /**
   * Show manual add section and hide others
   */
  showManualAddSection() {
    this.hideAllSections();
    this.updateActiveButton(this.elements.addManualBtn);
    this.elements.manualAddSection.classList.remove('hidden');
    
    // Scroll to the section
    setTimeout(() => {
      this.elements.manualAddSection.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'start' 
      });
    }, 100);
  }

  /**
   * Show data management section
   */
  showDataManagementSection() {
    logger.log('🗑️ Showing data management section...');
    this.hideAllSections();
    this.updateActiveButton(this.elements.manageDataBtn);
    this.elements.dataManagementSection.classList.remove('hidden');
    this.initializeLogsToggle();
    
    // Scroll to the section with smooth animation
    setTimeout(() => {
      this.elements.dataManagementSection.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'start' 
      });
    }, 100); // Small delay to ensure the section is visible before scrolling
  }

  /**
   * Hide all sections
   */
  hideAllSections() {
    const sections = [
      this.elements.importSection,
      this.elements.exportSection,
      this.elements.manualAddSection,
      this.elements.dataManagementSection
    ];
    
    sections.forEach(section => section.classList.add('hidden'));
    
    // Clear active states when hiding sections via other means (like cancel buttons)
    // Note: This will be overridden by updateActiveButton when showing a new section
  }

  /**
   * Start QR code scanning
   */
  async startQRScanning() {
    try {
      logger.log('📹 Starting QR scanner...');
      
      this.elements.startCamera.classList.add('hidden');
      this.elements.stopCamera.classList.remove('hidden');
      this.elements.scanResult.innerHTML = '<div class="scanning">🔍 Scanning for QR codes...</div>';
      
      await qrManager.startScanning((qrData) => {
        this.handleQRDetected(qrData);
      });
      
    } catch (error) {
      logger.error('❌ Failed to start camera:', error);
      this.elements.scanResult.innerHTML = `<div class="error">❌ Camera Error: ${error.message}</div>`;
      this.elements.startCamera.classList.remove('hidden');
      this.elements.stopCamera.classList.add('hidden');
    }
  }

  /**
   * Stop QR code scanning
   */
  stopQRScanning() {
    logger.log('⏹️ Stopping QR scanner...');
    
    qrManager.stopScanning();
    this.elements.startCamera.classList.remove('hidden');
    this.elements.stopCamera.classList.add('hidden');
    this.elements.scanResult.innerHTML = '';
  }

  /**
   * Handle detected QR code
   */
  async handleQRDetected(qrData) {
    try {
      logger.log('🔍 QR Code detected:', qrData);
      
      // Stop scanning
      this.stopQRScanning();
      
      // Check if it's a migration QR
      if (qrData.startsWith('otpauth-migration://')) {
        logger.log('📱 Google Authenticator migration QR detected');
        const secrets = await googleAuthManager.importFromGoogleAuth(qrData);
        await this.importTOTPSecrets(secrets);
      } else if (qrData.startsWith('otpauth://')) {
        logger.log('🔑 Individual TOTP QR detected');
        const secret = totpGenerator.parseOTPAuthURI(qrData);
        await this.importTOTPSecrets([secret]);
      } else {
        throw new Error('Unrecognized QR code format');
      }
      
    } catch (error) {
      logger.error('❌ QR processing failed:', error);
      this.elements.scanResult.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
    }
  }

  /**
   * Import TOTP secrets and store them
   */
  async importTOTPSecrets(secrets) {
    try {
      let importedCount = 0;
      
      for (const secret of secrets) {
        try {
          await storageManager.storeTOTPSecret(secret);
          importedCount++;
          logger.log(`✅ Imported: ${secret.issuer}:${secret.label}`);
        } catch (error) {
          logger.error(`❌ Failed to import ${secret.issuer}:${secret.label}:`, error);
        }
      }
      
      this.elements.scanResult.innerHTML = `
        <div class="success">
          ✅ Successfully imported ${importedCount} TOTP secrets!
        </div>
      `;
      
      // Refresh the TOTP display
      this.refreshTOTPCodes();
      
    } catch (error) {
      logger.error('❌ Import failed:', error);
      this.elements.scanResult.innerHTML = `<div class="error">❌ Import failed: ${error.message}</div>`;
    }
  }

  /**
   * Handle manual TOTP addition
   */
  async handleManualAdd(event) {
    event.preventDefault();
    
    const secret = {
      issuer: this.elements.manualIssuer.value.trim(),
      label: this.elements.manualLabel.value.trim(),
      secret: this.elements.manualSecret.value.trim(),
      algorithm: this.elements.manualAlgorithm.value,
      digits: parseInt(this.elements.manualDigits.value),
      period: parseInt(this.elements.manualPeriod.value)
    };
    
    try {
      // Validate the secret
      const validatedSecret = await googleAuthManager.validateTOTPSecret(secret);
      
      // Store the secret
      await storageManager.storeTOTPSecret(validatedSecret);
      
      logger.log(`✅ Added manual TOTP: ${secret.issuer}:${secret.label}`);
      
      // Reset form and hide section
      this.elements.manualAddForm.reset();
      this.hideAllSections();
      this.updateActiveButton(null); // Clear active button state
      
      // Refresh display
      this.refreshTOTPCodes();
      
    } catch (error) {
      logger.error('❌ Manual add failed:', error);
      this.showError('Failed to add TOTP: ' + error.message);
    }
  }

  /**
   * Handle logs toggle change
   */
  handleLogsToggle(event) {
    const enabled = event.target.checked;
    logger.setLogPreference(enabled);
    logger.log(`📝 Logs ${enabled ? 'habilitados' : 'deshabilitados'}`);
  }

  /**
   * Handle individual TOTP deletion
   */
  async handleDeleteTOTP(secretId, issuer, label) {
    try {
      // First confirmation dialog
      const firstConfirm = confirm(
        `¿Estás seguro de que quieres eliminar este código 2FA?\n\n` +
        `Servicio: ${issuer}\n` +
        `Cuenta: ${label}\n\n` +
        `⚠️ Esta acción no se puede deshacer.`
      );

      if (!firstConfirm) {
        logger.log('🔒 Delete cancelled by user (first confirmation)');
        return;
      }

      // Second confirmation with text input for safety
      const confirmText = prompt(
        `Para confirmar la eliminación, escribe: ELIMINAR\n\n` +
        `Servicio: ${issuer}\n` +
        `Cuenta: ${label}`
      );

      if (confirmText !== 'ELIMINAR') {
        logger.log('🔒 Delete cancelled - incorrect confirmation text');
        return;
      }

      logger.log(`🗑️ Deleting TOTP: ${issuer}:${label} (ID: ${secretId})`);

      // Add animation before deleting
      const totpElement = document.querySelector(`[data-id="${secretId}"]`);
      if (totpElement) {
        totpElement.classList.add('deleting');
        
        // Wait for animation to complete before actually deleting
        setTimeout(async () => {
          // Delete from storage
          await storageManager.deleteTOTPSecret(secretId);

          logger.log(`✅ Successfully deleted TOTP: ${issuer}:${label}`);

          // Refresh the display
          this.refreshTOTPCodes();
        }, 500); // Animation duration
      } else {
        // If element not found, delete immediately
        await storageManager.deleteTOTPSecret(secretId);
        this.refreshTOTPCodes();
      }

      // Show success message briefly (more subtle than alert)
      logger.log(`✅ Código eliminado: ${issuer}:${label}`);

    } catch (error) {
      logger.error('❌ Failed to delete TOTP:', error);
      this.showError(`❌ Error al eliminar: ${error.message}`);
    }
  }

  /**
   * Initialize logs toggle state
   */
  initializeLogsToggle() {
    if (this.elements.logsEnabledToggle) {
      this.elements.logsEnabledToggle.checked = logger.isEnabled();
    }
  }

  /**
   * Handle clearing all application data with multiple confirmations
   */
  async handleClearAllData() {
    try {
      // First confirmation - Basic warning
      const firstConfirm = confirm(
        '⚠️ ADVERTENCIA: Estás a punto de eliminar TODOS los códigos 2FA y datos de la aplicación.\n\n' +
        '🚨 Esta acción NO se puede deshacer.\n' +
        '🚨 Perderás el acceso a todas las cuentas configuradas.\n' +
        '🚨 NO podrás recuperar esta información.\n\n' +
        '¿Estás absolutamente seguro de que quieres continuar?'
      );
      
      if (!firstConfirm) {
        logger.log('🔒 Clear data cancelled by user (first confirmation)');
        return;
      }

      // Second confirmation - More specific
      const secondConfirm = confirm(
        '🚨 CONFIRMACIÓN FINAL 🚨\n\n' +
        'Vas a eliminar permanentemente:\n' +
        '• Todos los códigos 2FA guardados\n' +
        '• Configuraciones de la aplicación\n' +
        '• Datos de IndexedDB y localStorage\n' +
        '• Contraseña maestra configurada\n\n' +
        '⚠️ DESPUÉS DE ESTO TENDRÁS QUE:\n' +
        '• Configurar de nuevo todos tus códigos 2FA\n' +
        '• Crear una nueva contraseña maestra\n' +
        '• Volver a importar desde otras aplicaciones\n\n' +
        'Escribe "BORRAR TODO" si realmente quieres continuar:'
      );
      
      if (secondConfirm !== 'BORRAR TODO') {
        logger.log('🔒 Clear data cancelled - incorrect confirmation text');
        alert('❌ Cancelado. Para confirmar debes escribir exactamente "BORRAR TODO"');
        return;
      }

      // Third and final confirmation
      const finalConfirm = confirm(
        '🔥 ÚLTIMA OPORTUNIDAD 🔥\n\n' +
        'Esta es tu última oportunidad para cancelar.\n' +
        'Una vez que hagas clic en "Aceptar", NO HAY VUELTA ATRÁS.\n\n' +
        '¿Proceder con la eliminación TOTAL e IRREVERSIBLE de todos los datos?'
      );
      
      if (!finalConfirm) {
        logger.log('🔒 Clear data cancelled by user (final confirmation)');
        return;
      }

      logger.log('🗑️ User confirmed data deletion. Proceeding...');
      
      // Show progress message
      alert('🗑️ Eliminando todos los datos... Por favor espera...');
      
      // Clear all data
      await this.clearAllApplicationData();
      
      // Show success message
      alert(
        '✅ Datos eliminados exitosamente\n\n' +
        'Todos los datos han sido eliminados de forma permanente.\n' +
        'La página se recargará para reiniciar la aplicación.'
      );
      
      // Reload the page to start fresh
      window.location.reload();
      
    } catch (error) {
      logger.error('❌ Error clearing data:', error);
      this.showError('Error al eliminar los datos: ' + error.message);
    }
  }

  /**
   * Handle factory reset (complete application reset)
   */
  async handleFactoryReset() {
    try {
      // Use notification system for confirmation instead of blocking alerts
      return new Promise((resolve) => {
        // First confirmation
        notificationSystem.showConfirm(
          '🔄 FACTORY RESET - ADVERTENCIA CRÍTICA',
          '⚠️ Un Factory Reset ELIMINARÁ COMPLETAMENTE:<br><br>' +
          '🔐 Tu contraseña maestra configurada<br>' +
          '🗑️ TODOS los códigos 2FA guardados<br>' +
          '⚙️ TODAS las configuraciones personalizadas<br>' +
          '💾 TODO el historial y datos locales<br><br>' +
          '🚨 <strong>LA APLICACIÓN VOLVERÁ AL ESTADO INICIAL</strong><br>' +
          '🚨 <strong>COMO SI NUNCA LA HUBIERAS USADO</strong><br><br>' +
          '¿Estás completamente seguro de que quieres continuar?',
          () => {
            // If confirmed, show second confirmation with text input
            this.showFactoryResetTextConfirmation(resolve);
          },
          () => {
            logger.log('🔒 Factory reset cancelled by user (first confirmation)');
            resolve();
          },
          'Sí, Continuar',
          'Cancelar'
        );
      });
    } catch (error) {
      logger.error('❌ Factory reset failed:', error);
      notificationSystem.showNotification(
        '❌ Error durante el factory reset: ' + error.message,
        'error',
        5000
      );
    }
  }

  /**
   * Show text confirmation for factory reset
   */
  showFactoryResetTextConfirmation(resolve) {
    const confirmId = `factory-confirm-${Date.now()}`;
    
    const confirmDialog = document.createElement('div');
    confirmDialog.id = confirmId;
    confirmDialog.className = 'notification notification-confirm factory-reset-confirm';
    confirmDialog.innerHTML = `
      <div class="notification-content confirm-content">
        <div class="confirm-header">
          <span class="notification-icon">⚠️</span>
          <strong class="confirm-title">CONFIRMACIÓN DE FACTORY RESET</strong>
        </div>
        <div class="confirm-message">
          Para proceder con el reset completo de la aplicación,<br>
          escribe exactamente: <strong>FACTORY RESET</strong><br><br>
          ⚠️ Esta acción es <strong>COMPLETAMENTE IRREVERSIBLE</strong><br>
          ⚠️ Perderás <strong>TODO</strong> lo configurado en esta aplicación
        </div>
        <div class="factory-reset-input">
          <input type="text" id="factory-reset-text" placeholder="Escribe: FACTORY RESET" 
                 style="width: 100%; padding: 10px; margin: 10px 0; font-size: 14px; border: 2px solid #ccc; border-radius: 4px;">
        </div>
        <div class="confirm-buttons">
          <button class="btn-confirm-cancel">Cancelar</button>
          <button class="btn-confirm-ok">Continuar</button>
        </div>
      </div>
    `;

    const container = notificationSystem.container || document.body;
    container.appendChild(confirmDialog);

    // Get elements
    const textInput = confirmDialog.querySelector('#factory-reset-text');
    const cancelBtn = confirmDialog.querySelector('.btn-confirm-cancel');
    const confirmBtn = confirmDialog.querySelector('.btn-confirm-ok');

    // Focus input
    setTimeout(() => textInput.focus(), 100);

    // Handle input validation
    textInput.addEventListener('input', () => {
      const isValid = textInput.value === 'FACTORY RESET';
      confirmBtn.style.opacity = isValid ? '1' : '0.5';
      confirmBtn.disabled = !isValid;
    });

    // Handle enter key
    textInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && textInput.value === 'FACTORY RESET') {
        confirmBtn.click();
      }
    });

    // Handle cancel
    cancelBtn.addEventListener('click', () => {
      notificationSystem.removeNotification(confirmId);
      logger.log('🔒 Factory reset cancelled - text confirmation cancelled');
      resolve();
    });

    // Handle confirm
    confirmBtn.addEventListener('click', () => {
      if (textInput.value !== 'FACTORY RESET') {
        notificationSystem.showNotification('❌ Texto incorrecto. Debes escribir exactamente: FACTORY RESET', 'error');
        return;
      }
      
      notificationSystem.removeNotification(confirmId);
      this.showFactoryResetFinalConfirmation(resolve);
    });

    // Animate in
    requestAnimationFrame(() => {
      confirmDialog.classList.add('notification-show');
    });
  }

  /**
   * Show final confirmation for factory reset
   */
  showFactoryResetFinalConfirmation(resolve) {
    notificationSystem.showConfirm(
      '🚨 ÚLTIMA ADVERTENCIA - FACTORY RESET 🚨',
      '⚠️ Estás a punto de realizar un <strong>RESET COMPLETO</strong>.<br>' +
      'La aplicación volverá al estado inicial.<br><br>' +
      '❌ <strong>NO PODRÁS RECUPERAR NADA</strong><br>' +
      '❌ <strong>NO HAY COPIAS DE SEGURIDAD</strong><br>' +
      '❌ <strong>NO HAY FORMA DE DESHACER ESTA ACCIÓN</strong><br><br>' +
      'Una vez que hagas clic en "Ejecutar Reset", la aplicación<br>' +
      'se reseteará completamente como si nunca la hubieras usado.',
      async () => {
        logger.log('🔄 User confirmed factory reset. Proceeding with complete reset...');
        
        // Show progress notification
        const progressId = notificationSystem.showNotification(
          '🔄 Ejecutando Factory Reset... Por favor espera...',
          'progress',
          0 // No auto-hide
        );

        try {
          // Update progress
          notificationSystem.updateProgress(progressId, 'Limpiando almacenamiento local...', 25);
          
          // Perform complete factory reset
          await this.performFactoryReset();
          
          // Update progress
          notificationSystem.updateProgress(progressId, 'Factory Reset completado', 100);
          
        } catch (error) {
          // Even if factory reset fails, force clear and continue
          logger.error('Factory reset error, forcing cleanup:', error);
          localStorage.clear();
          sessionStorage.clear();
          notificationSystem.updateProgress(progressId, 'Forzando limpieza...', 90);
        }
        
        // Always remove progress notification and reload
        setTimeout(() => {
          notificationSystem.removeNotification(progressId);
          
          // Show completion and reload immediately
          notificationSystem.showNotification(
            '✅ FACTORY RESET COMPLETADO<br><br>' +
            'La aplicación ha sido completamente reseteada.<br>' +
            '🔄 Recargando página...',
            'success',
            2000
          );

          // Reload the page quickly
          setTimeout(() => {
            window.location.reload();
          }, 1500);
        }, 500);
        
        resolve();
      },
      () => {
        logger.log('🔒 Factory reset cancelled by user (final confirmation)');
        resolve();
      },
      'Ejecutar Reset',
      'Cancelar'
    );
  }

  /**
   * Clear all application data from all storage mechanisms
   */
  async clearAllApplicationData() {
    logger.log('🧹 Starting complete data cleanup...');
    
    try {
      // 1. Clear IndexedDB (TOTP secrets and encrypted data)
      logger.log('🗑️ Clearing IndexedDB...');
      if (storageManager) {
        await storageManager.clearAllData();
      }
      
      // 2. Clear localStorage (settings, cached data)
      logger.log('🗑️ Clearing localStorage...');
      localStorage.clear();
      
      // 3. Clear sessionStorage (temporary session data)
      logger.log('🗑️ Clearing sessionStorage...');
      sessionStorage.clear();
      
      // 4. Reset application state
      this.isLoggedIn = false;
      this.currentCodes = [];
      this.updateInterval = null;
      
      logger.log('✅ All application data cleared successfully');
      
    } catch (error) {
      logger.error('❌ Error during data cleanup:', error);
      throw error;
    }
  }

  /**
   * Perform complete factory reset - more thorough than clearAllApplicationData
   * Removes ALL traces of the application, including setup state
   */
  async performFactoryReset() {
    logger.log('🔄 Starting FACTORY RESET - complete application reset...');
    
    // Add timeout to prevent hanging
    const factoryResetPromise = this._doFactoryReset();
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Factory reset timeout')), 10000);
    });
    
    try {
      await Promise.race([factoryResetPromise, timeoutPromise]);
      logger.log('✅ FACTORY RESET completed successfully');
    } catch (error) {
      logger.error('❌ Error during factory reset:', error);
      // Force clear localStorage anyway
      localStorage.clear();
      sessionStorage.clear();
      throw error;
    }
  }

  /**
   * Internal factory reset implementation
   */
  async _doFactoryReset() {
    try {
      // 1. Clear all application data first (TOTP secrets, etc.)
      logger.log('🗑️ Clearing application data...');
      await this.clearAllApplicationData();
      
      // 2. Clear ALL localStorage keys (including setup state)
      logger.log('🗑️ Clearing ALL localStorage...');
      localStorage.clear();
      
      // 3. Clear ALL sessionStorage
      logger.log('🗑️ Clearing ALL sessionStorage...');
      sessionStorage.clear();
      
      // 4. Clear ALL cookies for this domain
      logger.log('🗑️ Clearing cookies...');
      document.cookie.split(";").forEach(cookie => {
        const eqPos = cookie.indexOf("=");
        const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=${window.location.hostname}`;
      });
      
      // 5. Clear IndexedDB completely (all databases)
      logger.log('🗑️ Clearing ALL IndexedDB databases...');
      try {
        if ('indexedDB' in window) {
          // Try to delete our specific database
          const deleteReq = indexedDB.deleteDatabase('Personal2FA');
          await new Promise((resolve) => {
            deleteReq.onsuccess = () => resolve();
            deleteReq.onerror = () => resolve(); // Continue even if it fails
            setTimeout(() => resolve(), 2000); // Timeout after 2 seconds
          });
          logger.log(`🗑️ Deleted IndexedDB: Personal2FA`);
        }
      } catch (e) {
        // Continue if IndexedDB cleanup fails
        logger.error('IndexedDB cleanup failed, continuing:', e);
      }
      
      // 6. Clear any Web SQL databases (legacy)
      logger.log('🗑️ Clearing Web SQL (if exists)...');
      try {
        if ('openDatabase' in window) {
          // Clear any Web SQL databases that might exist
          const db = openDatabase('', '', '', '', '');
          if (db) {
            db.transaction(tx => tx.executeSql('DROP TABLE IF EXISTS data'));
          }
        }
      } catch (e) {
        // Web SQL might not be supported, ignore
      }
      
      // 7. Clear Cache API if available
      logger.log('🗑️ Clearing Cache API...');
      try {
        if ('caches' in window) {
          const cacheNames = await caches.keys();
          for (const cacheName of cacheNames) {
            await caches.delete(cacheName);
            logger.log(`🗑️ Deleted cache: ${cacheName}`);
          }
        }
      } catch (e) {
        // Continue if cache cleanup fails
        logger.error('Cache cleanup failed, continuing:', e);
      }
      
      // 8. Reset application state completely
      logger.log('🔄 Resetting application state...');
      this.currentScreen = 'setup';
      this.isUnlocked = false;
      this.isLoggedIn = false;
      this.currentCodes = [];
      this.totpTimers = new Map();
      this.refreshInterval = null;
      this.cryptoManager = null;
      
      // 9. Clear any service worker registrations
      logger.log('🗑️ Clearing service workers...');
      try {
        if ('serviceWorker' in navigator) {
          const registrations = await navigator.serviceWorker.getRegistrations();
          for (const registration of registrations) {
            await registration.unregister();
            logger.log('🗑️ Unregistered service worker');
          }
        }
      } catch (e) {
        // Continue if service worker cleanup fails
        logger.error('Service worker cleanup failed, continuing:', e);
      }
      
      // 10. Force garbage collection if available
      if (window.gc) {
        window.gc();
      }
      
      logger.log('🔄 Application state has been completely reset to initial state');
      
    } catch (error) {
      logger.error('❌ Error during factory reset:', error);
      throw error;
    }
  }

  /**
   * Export in Google Authenticator format
   */
  async exportGoogleFormat() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const qrCodes = await googleAuthManager.generateExportQRs(secrets, 'migration');
      this.displayExportResult(qrCodes, 'Google Authenticator Migration');
    } catch (error) {
      logger.error('❌ Google format export failed:', error);
      this.showError('Export failed: ' + error.message);
    }
  }

  /**
   * Export individual QR codes
   */
  async exportIndividualQR() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const qrCodes = await googleAuthManager.generateExportQRs(secrets, 'individual');
      this.displayExportResult(qrCodes, 'Individual QR Codes');
    } catch (error) {
      logger.error('❌ Individual QR export failed:', error);
      this.showError('Export failed: ' + error.message);
    }
  }

  /**
   * Export JSON backup
   */
  async exportJSONBackup() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const jsonBackup = await googleAuthManager.exportToJSON(secrets);
      
      // Create download link
      const blob = new Blob([jsonBackup], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `personal-2fa-backup-${new Date().toISOString().split('T')[0]}.json`;
      link.click();
      
      URL.revokeObjectURL(url);
      
      this.elements.exportResult.innerHTML = '<div class="success">✅ JSON backup downloaded!</div>';
      
    } catch (error) {
      logger.error('❌ JSON export failed:', error);
      this.showError('Export failed: ' + error.message);
    }
  }

  /**
   * Display export results
   */
  displayExportResult(qrCodes, title) {
    let html = `<h4>${title}</h4>`;
    
    qrCodes.forEach((qr, index) => {
      html += `
        <div class="export-qr">
          <h5>${qr.type === 'individual' ? `${qr.issuer}: ${qr.label}` : `Batch ${qr.batchNumber}/${qr.totalBatches}`}</h5>
          <img src="${qr.qrCode}" alt="QR Code" style="max-width: 300px;">
        </div>
      `;
    });
    
    this.elements.exportResult.innerHTML = html;
  }

  /**
   * Refresh TOTP codes display
   */
  async refreshTOTPCodes() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      
      if (secrets.length === 0) {
        this.elements.totpList.style.display = 'none';
        this.elements.emptyState.style.display = 'block';
        return;
      }
      
      this.elements.totpList.style.display = 'block';
      this.elements.emptyState.style.display = 'none';
      
      // Clear existing timers
      this.totpTimers.clear();
      
      // Generate HTML for each TOTP
      let html = '';
      for (const secret of secrets) {
        const totpData = await totpGenerator.generateTOTP(secret.secret, secret);
        html += this.createTOTPItemHTML(secret, totpData);
        
        // Store timer info
        this.totpTimers.set(secret.id, {
          secret,
          lastUpdate: Date.now()
        });
      }
      
      this.elements.totpList.innerHTML = html;
      
      // Start refresh timer
      this.startTOTPRefresh();
      
    } catch (error) {
      logger.error('❌ Failed to refresh TOTP codes:', error);
      this.showError('Failed to load TOTP codes: ' + error.message);
    }
  }

  /**
   * Create HTML for TOTP item
   */
  createTOTPItemHTML(secret, totpData) {
    return `
      <div class="totp-item" data-id="${secret.id}">
        <div class="totp-header">
          <div class="totp-info">
            <div class="totp-service">${secret.issuer}</div>
            <div class="totp-account">${secret.label}</div>
          </div>
          <button class="totp-delete-btn" onclick="app.handleDeleteTOTP('${secret.id}', '${secret.issuer}', '${secret.label}')" title="Eliminar este código">
            🗑️
          </button>
        </div>
        <div class="totp-code" onclick="navigator.clipboard.writeText('${totpData.code}')">${totpData.code}</div>
        <div class="totp-timer">
          <div class="timer-progress">
            <div class="timer-bar" style="width: ${totpData.progress}%"></div>
          </div>
          <div class="timer-text">${totpData.timeRemaining}s</div>
        </div>
      </div>
    `;
  }

  /**
   * Start TOTP refresh timer
   */
  startTOTPRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
    
    this.refreshInterval = setInterval(() => {
      this.updateTOTPTimers();
    }, 1000);
  }

  /**
   * Update TOTP timers and regenerate codes when needed
   */
  async updateTOTPTimers() {
    for (const [secretId, timerInfo] of this.totpTimers) {
      try {
        const totpData = await totpGenerator.generateTOTP(timerInfo.secret.secret, timerInfo.secret);
        
        const element = document.querySelector(`[data-id="${secretId}"]`);
        if (element) {
          // Update code if it changed
          const codeElement = element.querySelector('.totp-code');
          if (codeElement.textContent !== totpData.code) {
            codeElement.textContent = totpData.code;
          }
          
          // Update timer
          const timerBar = element.querySelector('.timer-bar');
          const timerText = element.querySelector('.timer-text');
          
          if (timerBar && timerText) {
            timerBar.style.width = `${totpData.progress}%`;
            timerText.textContent = `${totpData.timeRemaining}s`;
          }
        }
      } catch (error) {
        logger.error(`❌ Failed to update TOTP for secret ${secretId}:`, error);
      }
    }
  }

  /**
   * Lock the application
   */
  lockApp() {
    logger.log('🔒 Locking application...');
    
    // Clear timers
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
    
    this.totpTimers.clear();
    
    // Lock storage
    storageManager.lock();
    this.isUnlocked = false;
    
    // Clear sensitive data from DOM
    this.elements.totpList.innerHTML = '';
    this.elements.loginPassword.value = '';
    
    // Show login screen
    this.showScreen('login');
  }

  /**
   * Show specific screen
   */
  showScreen(screenName) {
    const screens = ['loading', 'setup', 'login', 'main'];
    
    screens.forEach(screen => {
      const element = document.getElementById(`${screen}-screen`);
      if (element) {
        element.classList.toggle('active', screen === screenName);
      }
    });
    
    this.currentScreen = screenName;
    logger.log(`📱 Showing ${screenName} screen`);
  }

  /**
   * Show error message
   */
  showError(message) {
    logger.error('❌', message);
    notificationSystem.showNotification(message, 'error', 5000);
  }

  /**
   * Show success message
   */
  showSuccess(message) {
    logger.log('✅', message);
    notificationSystem.showNotification(message, 'success', 3000);
  }

  /**
   * Show login error
   */
  showLoginError(message) {
    this.elements.loginError.textContent = message;
    this.elements.loginError.classList.add('show');
    
    setTimeout(() => {
      this.elements.loginError.classList.remove('show');
    }, 5000);
  }

  /**
   * Perform security checks
   */
  performSecurityChecks() {
    const status = cryptoManager.getSecurityStatus();
    
    // Update security indicators
    this.elements.cryptoStatus.textContent = status.isSecure ? '🔐 Cifrado: AES-256' : '⚠️ Cifrado: No disponible';
    this.elements.storageStatus.textContent = '🏠 Local';
    this.updateNetworkStatus();
    
    // Display detailed security checks
    const checksHtml = Object.entries(status)
      .map(([key, value]) => `<div>${key}: ${value ? '✅' : '❌'}</div>`)
      .join('');
    
    this.elements.securityChecks.innerHTML = checksHtml;
    
    if (!status.isSecure) {
      this.showError('Security warning: Web Crypto API not available. Please use HTTPS or localhost.');
    }
  }

  /**
   * Update network status indicator
   */
  updateNetworkStatus() {
    const isOnline = navigator.onLine;
    this.elements.networkStatus.textContent = isOnline ? '📡 Online ⚠️' : '📡 Offline ✅';
    this.elements.networkStatus.className = `indicator ${isOnline ? 'warning' : 'secure'}`;
  }

  /**
   * Start security monitoring
   */
  startSecurityMonitoring() {
    this.securityCheckInterval = setInterval(() => {
      this.performSecurityChecks();
    }, 30000); // Check every 30 seconds
  }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  const app = new Personal2FAApp();
  app.init();
  
  // Make app globally available for debugging
  window.app = app;
  window.Personal2FA = app;
});

})();


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
