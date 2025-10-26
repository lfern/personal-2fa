/**
 * Secure Local Storage Module
 * Uses IndexedDB for persistent encrypted storage
 * All TOTP secrets and configuration are encrypted before storage
 */

import { cryptoManager } from './crypto.js';
import logger from './logger.js';

export class SecureStorage {
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
      const request = indexedDB.open(this.dbName, this.dbVersion);
      
      request.onerror = () => reject(new Error('Failed to open IndexedDB'));
      
      request.onsuccess = (event) => {
        this.db = event.target.result;
        this.isInitialized = true;
        resolve();
      };
      
      request.onupgradeneeded = (event) => {
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
export const storageManager = new SecureStorage();