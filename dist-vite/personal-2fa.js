(function polyfill() {
  const relList = document.createElement("link").relList;
  if (relList && relList.supports && relList.supports("modulepreload")) {
    return;
  }
  for (const link of document.querySelectorAll('link[rel="modulepreload"]')) {
    processPreload(link);
  }
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type !== "childList") {
        continue;
      }
      for (const node of mutation.addedNodes) {
        if (node.tagName === "LINK" && node.rel === "modulepreload")
          processPreload(node);
      }
    }
  }).observe(document, { childList: true, subtree: true });
  function getFetchOpts(link) {
    const fetchOpts = {};
    if (link.integrity) fetchOpts.integrity = link.integrity;
    if (link.referrerPolicy) fetchOpts.referrerPolicy = link.referrerPolicy;
    if (link.crossOrigin === "use-credentials")
      fetchOpts.credentials = "include";
    else if (link.crossOrigin === "anonymous") fetchOpts.credentials = "omit";
    else fetchOpts.credentials = "same-origin";
    return fetchOpts;
  }
  function processPreload(link) {
    if (link.ep)
      return;
    link.ep = true;
    const fetchOpts = getFetchOpts(link);
    fetch(link.href, fetchOpts);
  }
})();
class SecureCrypto {
  constructor() {
    this.algorithm = "AES-GCM";
    this.keyLength = 256;
    this.ivLength = 12;
    this.tagLength = 128;
    this.iterations = 1e5;
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
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: this.iterations,
        hash: "SHA-256"
      },
      baseKey,
      {
        name: this.algorithm,
        length: this.keyLength
      },
      false,
      ["encrypt", "decrypt"]
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
    const iv = this.generateRandomBytes(this.ivLength);
    const encrypted = await crypto.subtle.encrypt(
      {
        name: this.algorithm,
        iv,
        tagLength: this.tagLength
      },
      key,
      data
    );
    return {
      ciphertext: new Uint8Array(encrypted),
      iv
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
        iv,
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
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
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
    if (typeof sensitiveData === "string") {
      sensitiveData = null;
    } else if (sensitiveData instanceof Uint8Array || Array.isArray(sensitiveData)) {
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
      httpsOrLocalhost: window.location.protocol === "https:" || window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1",
      randomAvailable: !!window.crypto?.getRandomValues
    };
    status.isSecure = status.webCryptoAvailable && status.secureContext && status.randomAvailable;
    return status;
  }
}
const cryptoManager = new SecureCrypto();
class SecureStorage {
  constructor() {
    this.dbName = "Personal2FA";
    this.dbVersion = 1;
    this.storeName = "secrets";
    this.configStore = "config";
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
      request.onerror = () => reject(new Error("Failed to open IndexedDB"));
      request.onsuccess = (event) => {
        this.db = event.target.result;
        this.isInitialized = true;
        resolve();
      };
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          const secretsStore = db.createObjectStore(this.storeName, {
            keyPath: "id",
            autoIncrement: true
          });
          secretsStore.createIndex("issuer", "issuer", { unique: false });
          secretsStore.createIndex("label", "label", { unique: false });
        }
        if (!db.objectStoreNames.contains(this.configStore)) {
          db.createObjectStore(this.configStore, { keyPath: "key" });
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
    const salt = cryptoManager.generateRandomBytes(32);
    await this.setConfig("salt", cryptoManager.bytesToBase64(salt));
    this.encryptionKey = await cryptoManager.deriveKey(password, salt);
    const passwordHash = await cryptoManager.hash(password);
    await this.setConfig("passwordHash", passwordHash);
    await this.setConfig("isSetup", true);
  }
  /**
   * Unlock storage with master password
   * @param {string} password - Master password
   * @returns {Promise<boolean>} True if password is correct
   */
  async unlock(password) {
    const storedHash = await this.getConfig("passwordHash");
    const passwordHash = await cryptoManager.hash(password);
    if (storedHash !== passwordHash) {
      return false;
    }
    const saltBase64 = await this.getConfig("salt");
    const salt = cryptoManager.base64ToBytes(saltBase64);
    this.encryptionKey = await cryptoManager.deriveKey(password, salt);
    return true;
  }
  /**
   * Check if storage is already setup
   * @returns {Promise<boolean>}
   */
  async isSetup() {
    const setup = await this.getConfig("isSetup");
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
      throw new Error("Storage is locked. Unlock with master password first.");
    }
    const secretJson = JSON.stringify({
      secret: totpData.secret,
      algorithm: totpData.algorithm || "SHA1",
      digits: totpData.digits || 6,
      period: totpData.period || 30
    });
    const encrypted = await cryptoManager.encrypt(secretJson, this.encryptionKey);
    const record = {
      issuer: totpData.issuer,
      label: totpData.label,
      encryptedSecret: cryptoManager.bytesToBase64(encrypted.ciphertext),
      iv: cryptoManager.bytesToBase64(encrypted.iv),
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      lastUsed: null
    };
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      const request = store.add(record);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("Failed to store TOTP secret"));
    });
  }
  /**
   * Retrieve all TOTP secrets (decrypted)
   * @returns {Promise<Array>} Array of TOTP configurations
   */
  async getAllTOTPSecrets() {
    if (!this.isUnlocked()) {
      throw new Error("Storage is locked. Unlock with master password first.");
    }
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], "readonly");
      const store = transaction.objectStore(this.storeName);
      const request = store.getAll();
      request.onsuccess = async () => {
        const records = request.result;
        const decryptedSecrets = [];
        for (const record of records) {
          try {
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
            console.error("Failed to decrypt TOTP secret:", error);
          }
        }
        resolve(decryptedSecrets);
      };
      request.onerror = () => reject(new Error("Failed to retrieve TOTP secrets"));
    });
  }
  /**
   * Delete TOTP secret by ID
   * @param {number} id - Secret ID
   * @returns {Promise<void>}
   */
  async deleteTOTPSecret(id) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(id);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error("Failed to delete TOTP secret"));
    });
  }
  /**
   * Update last used timestamp for TOTP secret
   * @param {number} id - Secret ID
   * @returns {Promise<void>}
   */
  async updateLastUsed(id) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      const getRequest = store.get(id);
      getRequest.onsuccess = () => {
        const record = getRequest.result;
        if (record) {
          record.lastUsed = (/* @__PURE__ */ new Date()).toISOString();
          const putRequest = store.put(record);
          putRequest.onsuccess = () => resolve();
          putRequest.onerror = () => reject(new Error("Failed to update last used"));
        } else {
          reject(new Error("TOTP secret not found"));
        }
      };
      getRequest.onerror = () => reject(new Error("Failed to find TOTP secret"));
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
      const transaction = this.db.transaction([this.configStore], "readwrite");
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
      const transaction = this.db.transaction([this.configStore], "readonly");
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
      const transaction = this.db.transaction([this.storeName, this.configStore], "readwrite");
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
        reject(new Error("Failed to clear data"));
      };
    });
  }
  /**
   * Get storage statistics
   * @returns {Promise<Object>} Storage stats
   */
  async getStats() {
    const secretCount = await new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], "readonly");
      const store = transaction.objectStore(this.storeName);
      const request = store.count();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("Failed to count secrets"));
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
    if ("estimate" in navigator.storage) {
      const estimate = await navigator.storage.estimate();
      return estimate.usage || 0;
    }
    return 0;
  }
}
const storageManager = new SecureStorage();
class TOTPGenerator {
  constructor() {
    this.defaultAlgorithm = "SHA1";
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
    const timeCounter = Math.floor(timestamp / 1e3 / period);
    const code = await this.generateHOTP(secret, timeCounter, { algorithm, digits });
    const currentPeriodStart = timeCounter * period * 1e3;
    const nextPeriodStart = currentPeriodStart + period * 1e3;
    const timeRemaining = Math.ceil((nextPeriodStart - timestamp) / 1e3);
    const progress = (timestamp - currentPeriodStart) / (period * 1e3) * 100;
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
    const secretBytes = this.base32Decode(secret);
    const counterBytes = new ArrayBuffer(8);
    const counterView = new DataView(counterBytes);
    counterView.setUint32(4, counter, false);
    const key = await crypto.subtle.importKey(
      "raw",
      secretBytes,
      { name: "HMAC", hash: `SHA-${this.getHashSize(algorithm)}` },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, counterBytes);
    const hmac = new Uint8Array(signature);
    const offset = hmac[hmac.length - 1] & 15;
    const truncated = ((hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255) >>> 0;
    const code = (truncated % Math.pow(10, digits)).toString().padStart(digits, "0");
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
      window: window2 = 1,
      // Allow 1 period before/after current
      timestamp = Date.now()
    } = options;
    const currentCounter = Math.floor(timestamp / 1e3 / period);
    for (let i = -window2; i <= window2; i++) {
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
      if (url.protocol !== "otpauth:") {
        throw new Error("Invalid protocol. Expected otpauth://");
      }
      const type = url.hostname.toLowerCase();
      if (type !== "totp" && type !== "hotp") {
        throw new Error("Unsupported OTP type. Expected totp or hotp");
      }
      const label = decodeURIComponent(url.pathname.substring(1));
      let issuer = "";
      let account = label;
      const colonIndex = label.indexOf(":");
      if (colonIndex !== -1) {
        issuer = label.substring(0, colonIndex);
        account = label.substring(colonIndex + 1);
      }
      const params = new URLSearchParams(url.search);
      const secret = params.get("secret");
      const issuerParam = params.get("issuer");
      const algorithm = params.get("algorithm") || "SHA1";
      const digits = parseInt(params.get("digits")) || 6;
      const period = parseInt(params.get("period")) || 30;
      const counter = params.get("counter");
      if (!secret) {
        throw new Error("Secret parameter is required");
      }
      if (!this.isValidBase32(secret)) {
        throw new Error("Invalid Base32 secret");
      }
      return {
        type,
        issuer: issuerParam || issuer,
        label: account,
        secret: secret.toUpperCase().replace(/\s/g, ""),
        // Normalize
        algorithm: algorithm.toUpperCase(),
        digits,
        period: type === "totp" ? period : void 0,
        counter: type === "hotp" ? parseInt(counter) || 0 : void 0
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
      algorithm = "SHA1",
      digits = 6,
      period = 30,
      type = "totp"
    } = config;
    if (!secret || !label) {
      throw new Error("Secret and label are required");
    }
    const fullLabel = issuer ? `${issuer}:${label}` : label;
    const uri = new URL(`otpauth://${type}/${encodeURIComponent(fullLabel)}`);
    uri.searchParams.set("secret", secret.toUpperCase().replace(/\s/g, ""));
    if (issuer) {
      uri.searchParams.set("issuer", issuer);
    }
    if (algorithm !== "SHA1") {
      uri.searchParams.set("algorithm", algorithm);
    }
    if (digits !== 6) {
      uri.searchParams.set("digits", digits.toString());
    }
    if (type === "totp" && period !== 30) {
      uri.searchParams.set("period", period.toString());
    }
    return uri.toString();
  }
  /**
   * Decode Base32 string to bytes
   * @param {string} base32 - Base32 encoded string
   * @returns {Uint8Array} Decoded bytes
   */
  base32Decode(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const cleanInput = base32.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = "";
    for (const char of cleanInput) {
      const index = alphabet.indexOf(char);
      if (index === -1) {
        throw new Error(`Invalid Base32 character: ${char}`);
      }
      bits += index.toString(2).padStart(5, "0");
    }
    const bytes = [];
    for (let i = 0; i < bits.length - 4; i += 8) {
      const byte2 = bits.substring(i, i + 8);
      if (byte2.length === 8) {
        bytes.push(parseInt(byte2, 2));
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
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const byte2 of bytes) {
      bits += byte2.toString(2).padStart(8, "0");
    }
    while (bits.length % 5 !== 0) {
      bits += "0";
    }
    let result = "";
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
    const cleanInput = base32.toUpperCase().replace(/\s/g, "");
    return /^[A-Z2-7]*$/.test(cleanInput);
  }
  /**
   * Get hash size for algorithm
   * @param {string} algorithm - Hash algorithm
   * @returns {number} Hash size
   */
  getHashSize(algorithm) {
    switch (algorithm.toUpperCase()) {
      case "SHA1":
        return 1;
      case "SHA256":
        return 256;
      case "SHA512":
        return 512;
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
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
const totpGenerator = new TOTPGenerator();
var browser = {};
var canPromise$1 = function() {
  return typeof Promise === "function" && Promise.prototype && Promise.prototype.then;
};
var qrcode = {};
var utils$1 = {};
let toSJISFunction;
const CODEWORDS_COUNT = [
  0,
  // Not used
  26,
  44,
  70,
  100,
  134,
  172,
  196,
  242,
  292,
  346,
  404,
  466,
  532,
  581,
  655,
  733,
  815,
  901,
  991,
  1085,
  1156,
  1258,
  1364,
  1474,
  1588,
  1706,
  1828,
  1921,
  2051,
  2185,
  2323,
  2465,
  2611,
  2761,
  2876,
  3034,
  3196,
  3362,
  3532,
  3706
];
utils$1.getSymbolSize = function getSymbolSize(version2) {
  if (!version2) throw new Error('"version" cannot be null or undefined');
  if (version2 < 1 || version2 > 40) throw new Error('"version" should be in range from 1 to 40');
  return version2 * 4 + 17;
};
utils$1.getSymbolTotalCodewords = function getSymbolTotalCodewords(version2) {
  return CODEWORDS_COUNT[version2];
};
utils$1.getBCHDigit = function(data) {
  let digit = 0;
  while (data !== 0) {
    digit++;
    data >>>= 1;
  }
  return digit;
};
utils$1.setToSJISFunction = function setToSJISFunction(f) {
  if (typeof f !== "function") {
    throw new Error('"toSJISFunc" is not a valid function.');
  }
  toSJISFunction = f;
};
utils$1.isKanjiModeEnabled = function() {
  return typeof toSJISFunction !== "undefined";
};
utils$1.toSJIS = function toSJIS(kanji2) {
  return toSJISFunction(kanji2);
};
var errorCorrectionLevel = {};
(function(exports) {
  exports.L = { bit: 1 };
  exports.M = { bit: 0 };
  exports.Q = { bit: 3 };
  exports.H = { bit: 2 };
  function fromString(string) {
    if (typeof string !== "string") {
      throw new Error("Param is not a string");
    }
    const lcStr = string.toLowerCase();
    switch (lcStr) {
      case "l":
      case "low":
        return exports.L;
      case "m":
      case "medium":
        return exports.M;
      case "q":
      case "quartile":
        return exports.Q;
      case "h":
      case "high":
        return exports.H;
      default:
        throw new Error("Unknown EC Level: " + string);
    }
  }
  exports.isValid = function isValid2(level) {
    return level && typeof level.bit !== "undefined" && level.bit >= 0 && level.bit < 4;
  };
  exports.from = function from(value, defaultValue) {
    if (exports.isValid(value)) {
      return value;
    }
    try {
      return fromString(value);
    } catch (e) {
      return defaultValue;
    }
  };
})(errorCorrectionLevel);
function BitBuffer$1() {
  this.buffer = [];
  this.length = 0;
}
BitBuffer$1.prototype = {
  get: function(index) {
    const bufIndex = Math.floor(index / 8);
    return (this.buffer[bufIndex] >>> 7 - index % 8 & 1) === 1;
  },
  put: function(num, length) {
    for (let i = 0; i < length; i++) {
      this.putBit((num >>> length - i - 1 & 1) === 1);
    }
  },
  getLengthInBits: function() {
    return this.length;
  },
  putBit: function(bit) {
    const bufIndex = Math.floor(this.length / 8);
    if (this.buffer.length <= bufIndex) {
      this.buffer.push(0);
    }
    if (bit) {
      this.buffer[bufIndex] |= 128 >>> this.length % 8;
    }
    this.length++;
  }
};
var bitBuffer = BitBuffer$1;
function BitMatrix$1(size) {
  if (!size || size < 1) {
    throw new Error("BitMatrix size must be defined and greater than 0");
  }
  this.size = size;
  this.data = new Uint8Array(size * size);
  this.reservedBit = new Uint8Array(size * size);
}
BitMatrix$1.prototype.set = function(row, col, value, reserved) {
  const index = row * this.size + col;
  this.data[index] = value;
  if (reserved) this.reservedBit[index] = true;
};
BitMatrix$1.prototype.get = function(row, col) {
  return this.data[row * this.size + col];
};
BitMatrix$1.prototype.xor = function(row, col, value) {
  this.data[row * this.size + col] ^= value;
};
BitMatrix$1.prototype.isReserved = function(row, col) {
  return this.reservedBit[row * this.size + col];
};
var bitMatrix = BitMatrix$1;
var alignmentPattern = {};
(function(exports) {
  const getSymbolSize3 = utils$1.getSymbolSize;
  exports.getRowColCoords = function getRowColCoords(version2) {
    if (version2 === 1) return [];
    const posCount = Math.floor(version2 / 7) + 2;
    const size = getSymbolSize3(version2);
    const intervals = size === 145 ? 26 : Math.ceil((size - 13) / (2 * posCount - 2)) * 2;
    const positions = [size - 7];
    for (let i = 1; i < posCount - 1; i++) {
      positions[i] = positions[i - 1] - intervals;
    }
    positions.push(6);
    return positions.reverse();
  };
  exports.getPositions = function getPositions2(version2) {
    const coords = [];
    const pos = exports.getRowColCoords(version2);
    const posLength = pos.length;
    for (let i = 0; i < posLength; i++) {
      for (let j = 0; j < posLength; j++) {
        if (i === 0 && j === 0 || // top-left
        i === 0 && j === posLength - 1 || // bottom-left
        i === posLength - 1 && j === 0) {
          continue;
        }
        coords.push([pos[i], pos[j]]);
      }
    }
    return coords;
  };
})(alignmentPattern);
var finderPattern = {};
const getSymbolSize2 = utils$1.getSymbolSize;
const FINDER_PATTERN_SIZE = 7;
finderPattern.getPositions = function getPositions(version2) {
  const size = getSymbolSize2(version2);
  return [
    // top-left
    [0, 0],
    // top-right
    [size - FINDER_PATTERN_SIZE, 0],
    // bottom-left
    [0, size - FINDER_PATTERN_SIZE]
  ];
};
var maskPattern = {};
(function(exports) {
  exports.Patterns = {
    PATTERN000: 0,
    PATTERN001: 1,
    PATTERN010: 2,
    PATTERN011: 3,
    PATTERN100: 4,
    PATTERN101: 5,
    PATTERN110: 6,
    PATTERN111: 7
  };
  const PenaltyScores = {
    N1: 3,
    N2: 3,
    N3: 40,
    N4: 10
  };
  exports.isValid = function isValid2(mask) {
    return mask != null && mask !== "" && !isNaN(mask) && mask >= 0 && mask <= 7;
  };
  exports.from = function from(value) {
    return exports.isValid(value) ? parseInt(value, 10) : void 0;
  };
  exports.getPenaltyN1 = function getPenaltyN1(data) {
    const size = data.size;
    let points = 0;
    let sameCountCol = 0;
    let sameCountRow = 0;
    let lastCol = null;
    let lastRow = null;
    for (let row = 0; row < size; row++) {
      sameCountCol = sameCountRow = 0;
      lastCol = lastRow = null;
      for (let col = 0; col < size; col++) {
        let module = data.get(row, col);
        if (module === lastCol) {
          sameCountCol++;
        } else {
          if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
          lastCol = module;
          sameCountCol = 1;
        }
        module = data.get(col, row);
        if (module === lastRow) {
          sameCountRow++;
        } else {
          if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
          lastRow = module;
          sameCountRow = 1;
        }
      }
      if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
      if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
    }
    return points;
  };
  exports.getPenaltyN2 = function getPenaltyN2(data) {
    const size = data.size;
    let points = 0;
    for (let row = 0; row < size - 1; row++) {
      for (let col = 0; col < size - 1; col++) {
        const last = data.get(row, col) + data.get(row, col + 1) + data.get(row + 1, col) + data.get(row + 1, col + 1);
        if (last === 4 || last === 0) points++;
      }
    }
    return points * PenaltyScores.N2;
  };
  exports.getPenaltyN3 = function getPenaltyN3(data) {
    const size = data.size;
    let points = 0;
    let bitsCol = 0;
    let bitsRow = 0;
    for (let row = 0; row < size; row++) {
      bitsCol = bitsRow = 0;
      for (let col = 0; col < size; col++) {
        bitsCol = bitsCol << 1 & 2047 | data.get(row, col);
        if (col >= 10 && (bitsCol === 1488 || bitsCol === 93)) points++;
        bitsRow = bitsRow << 1 & 2047 | data.get(col, row);
        if (col >= 10 && (bitsRow === 1488 || bitsRow === 93)) points++;
      }
    }
    return points * PenaltyScores.N3;
  };
  exports.getPenaltyN4 = function getPenaltyN4(data) {
    let darkCount = 0;
    const modulesCount = data.data.length;
    for (let i = 0; i < modulesCount; i++) darkCount += data.data[i];
    const k = Math.abs(Math.ceil(darkCount * 100 / modulesCount / 5) - 10);
    return k * PenaltyScores.N4;
  };
  function getMaskAt(maskPattern2, i, j) {
    switch (maskPattern2) {
      case exports.Patterns.PATTERN000:
        return (i + j) % 2 === 0;
      case exports.Patterns.PATTERN001:
        return i % 2 === 0;
      case exports.Patterns.PATTERN010:
        return j % 3 === 0;
      case exports.Patterns.PATTERN011:
        return (i + j) % 3 === 0;
      case exports.Patterns.PATTERN100:
        return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
      case exports.Patterns.PATTERN101:
        return i * j % 2 + i * j % 3 === 0;
      case exports.Patterns.PATTERN110:
        return (i * j % 2 + i * j % 3) % 2 === 0;
      case exports.Patterns.PATTERN111:
        return (i * j % 3 + (i + j) % 2) % 2 === 0;
      default:
        throw new Error("bad maskPattern:" + maskPattern2);
    }
  }
  exports.applyMask = function applyMask(pattern, data) {
    const size = data.size;
    for (let col = 0; col < size; col++) {
      for (let row = 0; row < size; row++) {
        if (data.isReserved(row, col)) continue;
        data.xor(row, col, getMaskAt(pattern, row, col));
      }
    }
  };
  exports.getBestMask = function getBestMask(data, setupFormatFunc) {
    const numPatterns = Object.keys(exports.Patterns).length;
    let bestPattern = 0;
    let lowerPenalty = Infinity;
    for (let p = 0; p < numPatterns; p++) {
      setupFormatFunc(p);
      exports.applyMask(p, data);
      const penalty = exports.getPenaltyN1(data) + exports.getPenaltyN2(data) + exports.getPenaltyN3(data) + exports.getPenaltyN4(data);
      exports.applyMask(p, data);
      if (penalty < lowerPenalty) {
        lowerPenalty = penalty;
        bestPattern = p;
      }
    }
    return bestPattern;
  };
})(maskPattern);
var errorCorrectionCode = {};
const ECLevel$1 = errorCorrectionLevel;
const EC_BLOCKS_TABLE = [
  // L  M  Q  H
  1,
  1,
  1,
  1,
  1,
  1,
  1,
  1,
  1,
  1,
  2,
  2,
  1,
  2,
  2,
  4,
  1,
  2,
  4,
  4,
  2,
  4,
  4,
  4,
  2,
  4,
  6,
  5,
  2,
  4,
  6,
  6,
  2,
  5,
  8,
  8,
  4,
  5,
  8,
  8,
  4,
  5,
  8,
  11,
  4,
  8,
  10,
  11,
  4,
  9,
  12,
  16,
  4,
  9,
  16,
  16,
  6,
  10,
  12,
  18,
  6,
  10,
  17,
  16,
  6,
  11,
  16,
  19,
  6,
  13,
  18,
  21,
  7,
  14,
  21,
  25,
  8,
  16,
  20,
  25,
  8,
  17,
  23,
  25,
  9,
  17,
  23,
  34,
  9,
  18,
  25,
  30,
  10,
  20,
  27,
  32,
  12,
  21,
  29,
  35,
  12,
  23,
  34,
  37,
  12,
  25,
  34,
  40,
  13,
  26,
  35,
  42,
  14,
  28,
  38,
  45,
  15,
  29,
  40,
  48,
  16,
  31,
  43,
  51,
  17,
  33,
  45,
  54,
  18,
  35,
  48,
  57,
  19,
  37,
  51,
  60,
  19,
  38,
  53,
  63,
  20,
  40,
  56,
  66,
  21,
  43,
  59,
  70,
  22,
  45,
  62,
  74,
  24,
  47,
  65,
  77,
  25,
  49,
  68,
  81
];
const EC_CODEWORDS_TABLE = [
  // L  M  Q  H
  7,
  10,
  13,
  17,
  10,
  16,
  22,
  28,
  15,
  26,
  36,
  44,
  20,
  36,
  52,
  64,
  26,
  48,
  72,
  88,
  36,
  64,
  96,
  112,
  40,
  72,
  108,
  130,
  48,
  88,
  132,
  156,
  60,
  110,
  160,
  192,
  72,
  130,
  192,
  224,
  80,
  150,
  224,
  264,
  96,
  176,
  260,
  308,
  104,
  198,
  288,
  352,
  120,
  216,
  320,
  384,
  132,
  240,
  360,
  432,
  144,
  280,
  408,
  480,
  168,
  308,
  448,
  532,
  180,
  338,
  504,
  588,
  196,
  364,
  546,
  650,
  224,
  416,
  600,
  700,
  224,
  442,
  644,
  750,
  252,
  476,
  690,
  816,
  270,
  504,
  750,
  900,
  300,
  560,
  810,
  960,
  312,
  588,
  870,
  1050,
  336,
  644,
  952,
  1110,
  360,
  700,
  1020,
  1200,
  390,
  728,
  1050,
  1260,
  420,
  784,
  1140,
  1350,
  450,
  812,
  1200,
  1440,
  480,
  868,
  1290,
  1530,
  510,
  924,
  1350,
  1620,
  540,
  980,
  1440,
  1710,
  570,
  1036,
  1530,
  1800,
  570,
  1064,
  1590,
  1890,
  600,
  1120,
  1680,
  1980,
  630,
  1204,
  1770,
  2100,
  660,
  1260,
  1860,
  2220,
  720,
  1316,
  1950,
  2310,
  750,
  1372,
  2040,
  2430
];
errorCorrectionCode.getBlocksCount = function getBlocksCount(version2, errorCorrectionLevel2) {
  switch (errorCorrectionLevel2) {
    case ECLevel$1.L:
      return EC_BLOCKS_TABLE[(version2 - 1) * 4 + 0];
    case ECLevel$1.M:
      return EC_BLOCKS_TABLE[(version2 - 1) * 4 + 1];
    case ECLevel$1.Q:
      return EC_BLOCKS_TABLE[(version2 - 1) * 4 + 2];
    case ECLevel$1.H:
      return EC_BLOCKS_TABLE[(version2 - 1) * 4 + 3];
    default:
      return void 0;
  }
};
errorCorrectionCode.getTotalCodewordsCount = function getTotalCodewordsCount(version2, errorCorrectionLevel2) {
  switch (errorCorrectionLevel2) {
    case ECLevel$1.L:
      return EC_CODEWORDS_TABLE[(version2 - 1) * 4 + 0];
    case ECLevel$1.M:
      return EC_CODEWORDS_TABLE[(version2 - 1) * 4 + 1];
    case ECLevel$1.Q:
      return EC_CODEWORDS_TABLE[(version2 - 1) * 4 + 2];
    case ECLevel$1.H:
      return EC_CODEWORDS_TABLE[(version2 - 1) * 4 + 3];
    default:
      return void 0;
  }
};
var polynomial = {};
var galoisField = {};
const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x <<= 1;
    if (x & 256) {
      x ^= 285;
    }
  }
  for (let i = 255; i < 512; i++) {
    EXP_TABLE[i] = EXP_TABLE[i - 255];
  }
})();
galoisField.log = function log(n) {
  if (n < 1) throw new Error("log(" + n + ")");
  return LOG_TABLE[n];
};
galoisField.exp = function exp(n) {
  return EXP_TABLE[n];
};
galoisField.mul = function mul(x, y) {
  if (x === 0 || y === 0) return 0;
  return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]];
};
(function(exports) {
  const GF = galoisField;
  exports.mul = function mul2(p1, p2) {
    const coeff = new Uint8Array(p1.length + p2.length - 1);
    for (let i = 0; i < p1.length; i++) {
      for (let j = 0; j < p2.length; j++) {
        coeff[i + j] ^= GF.mul(p1[i], p2[j]);
      }
    }
    return coeff;
  };
  exports.mod = function mod(divident, divisor) {
    let result = new Uint8Array(divident);
    while (result.length - divisor.length >= 0) {
      const coeff = result[0];
      for (let i = 0; i < divisor.length; i++) {
        result[i] ^= GF.mul(divisor[i], coeff);
      }
      let offset = 0;
      while (offset < result.length && result[offset] === 0) offset++;
      result = result.slice(offset);
    }
    return result;
  };
  exports.generateECPolynomial = function generateECPolynomial(degree) {
    let poly = new Uint8Array([1]);
    for (let i = 0; i < degree; i++) {
      poly = exports.mul(poly, new Uint8Array([1, GF.exp(i)]));
    }
    return poly;
  };
})(polynomial);
const Polynomial = polynomial;
function ReedSolomonEncoder$1(degree) {
  this.genPoly = void 0;
  this.degree = degree;
  if (this.degree) this.initialize(this.degree);
}
ReedSolomonEncoder$1.prototype.initialize = function initialize(degree) {
  this.degree = degree;
  this.genPoly = Polynomial.generateECPolynomial(this.degree);
};
ReedSolomonEncoder$1.prototype.encode = function encode(data) {
  if (!this.genPoly) {
    throw new Error("Encoder not initialized");
  }
  const paddedData = new Uint8Array(data.length + this.degree);
  paddedData.set(data);
  const remainder = Polynomial.mod(paddedData, this.genPoly);
  const start = this.degree - remainder.length;
  if (start > 0) {
    const buff = new Uint8Array(this.degree);
    buff.set(remainder, start);
    return buff;
  }
  return remainder;
};
var reedSolomonEncoder = ReedSolomonEncoder$1;
var version = {};
var mode = {};
var versionCheck = {};
versionCheck.isValid = function isValid(version2) {
  return !isNaN(version2) && version2 >= 1 && version2 <= 40;
};
var regex = {};
const numeric = "[0-9]+";
const alphanumeric = "[A-Z $%*+\\-./:]+";
let kanji = "(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+";
kanji = kanji.replace(/u/g, "\\u");
const byte = "(?:(?![A-Z0-9 $%*+\\-./:]|" + kanji + ")(?:.|[\r\n]))+";
regex.KANJI = new RegExp(kanji, "g");
regex.BYTE_KANJI = new RegExp("[^A-Z0-9 $%*+\\-./:]+", "g");
regex.BYTE = new RegExp(byte, "g");
regex.NUMERIC = new RegExp(numeric, "g");
regex.ALPHANUMERIC = new RegExp(alphanumeric, "g");
const TEST_KANJI = new RegExp("^" + kanji + "$");
const TEST_NUMERIC = new RegExp("^" + numeric + "$");
const TEST_ALPHANUMERIC = new RegExp("^[A-Z0-9 $%*+\\-./:]+$");
regex.testKanji = function testKanji(str) {
  return TEST_KANJI.test(str);
};
regex.testNumeric = function testNumeric(str) {
  return TEST_NUMERIC.test(str);
};
regex.testAlphanumeric = function testAlphanumeric(str) {
  return TEST_ALPHANUMERIC.test(str);
};
(function(exports) {
  const VersionCheck = versionCheck;
  const Regex = regex;
  exports.NUMERIC = {
    id: "Numeric",
    bit: 1 << 0,
    ccBits: [10, 12, 14]
  };
  exports.ALPHANUMERIC = {
    id: "Alphanumeric",
    bit: 1 << 1,
    ccBits: [9, 11, 13]
  };
  exports.BYTE = {
    id: "Byte",
    bit: 1 << 2,
    ccBits: [8, 16, 16]
  };
  exports.KANJI = {
    id: "Kanji",
    bit: 1 << 3,
    ccBits: [8, 10, 12]
  };
  exports.MIXED = {
    bit: -1
  };
  exports.getCharCountIndicator = function getCharCountIndicator(mode2, version2) {
    if (!mode2.ccBits) throw new Error("Invalid mode: " + mode2);
    if (!VersionCheck.isValid(version2)) {
      throw new Error("Invalid version: " + version2);
    }
    if (version2 >= 1 && version2 < 10) return mode2.ccBits[0];
    else if (version2 < 27) return mode2.ccBits[1];
    return mode2.ccBits[2];
  };
  exports.getBestModeForData = function getBestModeForData(dataStr) {
    if (Regex.testNumeric(dataStr)) return exports.NUMERIC;
    else if (Regex.testAlphanumeric(dataStr)) return exports.ALPHANUMERIC;
    else if (Regex.testKanji(dataStr)) return exports.KANJI;
    else return exports.BYTE;
  };
  exports.toString = function toString(mode2) {
    if (mode2 && mode2.id) return mode2.id;
    throw new Error("Invalid mode");
  };
  exports.isValid = function isValid2(mode2) {
    return mode2 && mode2.bit && mode2.ccBits;
  };
  function fromString(string) {
    if (typeof string !== "string") {
      throw new Error("Param is not a string");
    }
    const lcStr = string.toLowerCase();
    switch (lcStr) {
      case "numeric":
        return exports.NUMERIC;
      case "alphanumeric":
        return exports.ALPHANUMERIC;
      case "kanji":
        return exports.KANJI;
      case "byte":
        return exports.BYTE;
      default:
        throw new Error("Unknown mode: " + string);
    }
  }
  exports.from = function from(value, defaultValue) {
    if (exports.isValid(value)) {
      return value;
    }
    try {
      return fromString(value);
    } catch (e) {
      return defaultValue;
    }
  };
})(mode);
(function(exports) {
  const Utils2 = utils$1;
  const ECCode2 = errorCorrectionCode;
  const ECLevel2 = errorCorrectionLevel;
  const Mode2 = mode;
  const VersionCheck = versionCheck;
  const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
  const G18_BCH = Utils2.getBCHDigit(G18);
  function getBestVersionForDataLength(mode2, length, errorCorrectionLevel2) {
    for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
      if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel2, mode2)) {
        return currentVersion;
      }
    }
    return void 0;
  }
  function getReservedBitsCount(mode2, version2) {
    return Mode2.getCharCountIndicator(mode2, version2) + 4;
  }
  function getTotalBitsFromDataArray(segments2, version2) {
    let totalBits = 0;
    segments2.forEach(function(data) {
      const reservedBits = getReservedBitsCount(data.mode, version2);
      totalBits += reservedBits + data.getBitsLength();
    });
    return totalBits;
  }
  function getBestVersionForMixedData(segments2, errorCorrectionLevel2) {
    for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
      const length = getTotalBitsFromDataArray(segments2, currentVersion);
      if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel2, Mode2.MIXED)) {
        return currentVersion;
      }
    }
    return void 0;
  }
  exports.from = function from(value, defaultValue) {
    if (VersionCheck.isValid(value)) {
      return parseInt(value, 10);
    }
    return defaultValue;
  };
  exports.getCapacity = function getCapacity(version2, errorCorrectionLevel2, mode2) {
    if (!VersionCheck.isValid(version2)) {
      throw new Error("Invalid QR Code version");
    }
    if (typeof mode2 === "undefined") mode2 = Mode2.BYTE;
    const totalCodewords = Utils2.getSymbolTotalCodewords(version2);
    const ecTotalCodewords = ECCode2.getTotalCodewordsCount(version2, errorCorrectionLevel2);
    const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
    if (mode2 === Mode2.MIXED) return dataTotalCodewordsBits;
    const usableBits = dataTotalCodewordsBits - getReservedBitsCount(mode2, version2);
    switch (mode2) {
      case Mode2.NUMERIC:
        return Math.floor(usableBits / 10 * 3);
      case Mode2.ALPHANUMERIC:
        return Math.floor(usableBits / 11 * 2);
      case Mode2.KANJI:
        return Math.floor(usableBits / 13);
      case Mode2.BYTE:
      default:
        return Math.floor(usableBits / 8);
    }
  };
  exports.getBestVersionForData = function getBestVersionForData(data, errorCorrectionLevel2) {
    let seg;
    const ecl = ECLevel2.from(errorCorrectionLevel2, ECLevel2.M);
    if (Array.isArray(data)) {
      if (data.length > 1) {
        return getBestVersionForMixedData(data, ecl);
      }
      if (data.length === 0) {
        return 1;
      }
      seg = data[0];
    } else {
      seg = data;
    }
    return getBestVersionForDataLength(seg.mode, seg.getLength(), ecl);
  };
  exports.getEncodedBits = function getEncodedBits2(version2) {
    if (!VersionCheck.isValid(version2) || version2 < 7) {
      throw new Error("Invalid QR Code version");
    }
    let d = version2 << 12;
    while (Utils2.getBCHDigit(d) - G18_BCH >= 0) {
      d ^= G18 << Utils2.getBCHDigit(d) - G18_BCH;
    }
    return version2 << 12 | d;
  };
})(version);
var formatInfo = {};
const Utils$3 = utils$1;
const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
const G15_BCH = Utils$3.getBCHDigit(G15);
formatInfo.getEncodedBits = function getEncodedBits(errorCorrectionLevel2, mask) {
  const data = errorCorrectionLevel2.bit << 3 | mask;
  let d = data << 10;
  while (Utils$3.getBCHDigit(d) - G15_BCH >= 0) {
    d ^= G15 << Utils$3.getBCHDigit(d) - G15_BCH;
  }
  return (data << 10 | d) ^ G15_MASK;
};
var segments = {};
const Mode$4 = mode;
function NumericData(data) {
  this.mode = Mode$4.NUMERIC;
  this.data = data.toString();
}
NumericData.getBitsLength = function getBitsLength(length) {
  return 10 * Math.floor(length / 3) + (length % 3 ? length % 3 * 3 + 1 : 0);
};
NumericData.prototype.getLength = function getLength() {
  return this.data.length;
};
NumericData.prototype.getBitsLength = function getBitsLength2() {
  return NumericData.getBitsLength(this.data.length);
};
NumericData.prototype.write = function write(bitBuffer2) {
  let i, group, value;
  for (i = 0; i + 3 <= this.data.length; i += 3) {
    group = this.data.substr(i, 3);
    value = parseInt(group, 10);
    bitBuffer2.put(value, 10);
  }
  const remainingNum = this.data.length - i;
  if (remainingNum > 0) {
    group = this.data.substr(i);
    value = parseInt(group, 10);
    bitBuffer2.put(value, remainingNum * 3 + 1);
  }
};
var numericData = NumericData;
const Mode$3 = mode;
const ALPHA_NUM_CHARS = [
  "0",
  "1",
  "2",
  "3",
  "4",
  "5",
  "6",
  "7",
  "8",
  "9",
  "A",
  "B",
  "C",
  "D",
  "E",
  "F",
  "G",
  "H",
  "I",
  "J",
  "K",
  "L",
  "M",
  "N",
  "O",
  "P",
  "Q",
  "R",
  "S",
  "T",
  "U",
  "V",
  "W",
  "X",
  "Y",
  "Z",
  " ",
  "$",
  "%",
  "*",
  "+",
  "-",
  ".",
  "/",
  ":"
];
function AlphanumericData(data) {
  this.mode = Mode$3.ALPHANUMERIC;
  this.data = data;
}
AlphanumericData.getBitsLength = function getBitsLength3(length) {
  return 11 * Math.floor(length / 2) + 6 * (length % 2);
};
AlphanumericData.prototype.getLength = function getLength2() {
  return this.data.length;
};
AlphanumericData.prototype.getBitsLength = function getBitsLength4() {
  return AlphanumericData.getBitsLength(this.data.length);
};
AlphanumericData.prototype.write = function write2(bitBuffer2) {
  let i;
  for (i = 0; i + 2 <= this.data.length; i += 2) {
    let value = ALPHA_NUM_CHARS.indexOf(this.data[i]) * 45;
    value += ALPHA_NUM_CHARS.indexOf(this.data[i + 1]);
    bitBuffer2.put(value, 11);
  }
  if (this.data.length % 2) {
    bitBuffer2.put(ALPHA_NUM_CHARS.indexOf(this.data[i]), 6);
  }
};
var alphanumericData = AlphanumericData;
const Mode$2 = mode;
function ByteData(data) {
  this.mode = Mode$2.BYTE;
  if (typeof data === "string") {
    this.data = new TextEncoder().encode(data);
  } else {
    this.data = new Uint8Array(data);
  }
}
ByteData.getBitsLength = function getBitsLength5(length) {
  return length * 8;
};
ByteData.prototype.getLength = function getLength3() {
  return this.data.length;
};
ByteData.prototype.getBitsLength = function getBitsLength6() {
  return ByteData.getBitsLength(this.data.length);
};
ByteData.prototype.write = function(bitBuffer2) {
  for (let i = 0, l = this.data.length; i < l; i++) {
    bitBuffer2.put(this.data[i], 8);
  }
};
var byteData = ByteData;
const Mode$1 = mode;
const Utils$2 = utils$1;
function KanjiData(data) {
  this.mode = Mode$1.KANJI;
  this.data = data;
}
KanjiData.getBitsLength = function getBitsLength7(length) {
  return length * 13;
};
KanjiData.prototype.getLength = function getLength4() {
  return this.data.length;
};
KanjiData.prototype.getBitsLength = function getBitsLength8() {
  return KanjiData.getBitsLength(this.data.length);
};
KanjiData.prototype.write = function(bitBuffer2) {
  let i;
  for (i = 0; i < this.data.length; i++) {
    let value = Utils$2.toSJIS(this.data[i]);
    if (value >= 33088 && value <= 40956) {
      value -= 33088;
    } else if (value >= 57408 && value <= 60351) {
      value -= 49472;
    } else {
      throw new Error(
        "Invalid SJIS character: " + this.data[i] + "\nMake sure your charset is UTF-8"
      );
    }
    value = (value >>> 8 & 255) * 192 + (value & 255);
    bitBuffer2.put(value, 13);
  }
};
var kanjiData = KanjiData;
var dijkstra = { exports: {} };
(function(module) {
  var dijkstra2 = {
    single_source_shortest_paths: function(graph, s, d) {
      var predecessors = {};
      var costs = {};
      costs[s] = 0;
      var open = dijkstra2.PriorityQueue.make();
      open.push(s, 0);
      var closest, u, v, cost_of_s_to_u, adjacent_nodes, cost_of_e, cost_of_s_to_u_plus_cost_of_e, cost_of_s_to_v, first_visit;
      while (!open.empty()) {
        closest = open.pop();
        u = closest.value;
        cost_of_s_to_u = closest.cost;
        adjacent_nodes = graph[u] || {};
        for (v in adjacent_nodes) {
          if (adjacent_nodes.hasOwnProperty(v)) {
            cost_of_e = adjacent_nodes[v];
            cost_of_s_to_u_plus_cost_of_e = cost_of_s_to_u + cost_of_e;
            cost_of_s_to_v = costs[v];
            first_visit = typeof costs[v] === "undefined";
            if (first_visit || cost_of_s_to_v > cost_of_s_to_u_plus_cost_of_e) {
              costs[v] = cost_of_s_to_u_plus_cost_of_e;
              open.push(v, cost_of_s_to_u_plus_cost_of_e);
              predecessors[v] = u;
            }
          }
        }
      }
      if (typeof d !== "undefined" && typeof costs[d] === "undefined") {
        var msg = ["Could not find a path from ", s, " to ", d, "."].join("");
        throw new Error(msg);
      }
      return predecessors;
    },
    extract_shortest_path_from_predecessor_list: function(predecessors, d) {
      var nodes = [];
      var u = d;
      while (u) {
        nodes.push(u);
        predecessors[u];
        u = predecessors[u];
      }
      nodes.reverse();
      return nodes;
    },
    find_path: function(graph, s, d) {
      var predecessors = dijkstra2.single_source_shortest_paths(graph, s, d);
      return dijkstra2.extract_shortest_path_from_predecessor_list(
        predecessors,
        d
      );
    },
    /**
     * A very naive priority queue implementation.
     */
    PriorityQueue: {
      make: function(opts) {
        var T = dijkstra2.PriorityQueue, t = {}, key;
        opts = opts || {};
        for (key in T) {
          if (T.hasOwnProperty(key)) {
            t[key] = T[key];
          }
        }
        t.queue = [];
        t.sorter = opts.sorter || T.default_sorter;
        return t;
      },
      default_sorter: function(a, b) {
        return a.cost - b.cost;
      },
      /**
       * Add a new item to the queue and ensure the highest priority element
       * is at the front of the queue.
       */
      push: function(value, cost) {
        var item = { value, cost };
        this.queue.push(item);
        this.queue.sort(this.sorter);
      },
      /**
       * Return the highest priority element in the queue.
       */
      pop: function() {
        return this.queue.shift();
      },
      empty: function() {
        return this.queue.length === 0;
      }
    }
  };
  {
    module.exports = dijkstra2;
  }
})(dijkstra);
var dijkstraExports = dijkstra.exports;
(function(exports) {
  const Mode2 = mode;
  const NumericData2 = numericData;
  const AlphanumericData2 = alphanumericData;
  const ByteData2 = byteData;
  const KanjiData2 = kanjiData;
  const Regex = regex;
  const Utils2 = utils$1;
  const dijkstra2 = dijkstraExports;
  function getStringByteLength(str) {
    return unescape(encodeURIComponent(str)).length;
  }
  function getSegments(regex2, mode2, str) {
    const segments2 = [];
    let result;
    while ((result = regex2.exec(str)) !== null) {
      segments2.push({
        data: result[0],
        index: result.index,
        mode: mode2,
        length: result[0].length
      });
    }
    return segments2;
  }
  function getSegmentsFromString(dataStr) {
    const numSegs = getSegments(Regex.NUMERIC, Mode2.NUMERIC, dataStr);
    const alphaNumSegs = getSegments(Regex.ALPHANUMERIC, Mode2.ALPHANUMERIC, dataStr);
    let byteSegs;
    let kanjiSegs;
    if (Utils2.isKanjiModeEnabled()) {
      byteSegs = getSegments(Regex.BYTE, Mode2.BYTE, dataStr);
      kanjiSegs = getSegments(Regex.KANJI, Mode2.KANJI, dataStr);
    } else {
      byteSegs = getSegments(Regex.BYTE_KANJI, Mode2.BYTE, dataStr);
      kanjiSegs = [];
    }
    const segs = numSegs.concat(alphaNumSegs, byteSegs, kanjiSegs);
    return segs.sort(function(s1, s2) {
      return s1.index - s2.index;
    }).map(function(obj) {
      return {
        data: obj.data,
        mode: obj.mode,
        length: obj.length
      };
    });
  }
  function getSegmentBitsLength(length, mode2) {
    switch (mode2) {
      case Mode2.NUMERIC:
        return NumericData2.getBitsLength(length);
      case Mode2.ALPHANUMERIC:
        return AlphanumericData2.getBitsLength(length);
      case Mode2.KANJI:
        return KanjiData2.getBitsLength(length);
      case Mode2.BYTE:
        return ByteData2.getBitsLength(length);
    }
  }
  function mergeSegments(segs) {
    return segs.reduce(function(acc, curr) {
      const prevSeg = acc.length - 1 >= 0 ? acc[acc.length - 1] : null;
      if (prevSeg && prevSeg.mode === curr.mode) {
        acc[acc.length - 1].data += curr.data;
        return acc;
      }
      acc.push(curr);
      return acc;
    }, []);
  }
  function buildNodes(segs) {
    const nodes = [];
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      switch (seg.mode) {
        case Mode2.NUMERIC:
          nodes.push([
            seg,
            { data: seg.data, mode: Mode2.ALPHANUMERIC, length: seg.length },
            { data: seg.data, mode: Mode2.BYTE, length: seg.length }
          ]);
          break;
        case Mode2.ALPHANUMERIC:
          nodes.push([
            seg,
            { data: seg.data, mode: Mode2.BYTE, length: seg.length }
          ]);
          break;
        case Mode2.KANJI:
          nodes.push([
            seg,
            { data: seg.data, mode: Mode2.BYTE, length: getStringByteLength(seg.data) }
          ]);
          break;
        case Mode2.BYTE:
          nodes.push([
            { data: seg.data, mode: Mode2.BYTE, length: getStringByteLength(seg.data) }
          ]);
      }
    }
    return nodes;
  }
  function buildGraph(nodes, version2) {
    const table = {};
    const graph = { start: {} };
    let prevNodeIds = ["start"];
    for (let i = 0; i < nodes.length; i++) {
      const nodeGroup = nodes[i];
      const currentNodeIds = [];
      for (let j = 0; j < nodeGroup.length; j++) {
        const node = nodeGroup[j];
        const key = "" + i + j;
        currentNodeIds.push(key);
        table[key] = { node, lastCount: 0 };
        graph[key] = {};
        for (let n = 0; n < prevNodeIds.length; n++) {
          const prevNodeId = prevNodeIds[n];
          if (table[prevNodeId] && table[prevNodeId].node.mode === node.mode) {
            graph[prevNodeId][key] = getSegmentBitsLength(table[prevNodeId].lastCount + node.length, node.mode) - getSegmentBitsLength(table[prevNodeId].lastCount, node.mode);
            table[prevNodeId].lastCount += node.length;
          } else {
            if (table[prevNodeId]) table[prevNodeId].lastCount = node.length;
            graph[prevNodeId][key] = getSegmentBitsLength(node.length, node.mode) + 4 + Mode2.getCharCountIndicator(node.mode, version2);
          }
        }
      }
      prevNodeIds = currentNodeIds;
    }
    for (let n = 0; n < prevNodeIds.length; n++) {
      graph[prevNodeIds[n]].end = 0;
    }
    return { map: graph, table };
  }
  function buildSingleSegment(data, modesHint) {
    let mode2;
    const bestMode = Mode2.getBestModeForData(data);
    mode2 = Mode2.from(modesHint, bestMode);
    if (mode2 !== Mode2.BYTE && mode2.bit < bestMode.bit) {
      throw new Error('"' + data + '" cannot be encoded with mode ' + Mode2.toString(mode2) + ".\n Suggested mode is: " + Mode2.toString(bestMode));
    }
    if (mode2 === Mode2.KANJI && !Utils2.isKanjiModeEnabled()) {
      mode2 = Mode2.BYTE;
    }
    switch (mode2) {
      case Mode2.NUMERIC:
        return new NumericData2(data);
      case Mode2.ALPHANUMERIC:
        return new AlphanumericData2(data);
      case Mode2.KANJI:
        return new KanjiData2(data);
      case Mode2.BYTE:
        return new ByteData2(data);
    }
  }
  exports.fromArray = function fromArray(array) {
    return array.reduce(function(acc, seg) {
      if (typeof seg === "string") {
        acc.push(buildSingleSegment(seg, null));
      } else if (seg.data) {
        acc.push(buildSingleSegment(seg.data, seg.mode));
      }
      return acc;
    }, []);
  };
  exports.fromString = function fromString(data, version2) {
    const segs = getSegmentsFromString(data, Utils2.isKanjiModeEnabled());
    const nodes = buildNodes(segs);
    const graph = buildGraph(nodes, version2);
    const path = dijkstra2.find_path(graph.map, "start", "end");
    const optimizedSegs = [];
    for (let i = 1; i < path.length - 1; i++) {
      optimizedSegs.push(graph.table[path[i]].node);
    }
    return exports.fromArray(mergeSegments(optimizedSegs));
  };
  exports.rawSplit = function rawSplit(data) {
    return exports.fromArray(
      getSegmentsFromString(data, Utils2.isKanjiModeEnabled())
    );
  };
})(segments);
const Utils$1 = utils$1;
const ECLevel = errorCorrectionLevel;
const BitBuffer = bitBuffer;
const BitMatrix = bitMatrix;
const AlignmentPattern = alignmentPattern;
const FinderPattern = finderPattern;
const MaskPattern = maskPattern;
const ECCode = errorCorrectionCode;
const ReedSolomonEncoder = reedSolomonEncoder;
const Version = version;
const FormatInfo = formatInfo;
const Mode = mode;
const Segments = segments;
function setupFinderPattern(matrix, version2) {
  const size = matrix.size;
  const pos = FinderPattern.getPositions(version2);
  for (let i = 0; i < pos.length; i++) {
    const row = pos[i][0];
    const col = pos[i][1];
    for (let r = -1; r <= 7; r++) {
      if (row + r <= -1 || size <= row + r) continue;
      for (let c = -1; c <= 7; c++) {
        if (col + c <= -1 || size <= col + c) continue;
        if (r >= 0 && r <= 6 && (c === 0 || c === 6) || c >= 0 && c <= 6 && (r === 0 || r === 6) || r >= 2 && r <= 4 && c >= 2 && c <= 4) {
          matrix.set(row + r, col + c, true, true);
        } else {
          matrix.set(row + r, col + c, false, true);
        }
      }
    }
  }
}
function setupTimingPattern(matrix) {
  const size = matrix.size;
  for (let r = 8; r < size - 8; r++) {
    const value = r % 2 === 0;
    matrix.set(r, 6, value, true);
    matrix.set(6, r, value, true);
  }
}
function setupAlignmentPattern(matrix, version2) {
  const pos = AlignmentPattern.getPositions(version2);
  for (let i = 0; i < pos.length; i++) {
    const row = pos[i][0];
    const col = pos[i][1];
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        if (r === -2 || r === 2 || c === -2 || c === 2 || r === 0 && c === 0) {
          matrix.set(row + r, col + c, true, true);
        } else {
          matrix.set(row + r, col + c, false, true);
        }
      }
    }
  }
}
function setupVersionInfo(matrix, version2) {
  const size = matrix.size;
  const bits = Version.getEncodedBits(version2);
  let row, col, mod;
  for (let i = 0; i < 18; i++) {
    row = Math.floor(i / 3);
    col = i % 3 + size - 8 - 3;
    mod = (bits >> i & 1) === 1;
    matrix.set(row, col, mod, true);
    matrix.set(col, row, mod, true);
  }
}
function setupFormatInfo(matrix, errorCorrectionLevel2, maskPattern2) {
  const size = matrix.size;
  const bits = FormatInfo.getEncodedBits(errorCorrectionLevel2, maskPattern2);
  let i, mod;
  for (i = 0; i < 15; i++) {
    mod = (bits >> i & 1) === 1;
    if (i < 6) {
      matrix.set(i, 8, mod, true);
    } else if (i < 8) {
      matrix.set(i + 1, 8, mod, true);
    } else {
      matrix.set(size - 15 + i, 8, mod, true);
    }
    if (i < 8) {
      matrix.set(8, size - i - 1, mod, true);
    } else if (i < 9) {
      matrix.set(8, 15 - i - 1 + 1, mod, true);
    } else {
      matrix.set(8, 15 - i - 1, mod, true);
    }
  }
  matrix.set(size - 8, 8, 1, true);
}
function setupData(matrix, data) {
  const size = matrix.size;
  let inc = -1;
  let row = size - 1;
  let bitIndex = 7;
  let byteIndex = 0;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    while (true) {
      for (let c = 0; c < 2; c++) {
        if (!matrix.isReserved(row, col - c)) {
          let dark = false;
          if (byteIndex < data.length) {
            dark = (data[byteIndex] >>> bitIndex & 1) === 1;
          }
          matrix.set(row, col - c, dark);
          bitIndex--;
          if (bitIndex === -1) {
            byteIndex++;
            bitIndex = 7;
          }
        }
      }
      row += inc;
      if (row < 0 || size <= row) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}
function createData(version2, errorCorrectionLevel2, segments2) {
  const buffer = new BitBuffer();
  segments2.forEach(function(data) {
    buffer.put(data.mode.bit, 4);
    buffer.put(data.getLength(), Mode.getCharCountIndicator(data.mode, version2));
    data.write(buffer);
  });
  const totalCodewords = Utils$1.getSymbolTotalCodewords(version2);
  const ecTotalCodewords = ECCode.getTotalCodewordsCount(version2, errorCorrectionLevel2);
  const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
  if (buffer.getLengthInBits() + 4 <= dataTotalCodewordsBits) {
    buffer.put(0, 4);
  }
  while (buffer.getLengthInBits() % 8 !== 0) {
    buffer.putBit(0);
  }
  const remainingByte = (dataTotalCodewordsBits - buffer.getLengthInBits()) / 8;
  for (let i = 0; i < remainingByte; i++) {
    buffer.put(i % 2 ? 17 : 236, 8);
  }
  return createCodewords(buffer, version2, errorCorrectionLevel2);
}
function createCodewords(bitBuffer2, version2, errorCorrectionLevel2) {
  const totalCodewords = Utils$1.getSymbolTotalCodewords(version2);
  const ecTotalCodewords = ECCode.getTotalCodewordsCount(version2, errorCorrectionLevel2);
  const dataTotalCodewords = totalCodewords - ecTotalCodewords;
  const ecTotalBlocks = ECCode.getBlocksCount(version2, errorCorrectionLevel2);
  const blocksInGroup2 = totalCodewords % ecTotalBlocks;
  const blocksInGroup1 = ecTotalBlocks - blocksInGroup2;
  const totalCodewordsInGroup1 = Math.floor(totalCodewords / ecTotalBlocks);
  const dataCodewordsInGroup1 = Math.floor(dataTotalCodewords / ecTotalBlocks);
  const dataCodewordsInGroup2 = dataCodewordsInGroup1 + 1;
  const ecCount = totalCodewordsInGroup1 - dataCodewordsInGroup1;
  const rs = new ReedSolomonEncoder(ecCount);
  let offset = 0;
  const dcData = new Array(ecTotalBlocks);
  const ecData = new Array(ecTotalBlocks);
  let maxDataSize = 0;
  const buffer = new Uint8Array(bitBuffer2.buffer);
  for (let b = 0; b < ecTotalBlocks; b++) {
    const dataSize = b < blocksInGroup1 ? dataCodewordsInGroup1 : dataCodewordsInGroup2;
    dcData[b] = buffer.slice(offset, offset + dataSize);
    ecData[b] = rs.encode(dcData[b]);
    offset += dataSize;
    maxDataSize = Math.max(maxDataSize, dataSize);
  }
  const data = new Uint8Array(totalCodewords);
  let index = 0;
  let i, r;
  for (i = 0; i < maxDataSize; i++) {
    for (r = 0; r < ecTotalBlocks; r++) {
      if (i < dcData[r].length) {
        data[index++] = dcData[r][i];
      }
    }
  }
  for (i = 0; i < ecCount; i++) {
    for (r = 0; r < ecTotalBlocks; r++) {
      data[index++] = ecData[r][i];
    }
  }
  return data;
}
function createSymbol(data, version2, errorCorrectionLevel2, maskPattern2) {
  let segments2;
  if (Array.isArray(data)) {
    segments2 = Segments.fromArray(data);
  } else if (typeof data === "string") {
    let estimatedVersion = version2;
    if (!estimatedVersion) {
      const rawSegments = Segments.rawSplit(data);
      estimatedVersion = Version.getBestVersionForData(rawSegments, errorCorrectionLevel2);
    }
    segments2 = Segments.fromString(data, estimatedVersion || 40);
  } else {
    throw new Error("Invalid data");
  }
  const bestVersion = Version.getBestVersionForData(segments2, errorCorrectionLevel2);
  if (!bestVersion) {
    throw new Error("The amount of data is too big to be stored in a QR Code");
  }
  if (!version2) {
    version2 = bestVersion;
  } else if (version2 < bestVersion) {
    throw new Error(
      "\nThe chosen QR Code version cannot contain this amount of data.\nMinimum version required to store current data is: " + bestVersion + ".\n"
    );
  }
  const dataBits = createData(version2, errorCorrectionLevel2, segments2);
  const moduleCount = Utils$1.getSymbolSize(version2);
  const modules = new BitMatrix(moduleCount);
  setupFinderPattern(modules, version2);
  setupTimingPattern(modules);
  setupAlignmentPattern(modules, version2);
  setupFormatInfo(modules, errorCorrectionLevel2, 0);
  if (version2 >= 7) {
    setupVersionInfo(modules, version2);
  }
  setupData(modules, dataBits);
  if (isNaN(maskPattern2)) {
    maskPattern2 = MaskPattern.getBestMask(
      modules,
      setupFormatInfo.bind(null, modules, errorCorrectionLevel2)
    );
  }
  MaskPattern.applyMask(maskPattern2, modules);
  setupFormatInfo(modules, errorCorrectionLevel2, maskPattern2);
  return {
    modules,
    version: version2,
    errorCorrectionLevel: errorCorrectionLevel2,
    maskPattern: maskPattern2,
    segments: segments2
  };
}
qrcode.create = function create(data, options) {
  if (typeof data === "undefined" || data === "") {
    throw new Error("No input text");
  }
  let errorCorrectionLevel2 = ECLevel.M;
  let version2;
  let mask;
  if (typeof options !== "undefined") {
    errorCorrectionLevel2 = ECLevel.from(options.errorCorrectionLevel, ECLevel.M);
    version2 = Version.from(options.version);
    mask = MaskPattern.from(options.maskPattern);
    if (options.toSJISFunc) {
      Utils$1.setToSJISFunction(options.toSJISFunc);
    }
  }
  return createSymbol(data, version2, errorCorrectionLevel2, mask);
};
var canvas = {};
var utils = {};
(function(exports) {
  function hex2rgba(hex) {
    if (typeof hex === "number") {
      hex = hex.toString();
    }
    if (typeof hex !== "string") {
      throw new Error("Color should be defined as hex string");
    }
    let hexCode = hex.slice().replace("#", "").split("");
    if (hexCode.length < 3 || hexCode.length === 5 || hexCode.length > 8) {
      throw new Error("Invalid hex color: " + hex);
    }
    if (hexCode.length === 3 || hexCode.length === 4) {
      hexCode = Array.prototype.concat.apply([], hexCode.map(function(c) {
        return [c, c];
      }));
    }
    if (hexCode.length === 6) hexCode.push("F", "F");
    const hexValue = parseInt(hexCode.join(""), 16);
    return {
      r: hexValue >> 24 & 255,
      g: hexValue >> 16 & 255,
      b: hexValue >> 8 & 255,
      a: hexValue & 255,
      hex: "#" + hexCode.slice(0, 6).join("")
    };
  }
  exports.getOptions = function getOptions(options) {
    if (!options) options = {};
    if (!options.color) options.color = {};
    const margin = typeof options.margin === "undefined" || options.margin === null || options.margin < 0 ? 4 : options.margin;
    const width = options.width && options.width >= 21 ? options.width : void 0;
    const scale = options.scale || 4;
    return {
      width,
      scale: width ? 4 : scale,
      margin,
      color: {
        dark: hex2rgba(options.color.dark || "#000000ff"),
        light: hex2rgba(options.color.light || "#ffffffff")
      },
      type: options.type,
      rendererOpts: options.rendererOpts || {}
    };
  };
  exports.getScale = function getScale(qrSize, opts) {
    return opts.width && opts.width >= qrSize + opts.margin * 2 ? opts.width / (qrSize + opts.margin * 2) : opts.scale;
  };
  exports.getImageWidth = function getImageWidth(qrSize, opts) {
    const scale = exports.getScale(qrSize, opts);
    return Math.floor((qrSize + opts.margin * 2) * scale);
  };
  exports.qrToImageData = function qrToImageData(imgData, qr, opts) {
    const size = qr.modules.size;
    const data = qr.modules.data;
    const scale = exports.getScale(size, opts);
    const symbolSize = Math.floor((size + opts.margin * 2) * scale);
    const scaledMargin = opts.margin * scale;
    const palette = [opts.color.light, opts.color.dark];
    for (let i = 0; i < symbolSize; i++) {
      for (let j = 0; j < symbolSize; j++) {
        let posDst = (i * symbolSize + j) * 4;
        let pxColor = opts.color.light;
        if (i >= scaledMargin && j >= scaledMargin && i < symbolSize - scaledMargin && j < symbolSize - scaledMargin) {
          const iSrc = Math.floor((i - scaledMargin) / scale);
          const jSrc = Math.floor((j - scaledMargin) / scale);
          pxColor = palette[data[iSrc * size + jSrc] ? 1 : 0];
        }
        imgData[posDst++] = pxColor.r;
        imgData[posDst++] = pxColor.g;
        imgData[posDst++] = pxColor.b;
        imgData[posDst] = pxColor.a;
      }
    }
  };
})(utils);
(function(exports) {
  const Utils2 = utils;
  function clearCanvas(ctx, canvas2, size) {
    ctx.clearRect(0, 0, canvas2.width, canvas2.height);
    if (!canvas2.style) canvas2.style = {};
    canvas2.height = size;
    canvas2.width = size;
    canvas2.style.height = size + "px";
    canvas2.style.width = size + "px";
  }
  function getCanvasElement() {
    try {
      return document.createElement("canvas");
    } catch (e) {
      throw new Error("You need to specify a canvas element");
    }
  }
  exports.render = function render2(qrData, canvas2, options) {
    let opts = options;
    let canvasEl = canvas2;
    if (typeof opts === "undefined" && (!canvas2 || !canvas2.getContext)) {
      opts = canvas2;
      canvas2 = void 0;
    }
    if (!canvas2) {
      canvasEl = getCanvasElement();
    }
    opts = Utils2.getOptions(opts);
    const size = Utils2.getImageWidth(qrData.modules.size, opts);
    const ctx = canvasEl.getContext("2d");
    const image = ctx.createImageData(size, size);
    Utils2.qrToImageData(image.data, qrData, opts);
    clearCanvas(ctx, canvasEl, size);
    ctx.putImageData(image, 0, 0);
    return canvasEl;
  };
  exports.renderToDataURL = function renderToDataURL(qrData, canvas2, options) {
    let opts = options;
    if (typeof opts === "undefined" && (!canvas2 || !canvas2.getContext)) {
      opts = canvas2;
      canvas2 = void 0;
    }
    if (!opts) opts = {};
    const canvasEl = exports.render(qrData, canvas2, opts);
    const type = opts.type || "image/png";
    const rendererOpts = opts.rendererOpts || {};
    return canvasEl.toDataURL(type, rendererOpts.quality);
  };
})(canvas);
var svgTag = {};
const Utils = utils;
function getColorAttrib(color, attrib) {
  const alpha = color.a / 255;
  const str = attrib + '="' + color.hex + '"';
  return alpha < 1 ? str + " " + attrib + '-opacity="' + alpha.toFixed(2).slice(1) + '"' : str;
}
function svgCmd(cmd, x, y) {
  let str = cmd + x;
  if (typeof y !== "undefined") str += " " + y;
  return str;
}
function qrToPath(data, size, margin) {
  let path = "";
  let moveBy = 0;
  let newRow = false;
  let lineLength = 0;
  for (let i = 0; i < data.length; i++) {
    const col = Math.floor(i % size);
    const row = Math.floor(i / size);
    if (!col && !newRow) newRow = true;
    if (data[i]) {
      lineLength++;
      if (!(i > 0 && col > 0 && data[i - 1])) {
        path += newRow ? svgCmd("M", col + margin, 0.5 + row + margin) : svgCmd("m", moveBy, 0);
        moveBy = 0;
        newRow = false;
      }
      if (!(col + 1 < size && data[i + 1])) {
        path += svgCmd("h", lineLength);
        lineLength = 0;
      }
    } else {
      moveBy++;
    }
  }
  return path;
}
svgTag.render = function render(qrData, options, cb) {
  const opts = Utils.getOptions(options);
  const size = qrData.modules.size;
  const data = qrData.modules.data;
  const qrcodesize = size + opts.margin * 2;
  const bg = !opts.color.light.a ? "" : "<path " + getColorAttrib(opts.color.light, "fill") + ' d="M0 0h' + qrcodesize + "v" + qrcodesize + 'H0z"/>';
  const path = "<path " + getColorAttrib(opts.color.dark, "stroke") + ' d="' + qrToPath(data, size, opts.margin) + '"/>';
  const viewBox = 'viewBox="0 0 ' + qrcodesize + " " + qrcodesize + '"';
  const width = !opts.width ? "" : 'width="' + opts.width + '" height="' + opts.width + '" ';
  const svgTag2 = '<svg xmlns="http://www.w3.org/2000/svg" ' + width + viewBox + ' shape-rendering="crispEdges">' + bg + path + "</svg>\n";
  if (typeof cb === "function") {
    cb(null, svgTag2);
  }
  return svgTag2;
};
const canPromise = canPromise$1;
const QRCode = qrcode;
const CanvasRenderer = canvas;
const SvgRenderer = svgTag;
function renderCanvas(renderFunc, canvas2, text, opts, cb) {
  const args = [].slice.call(arguments, 1);
  const argsNum = args.length;
  const isLastArgCb = typeof args[argsNum - 1] === "function";
  if (!isLastArgCb && !canPromise()) {
    throw new Error("Callback required as last argument");
  }
  if (isLastArgCb) {
    if (argsNum < 2) {
      throw new Error("Too few arguments provided");
    }
    if (argsNum === 2) {
      cb = text;
      text = canvas2;
      canvas2 = opts = void 0;
    } else if (argsNum === 3) {
      if (canvas2.getContext && typeof cb === "undefined") {
        cb = opts;
        opts = void 0;
      } else {
        cb = opts;
        opts = text;
        text = canvas2;
        canvas2 = void 0;
      }
    }
  } else {
    if (argsNum < 1) {
      throw new Error("Too few arguments provided");
    }
    if (argsNum === 1) {
      text = canvas2;
      canvas2 = opts = void 0;
    } else if (argsNum === 2 && !canvas2.getContext) {
      opts = text;
      text = canvas2;
      canvas2 = void 0;
    }
    return new Promise(function(resolve, reject) {
      try {
        const data = QRCode.create(text, opts);
        resolve(renderFunc(data, canvas2, opts));
      } catch (e) {
        reject(e);
      }
    });
  }
  try {
    const data = QRCode.create(text, opts);
    cb(null, renderFunc(data, canvas2, opts));
  } catch (e) {
    cb(e);
  }
}
browser.create = QRCode.create;
browser.toCanvas = renderCanvas.bind(null, CanvasRenderer.render);
browser.toDataURL = renderCanvas.bind(null, CanvasRenderer.renderToDataURL);
browser.toString = renderCanvas.bind(null, function(data, _, opts) {
  return SvgRenderer.render(data, opts);
});
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
    this.context = canvasElement.getContext("2d");
  }
  /**
   * Start camera and begin QR code scanning
   * @param {Function} onDetected - Callback function when QR is detected
   * @returns {Promise<void>}
   */
  async startScanning(onDetected) {
    try {
      this.onQRDetected = onDetected;
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 640 },
          height: { ideal: 480 },
          facingMode: "environment"
          // Use back camera on mobile
        }
      });
      this.video.srcObject = stream;
      this.video.play();
      await new Promise((resolve) => {
        this.video.onloadedmetadata = () => {
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
      tracks.forEach((track) => track.stop());
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
      this.context.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
      const imageData = this.context.getImageData(0, 0, this.canvas.width, this.canvas.height);
      try {
        const qrData = this.detectQRCode(imageData);
        if (qrData && this.onQRDetected) {
          this.onQRDetected(qrData);
        }
      } catch (error) {
      }
    }, 250);
  }
  /**
   * Detect QR code in image data (basic implementation)
   * In a real implementation, you would use a library like jsQR or zxing
   * @param {ImageData} imageData - Image data from canvas
   * @returns {string|null} QR code data or null if not found
   */
  detectQRCode(imageData) {
    try {
      if (!window.jsQR) {
        console.log("📱 Loading jsQR library...");
        return null;
      }
      console.log("📱 Scanning for QR code...");
      const code = window.jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        console.log("📱 QR Code detected:", code.data);
        return code.data;
      }
      return null;
    } catch (error) {
      console.error("📱 QR detection error:", error);
      return null;
    }
  }
  /**
   * Mock QR detection for development
   * Replace this with actual QR detection library
   * @returns {string|null} Mock QR data
   */
  mockQRDetection() {
    return null;
  }
  /**
   * Convert Base32 to bytes (helper for mock)
   * @param {string} base32 - Base32 string
   * @returns {Uint8Array} Decoded bytes
   */
  base32ToBytes(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const char of base32.toUpperCase()) {
      const index = alphabet.indexOf(char);
      if (index !== -1) {
        bits += index.toString(2).padStart(5, "0");
      }
    }
    const bytes = [];
    for (let i = 0; i < bits.length - 4; i += 8) {
      const byte2 = bits.substring(i, i + 8);
      if (byte2.length === 8) {
        bytes.push(parseInt(byte2, 2));
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
      errorCorrectionLevel: errorCorrectionLevel2 = "M",
      type = "image/png",
      quality = 0.92,
      margin = 1,
      color = {
        dark: "#000000",
        light: "#FFFFFF"
      },
      width = 256
    } = options;
    try {
      const qrDataUrl = await browser.toDataURL(otpauthUri, {
        errorCorrectionLevel: errorCorrectionLevel2,
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
      const migrationData = this.createMigrationPayload(totpSecrets);
      const base64Data = btoa(migrationData);
      const migrationUri = `otpauth-migration://offline?data=${base64Data}`;
      return await this.generateQRCode(migrationUri, {
        errorCorrectionLevel: "L",
        // Lower correction for larger data
        width: 400
        // Larger size for migration QR
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
    console.log("📤 Creating migration payload for", totpSecrets.length, "secrets");
    const payloadBytes = [];
    for (const secret of totpSecrets) {
      console.log("📤 Processing secret:", secret.issuer, secret.label);
      const secretBytes = this.base32ToBytes(secret.secret);
      const nameBytes = new TextEncoder().encode(secret.label);
      const issuerBytes = new TextEncoder().encode(secret.issuer || "");
      let digitsValue;
      if (secret.digits === 8) {
        digitsValue = 2;
      } else {
        digitsValue = 1;
      }
      const algorithmValue = this.algorithmToNumber(secret.algorithm);
      const otpParams = [];
      otpParams.push(10, secretBytes.length, ...secretBytes);
      otpParams.push(18, nameBytes.length, ...nameBytes);
      if (issuerBytes.length > 0) {
        otpParams.push(26, issuerBytes.length, ...issuerBytes);
      }
      otpParams.push(32, algorithmValue);
      otpParams.push(40, digitsValue);
      otpParams.push(48, 2);
      payloadBytes.push(10, otpParams.length, ...otpParams);
      console.log("📤 Encoded secret with digits:", secret.digits, "→", digitsValue);
    }
    payloadBytes.push(16, 1);
    payloadBytes.push(24, totpSecrets.length);
    payloadBytes.push(32, 0);
    const payloadString = String.fromCharCode.apply(null, payloadBytes);
    console.log("📤 Generated migration payload:", payloadBytes.length, "bytes");
    return payloadString;
  }
  /**
   * Parse Google Authenticator migration QR data
   * @param {string} migrationUri - Migration URI from QR code
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationQR(migrationUri) {
    try {
      console.log("📱 Parsing migration QR URI:", migrationUri);
      const url = new URL(migrationUri);
      console.log("🔗 URL protocol:", url.protocol);
      if (url.protocol !== "otpauth-migration:") {
        throw new Error("Invalid migration URI protocol");
      }
      const dataParam = url.searchParams.get("data");
      console.log("📊 Data parameter length:", dataParam ? dataParam.length : "null");
      console.log("📊 Data parameter (first 100 chars):", dataParam ? dataParam.substring(0, 100) : "null");
      if (!dataParam) {
        throw new Error("Missing data parameter in migration URI");
      }
      const decodedData = atob(dataParam);
      console.log("🔓 Decoded data length:", decodedData.length);
      console.log(
        "🔓 Decoded data (ALL bytes as hex):",
        Array.from(decodedData).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ")
      );
      console.log("🔓 Data parameter was:", dataParam);
      return this.parseMigrationData(decodedData);
    } catch (error) {
      console.error("❌ Migration QR parsing failed:", error);
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
      const byte2 = bytes[currentOffset++];
      value |= (byte2 & 127) << shift;
      if ((byte2 & 128) === 0) {
        return { value, newOffset: currentOffset };
      }
      shift += 7;
      if (shift >= 32) {
        throw new Error("Varint too long");
      }
    }
    throw new Error("Incomplete varint");
  }
  /**
   * Parse migration data payload
   * @param {string} data - Decoded migration data
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationData(data) {
    try {
      console.log("🔍 Parsing migration data, length:", data.length);
      const secrets = [];
      const bytes = new Uint8Array([...data].map((char) => char.charCodeAt(0)));
      console.log("🔍 Bytes array length:", bytes.length);
      console.log("🔍 ALL bytes:", Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(" "));
      console.log("🔍 Analyzing structure:");
      for (let j = 0; j < Math.min(bytes.length, 10); j++) {
        const byte2 = bytes[j];
        if ((byte2 & 7) === 2) {
          const field = byte2 >> 3;
          console.log(`  Position ${j}: Field ${field}, wire type 2 (length-delimited)`);
        }
      }
      let i = 0;
      while (i < bytes.length) {
        const tag = bytes[i++];
        const field = tag >> 3;
        const wireType = tag & 7;
        console.log(`🔍 Processing field ${field}, wire type ${wireType} at position ${i - 1}`);
        if (field === 1 && wireType === 2) {
          let length;
          if (bytes[i] < 128) {
            length = bytes[i++];
          } else {
            const lengthResult = this.readVarint(bytes, i);
            length = lengthResult.value;
            i = lengthResult.newOffset;
          }
          console.log(`🔍 OtpParameters length: ${length}, remaining bytes: ${bytes.length - i}`);
          console.log(`🔍 Available bytes for OtpParameters: ${Math.min(length, bytes.length - i)}`);
          const actualLength = Math.min(length, bytes.length - i);
          if (actualLength > 0) {
            const otpData = bytes.slice(i, i + actualLength);
            console.log(`🔍 OtpParameters data (${actualLength} bytes):`, Array.from(otpData).map((b) => b.toString(16).padStart(2, "0")).join(" "));
            const secret = this.parseOtpParameters(otpData);
            console.log(`🔍 Parsed OtpParameters result:`, secret);
            if (secret && secret.secret && secret.label) {
              secrets.push(secret);
              console.log(`✅ Successfully parsed secret: ${secret.issuer}:${secret.label}`);
            } else {
              console.log(`❌ Failed to parse valid OtpParameters - missing secret or label`);
            }
            i += actualLength;
          } else {
            console.log(`❌ No bytes available for OtpParameters`);
            break;
          }
        } else {
          console.log(`🔍 Skipping field ${field}, wire type ${wireType}`);
          if (wireType === 0) {
            while (i < bytes.length && bytes[i] >= 128) {
              i++;
            }
            if (i < bytes.length) i++;
          } else if (wireType === 2) {
            const length = bytes[i++];
            i += length;
          } else {
            i++;
          }
        }
      }
      console.log(`🔍 Successfully parsed ${secrets.length} secrets from migration data`);
      if (secrets.length === 0) {
        console.log("🔄 No secrets found, trying fallback parsing...");
        return this.parseMigrationDataFallback(data);
      }
      return secrets;
    } catch (error) {
      console.warn("❌ Migration parsing failed, trying fallback:", error);
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
      console.log("🔧 Parsing OTP parameters, data length:", data.length);
      console.log("🔧 OTP data (hex):", Array.from(data).map((b) => b.toString(16).padStart(2, "0")).join(" "));
      const params = {
        secret: "",
        label: "",
        issuer: "",
        algorithm: "SHA1",
        digits: 6,
        period: 30
      };
      let i = 0;
      while (i < data.length) {
        const tag = data[i++];
        const field = tag >> 3;
        const wireType = tag & 7;
        console.log(`🔧 Field ${field}, wireType ${wireType} at position ${i - 1}`);
        switch (field) {
          case 1:
            if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              console.log(`🔧 Secret length (varint): ${length}`);
              if (i + length <= data.length) {
                const secretBytes = data.slice(i, i + length);
                console.log("🔧 Secret bytes:", Array.from(secretBytes).map((b) => b.toString(16).padStart(2, "0")).join(" "));
                params.secret = this.bytesToBase32(secretBytes);
                console.log("🔧 Converted secret:", params.secret);
                i += length;
              }
            }
            break;
          case 2:
            if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              console.log(`🔧 Label length (varint): ${length}`);
              if (i + length <= data.length) {
                params.label = new TextDecoder().decode(data.slice(i, i + length));
                console.log("🔧 Label:", params.label);
                i += length;
              }
            }
            break;
          case 3:
            if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset;
              console.log(`🔧 Issuer length (varint): ${length}`);
              if (i + length <= data.length) {
                params.issuer = new TextDecoder().decode(data.slice(i, i + length));
                console.log("🔧 Issuer:", params.issuer);
                i += length;
              }
            }
            break;
          case 4:
            if (wireType === 0) {
              const algorithmResult = this.readVarint(data, i);
              const algorithm = algorithmResult.value;
              i = algorithmResult.newOffset;
              params.algorithm = this.numberToAlgorithm(algorithm);
              console.log("🔧 Algorithm (varint):", algorithm, "→", params.algorithm);
            }
            break;
          case 5:
            if (wireType === 0) {
              console.log("🔧 PARSING DIGITS - Position before:", i, "Byte at position:", data[i].toString(16));
              const digitsResult = this.readVarint(data, i);
              const rawDigitsValue = digitsResult.value;
              if (rawDigitsValue <= 1) {
                params.digits = 6;
              } else if (rawDigitsValue === 2) {
                params.digits = 8;
              } else {
                params.digits = 6;
              }
              i = digitsResult.newOffset;
              console.log("🔧 DIGITS RESULT - Raw value:", rawDigitsValue, "→ Interpreted as:", params.digits, "digits");
              console.log("🔧 Position after digits:", i);
            } else {
              console.log("🔧 DIGITS FIELD - Wrong wire type:", wireType, "expected 0");
            }
            break;
          default:
            console.log(`🔧 Skipping unknown field ${field}, wire type ${wireType}`);
            if (wireType === 0) {
              const skipResult = this.readVarint(data, i);
              i = skipResult.newOffset;
            } else if (wireType === 2) {
              const lengthResult = this.readVarint(data, i);
              const length = lengthResult.value;
              i = lengthResult.newOffset + length;
            } else {
              i++;
            }
        }
      }
      console.log("🔧 === FINAL PARSED PARAMS ===");
      console.log("🔧 Secret:", params.secret);
      console.log("🔧 Label:", params.label);
      console.log("🔧 Issuer:", params.issuer);
      console.log("🔧 Algorithm:", params.algorithm);
      console.log("🔧 Digits:", params.digits, typeof params.digits);
      console.log("🔧 Period:", params.period);
      const result = params.secret && params.label ? params : null;
      console.log("🔧 Returning result:", result);
      return result;
    } catch (error) {
      console.error("🔧 Error parsing OTP parameters:", error);
      return null;
    }
  }
  /**
   * Fallback parser for migration data
   * @param {string} data - Migration data
   * @returns {Array} Array of TOTP configurations
   */
  parseMigrationDataFallback(data) {
    console.log("🔄 Using fallback parser for migration data");
    const strings = data.match(/[a-zA-Z0-9@._-]{3,}/g) || [];
    console.log("🔄 Extracted strings:", strings);
    const secrets = [];
    let currentSecret = null;
    for (const str of strings) {
      if (/^[A-Z2-7]{16,}$/.test(str) && str.length >= 16) {
        if (currentSecret) {
          secrets.push(currentSecret);
        }
        currentSecret = {
          secret: str,
          label: "",
          issuer: "",
          algorithm: "SHA1",
          digits: 6,
          period: 30
        };
      } else if (str.includes("@") || str.includes(".")) {
        if (currentSecret && !currentSecret.label) {
          currentSecret.label = str;
        }
      } else if (str.length > 2 && str.length < 20 && /^[A-Za-z]/.test(str)) {
        if (currentSecret && !currentSecret.issuer) {
          currentSecret.issuer = str;
        }
      }
    }
    if (currentSecret) {
      secrets.push(currentSecret);
    }
    return secrets.filter((s) => s.secret && (s.label || s.issuer));
  }
  /**
   * Convert bytes to Base32 (for secret encoding)
   * @param {Uint8Array} bytes - Bytes to encode
   * @returns {string} Base32 string
   */
  bytesToBase32(bytes) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const byte2 of bytes) {
      bits += byte2.toString(2).padStart(8, "0");
    }
    while (bits.length % 5 !== 0) {
      bits += "0";
    }
    let result = "";
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
      case "SHA1":
        return 1;
      case "SHA256":
        return 2;
      case "SHA512":
        return 3;
      default:
        return 1;
    }
  }
  /**
   * Convert algorithm number to name (Google's format)
   * @param {number} algorithmNumber - Algorithm number
   * @returns {string} Algorithm name
   */
  numberToAlgorithm(algorithmNumber) {
    switch (algorithmNumber) {
      case 1:
        return "SHA1";
      case 2:
        return "SHA256";
      case 3:
        return "SHA512";
      default:
        return "SHA1";
    }
  }
  /**
   * Check if camera is available
   * @returns {Promise<boolean>} True if camera is available
   */
  async isCameraAvailable() {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.some((device) => device.kind === "videoinput");
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
      const permission = await navigator.permissions.query({ name: "camera" });
      return permission.state;
    } catch (error) {
      return "unknown";
    }
  }
}
const qrManager = new QRManager();
class GoogleAuthManager {
  constructor() {
    this.exportedSecrets = [];
  }
  /**
   * Import TOTP secrets from Google Authenticator migration QR
   * @param {string} migrationUri - Migration URI from QR scan
   * @returns {Promise<Array>} Array of imported TOTP configurations
   */
  async importFromGoogleAuth(migrationUri) {
    try {
      console.log("🔄 Importing from Google Authenticator...");
      console.log("🔄 Migration URI:", migrationUri);
      const secrets = qrManager.parseMigrationQR(migrationUri);
      console.log("🔄 Parsed secrets from QR manager:", secrets);
      if (!secrets || secrets.length === 0) {
        console.error("❌ No secrets found - parsed result:", secrets);
        throw new Error("No TOTP secrets found in migration data");
      }
      console.log(`✅ Found ${secrets.length} TOTP secrets to import`);
      const validatedSecrets = [];
      for (const secret of secrets) {
        try {
          console.log("🔄 Validating secret:", secret);
          const validated = await this.validateTOTPSecret(secret);
          validatedSecrets.push(validated);
          console.log("✅ Validated secret:", validated);
        } catch (error) {
          console.warn(`⚠️ Skipping invalid secret for ${secret.issuer}:${secret.label}:`, error.message);
        }
      }
      console.log("🔄 Final validated secrets:", validatedSecrets);
      return validatedSecrets;
    } catch (error) {
      console.error("❌ Import error:", error);
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
  async generateExportQRs(secrets, format = "individual") {
    try {
      console.log(`📤 Generating ${format} export QRs for ${secrets.length} secrets...`);
      if (format === "individual") {
        return await this.generateIndividualQRs(secrets);
      } else if (format === "migration") {
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
        const otpauthUri = totpGenerator.generateOTPAuthURI({
          type: "totp",
          issuer: secret.issuer,
          label: secret.label,
          secret: secret.secret,
          algorithm: secret.algorithm,
          digits: secret.digits,
          period: secret.period
        });
        const qrDataUrl = await qrManager.generateQRCode(otpauthUri);
        qrCodes.push({
          type: "individual",
          issuer: secret.issuer,
          label: secret.label,
          qrCode: qrDataUrl,
          otpauthUri
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
    const batchSize = 10;
    const qrCodes = [];
    for (let i = 0; i < secrets.length; i += batchSize) {
      const batch = secrets.slice(i, i + batchSize);
      try {
        const qrDataUrl = await qrManager.generateMigrationQR(batch);
        qrCodes.push({
          type: "migration",
          secretCount: batch.length,
          batchNumber: Math.floor(i / batchSize) + 1,
          totalBatches: Math.ceil(secrets.length / batchSize),
          qrCode: qrDataUrl,
          secrets: batch.map((s) => ({ issuer: s.issuer, label: s.label }))
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
        version: "1.0",
        type: "personal-2fa-backup",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        secretCount: secrets.length,
        secrets: secrets.map((secret) => ({
          issuer: secret.issuer,
          label: secret.label,
          secret: secret.secret,
          algorithm: secret.algorithm,
          digits: secret.digits,
          period: secret.period
        }))
      };
      if (password) {
        console.log("🔐 TODO: Encrypt backup with password");
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
      if (password) {
        console.log("🔓 TODO: Decrypt backup with password");
      }
      const backupData = JSON.parse(jsonData);
      if (backupData.type !== "personal-2fa-backup") {
        throw new Error("Invalid backup format");
      }
      if (!backupData.secrets || !Array.isArray(backupData.secrets)) {
        throw new Error("No secrets found in backup");
      }
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
    if (!secretKey || !label) {
      throw new Error("Secret and label are required");
    }
    if (!totpGenerator.isValidBase32(secretKey)) {
      throw new Error("Invalid Base32 secret");
    }
    const normalizedAlgorithm = (algorithm || "SHA1").toUpperCase();
    if (!["SHA1", "SHA256", "SHA512"].includes(normalizedAlgorithm)) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    const normalizedDigits = parseInt(digits) || 6;
    if (![6, 8].includes(normalizedDigits)) {
      throw new Error(`Invalid digits count: ${digits}`);
    }
    const normalizedPeriod = parseInt(period) || 30;
    if (normalizedPeriod < 15 || normalizedPeriod > 300) {
      throw new Error(`Invalid period: ${period}`);
    }
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
      issuer: issuer || "Unknown",
      label: label.trim(),
      secret: secretKey.toUpperCase().replace(/\s/g, ""),
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
    console.log("📝 Adding secret for export-only mode (not storing permanently)");
    this.exportedSecrets.push({
      ...secret,
      addedAt: (/* @__PURE__ */ new Date()).toISOString()
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
    console.log("🗑️ Clearing export-only secrets queue");
    this.exportedSecrets = [];
  }
  /**
   * Check compatibility with different authenticator apps
   * @param {Object} secret - TOTP secret
   * @returns {Object} Compatibility information
   */
  checkCompatibility(secret) {
    const compatibility = {
      googleAuth: true,
      // Always compatible
      microsoftAuth: true,
      authy: false,
      // Authy doesn't support standard imports
      aegis: true,
      andOTP: true,
      lastpass: secret.algorithm === "SHA1" && secret.digits === 6,
      // Limited support
      bitwarden: true
    };
    if (secret.algorithm !== "SHA1") {
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
    if (secret.algorithm !== "SHA1") {
      warnings.push("Non-SHA1 algorithms may not work with all authenticator apps");
    }
    if (secret.digits !== 6) {
      warnings.push("8-digit codes may not be supported by all apps");
    }
    if (secret.period !== 30) {
      warnings.push("Non-standard periods may not work with all apps");
    }
    const incompatibleApps = Object.entries(compatibility).filter(([app, isCompatible]) => !isCompatible).map(([app]) => app);
    if (incompatibleApps.length > 0) {
      warnings.push(`Not compatible with: ${incompatibleApps.join(", ")}`);
    }
    return warnings;
  }
}
const googleAuthManager = new GoogleAuthManager();
class Personal2FAApp {
  constructor() {
    this.currentScreen = "setup";
    this.isUnlocked = false;
    this.totpTimers = /* @__PURE__ */ new Map();
    this.refreshInterval = null;
    this.securityCheckInterval = null;
    this.elements = {};
  }
  /**
   * Initialize the application
   */
  async init() {
    console.log("🚀 Initializing Personal 2FA App...");
    try {
      await storageManager.init();
      this.initDOMElements();
      this.setupEventListeners();
      qrManager.init(this.elements.qrVideo, this.elements.qrCanvas);
      this.performSecurityChecks();
      const isSetup = await storageManager.isSetup();
      if (isSetup) {
        this.showScreen("login");
      } else {
        this.showScreen("setup");
      }
      console.log("✅ App initialization complete");
    } catch (error) {
      console.error("❌ App initialization failed:", error);
      this.showError("Failed to initialize app: " + error.message);
    }
  }
  /**
   * Cache DOM elements for performance
   */
  initDOMElements() {
    this.elements = {
      // Screens
      setupScreen: document.getElementById("setup-screen"),
      loginScreen: document.getElementById("login-screen"),
      mainScreen: document.getElementById("main-screen"),
      // Setup elements
      masterPassword: document.getElementById("master-password"),
      confirmPassword: document.getElementById("confirm-password"),
      setupComplete: document.getElementById("setup-complete"),
      // Login elements
      loginPassword: document.getElementById("login-password"),
      loginBtn: document.getElementById("login-btn"),
      loginError: document.getElementById("login-error"),
      // Main app elements
      importBtn: document.getElementById("import-btn"),
      exportBtn: document.getElementById("export-btn"),
      addManualBtn: document.getElementById("add-manual-btn"),
      manageDataBtn: document.getElementById("manage-data-btn"),
      lockBtn: document.getElementById("lock-btn"),
      // Sections
      importSection: document.getElementById("import-section"),
      exportSection: document.getElementById("export-section"),
      codesSection: document.getElementById("codes-section"),
      manualAddSection: document.getElementById("manual-add-section"),
      dataManagementSection: document.getElementById("data-management-section"),
      // QR Scanner
      qrVideo: document.getElementById("qr-video"),
      qrCanvas: document.getElementById("qr-canvas"),
      startCamera: document.getElementById("start-camera"),
      stopCamera: document.getElementById("stop-camera"),
      scanResult: document.getElementById("scan-result"),
      // Export
      exportGoogleFormat: document.getElementById("export-google-format"),
      exportIndividualQR: document.getElementById("export-individual-qr"),
      exportJSONBackup: document.getElementById("export-json-backup"),
      exportResult: document.getElementById("export-result"),
      // TOTP Display
      totpList: document.getElementById("totp-list"),
      emptyState: document.getElementById("empty-state"),
      // Manual Add Form
      manualAddForm: document.getElementById("manual-add-form"),
      manualIssuer: document.getElementById("manual-issuer"),
      manualLabel: document.getElementById("manual-label"),
      manualSecret: document.getElementById("manual-secret"),
      manualAlgorithm: document.getElementById("manual-algorithm"),
      manualDigits: document.getElementById("manual-digits"),
      manualPeriod: document.getElementById("manual-period"),
      cancelManual: document.getElementById("cancel-manual"),
      // Data Management
      clearAllData: document.getElementById("clear-all-data"),
      // Security indicators
      cryptoStatus: document.getElementById("crypto-status"),
      storageStatus: document.getElementById("storage-status"),
      networkStatus: document.getElementById("network-status"),
      securityChecks: document.getElementById("security-checks")
    };
  }
  /**
   * Setup all event listeners
   */
  setupEventListeners() {
    this.elements.setupComplete.addEventListener("click", () => this.handleSetup());
    this.elements.loginBtn.addEventListener("click", () => this.handleLogin());
    this.elements.loginPassword.addEventListener("keypress", (e) => {
      if (e.key === "Enter") this.handleLogin();
    });
    this.elements.importBtn.addEventListener("click", () => this.showImportSection());
    this.elements.exportBtn.addEventListener("click", () => this.showExportSection());
    this.elements.addManualBtn.addEventListener("click", () => this.showManualAddSection());
    this.elements.manageDataBtn.addEventListener("click", () => this.showDataManagementSection());
    this.elements.lockBtn.addEventListener("click", () => this.lockApp());
    this.elements.startCamera.addEventListener("click", () => this.startQRScanning());
    this.elements.stopCamera.addEventListener("click", () => this.stopQRScanning());
    this.elements.exportGoogleFormat.addEventListener("click", () => this.exportGoogleFormat());
    this.elements.exportIndividualQR.addEventListener("click", () => this.exportIndividualQR());
    this.elements.exportJSONBackup.addEventListener("click", () => this.exportJSONBackup());
    this.elements.manualAddForm.addEventListener("submit", (e) => this.handleManualAdd(e));
    this.elements.cancelManual.addEventListener("click", () => this.hideAllSections());
    this.elements.clearAllData.addEventListener("click", () => this.handleClearAllData());
    window.addEventListener("online", () => this.updateNetworkStatus());
    window.addEventListener("offline", () => this.updateNetworkStatus());
    this.startSecurityMonitoring();
  }
  /**
   * Handle master password setup
   */
  async handleSetup() {
    const password = this.elements.masterPassword.value;
    const confirmPassword = this.elements.confirmPassword.value;
    if (!password || password.length < 8) {
      this.showError("Password must be at least 8 characters long");
      return;
    }
    if (password !== confirmPassword) {
      this.showError("Passwords do not match");
      return;
    }
    try {
      console.log("🔐 Setting up master password...");
      await storageManager.setupMasterPassword(password);
      this.isUnlocked = true;
      this.showScreen("main");
      this.refreshTOTPCodes();
      console.log("✅ Master password setup complete");
    } catch (error) {
      console.error("❌ Setup failed:", error);
      this.showError("Setup failed: " + error.message);
    }
  }
  /**
   * Handle login with master password
   */
  async handleLogin() {
    const password = this.elements.loginPassword.value;
    if (!password) {
      this.showLoginError("Please enter your master password");
      return;
    }
    try {
      console.log("🔓 Attempting to unlock storage...");
      const success = await storageManager.unlock(password);
      if (success) {
        this.isUnlocked = true;
        this.showScreen("main");
        this.refreshTOTPCodes();
        console.log("✅ Storage unlocked successfully");
      } else {
        this.showLoginError("Invalid password");
      }
    } catch (error) {
      console.error("❌ Login failed:", error);
      this.showLoginError("Login failed: " + error.message);
    }
  }
  /**
   * Show import section and hide others
   */
  showImportSection() {
    this.hideAllSections();
    this.elements.importSection.classList.remove("hidden");
  }
  /**
   * Show export section and hide others
   */
  showExportSection() {
    this.hideAllSections();
    this.elements.exportSection.classList.remove("hidden");
  }
  /**
   * Show manual add section and hide others
   */
  showManualAddSection() {
    this.hideAllSections();
    this.elements.manualAddSection.classList.remove("hidden");
  }
  /**
   * Show data management section
   */
  showDataManagementSection() {
    this.hideAllSections();
    this.elements.dataManagementSection.classList.remove("hidden");
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
    sections.forEach((section) => section.classList.add("hidden"));
  }
  /**
   * Start QR code scanning
   */
  async startQRScanning() {
    try {
      console.log("📹 Starting QR scanner...");
      this.elements.startCamera.classList.add("hidden");
      this.elements.stopCamera.classList.remove("hidden");
      this.elements.scanResult.innerHTML = '<div class="scanning">🔍 Scanning for QR codes...</div>';
      await qrManager.startScanning((qrData) => {
        this.handleQRDetected(qrData);
      });
    } catch (error) {
      console.error("❌ Failed to start camera:", error);
      this.elements.scanResult.innerHTML = `<div class="error">❌ Camera Error: ${error.message}</div>`;
      this.elements.startCamera.classList.remove("hidden");
      this.elements.stopCamera.classList.add("hidden");
    }
  }
  /**
   * Stop QR code scanning
   */
  stopQRScanning() {
    console.log("⏹️ Stopping QR scanner...");
    qrManager.stopScanning();
    this.elements.startCamera.classList.remove("hidden");
    this.elements.stopCamera.classList.add("hidden");
    this.elements.scanResult.innerHTML = "";
  }
  /**
   * Handle detected QR code
   */
  async handleQRDetected(qrData) {
    try {
      console.log("🔍 QR Code detected:", qrData);
      this.stopQRScanning();
      if (qrData.startsWith("otpauth-migration://")) {
        console.log("📱 Google Authenticator migration QR detected");
        const secrets = await googleAuthManager.importFromGoogleAuth(qrData);
        await this.importTOTPSecrets(secrets);
      } else if (qrData.startsWith("otpauth://")) {
        console.log("🔑 Individual TOTP QR detected");
        const secret = totpGenerator.parseOTPAuthURI(qrData);
        await this.importTOTPSecrets([secret]);
      } else {
        throw new Error("Unrecognized QR code format");
      }
    } catch (error) {
      console.error("❌ QR processing failed:", error);
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
          console.log(`✅ Imported: ${secret.issuer}:${secret.label}`);
        } catch (error) {
          console.error(`❌ Failed to import ${secret.issuer}:${secret.label}:`, error);
        }
      }
      this.elements.scanResult.innerHTML = `
        <div class="success">
          ✅ Successfully imported ${importedCount} TOTP secrets!
        </div>
      `;
      this.refreshTOTPCodes();
    } catch (error) {
      console.error("❌ Import failed:", error);
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
      const validatedSecret = await googleAuthManager.validateTOTPSecret(secret);
      await storageManager.storeTOTPSecret(validatedSecret);
      console.log(`✅ Added manual TOTP: ${secret.issuer}:${secret.label}`);
      this.elements.manualAddForm.reset();
      this.hideAllSections();
      this.refreshTOTPCodes();
    } catch (error) {
      console.error("❌ Manual add failed:", error);
      this.showError("Failed to add TOTP: " + error.message);
    }
  }
  /**
   * Handle clearing all application data with multiple confirmations
   */
  async handleClearAllData() {
    try {
      const firstConfirm = confirm(
        "⚠️ ADVERTENCIA: Estás a punto de eliminar TODOS los códigos 2FA y datos de la aplicación.\n\n🚨 Esta acción NO se puede deshacer.\n🚨 Perderás el acceso a todas las cuentas configuradas.\n🚨 NO podrás recuperar esta información.\n\n¿Estás absolutamente seguro de que quieres continuar?"
      );
      if (!firstConfirm) {
        console.log("🔒 Clear data cancelled by user (first confirmation)");
        return;
      }
      const secondConfirm = confirm(
        '🚨 CONFIRMACIÓN FINAL 🚨\n\nVas a eliminar permanentemente:\n• Todos los códigos 2FA guardados\n• Configuraciones de la aplicación\n• Datos de IndexedDB y localStorage\n• Contraseña maestra configurada\n\n⚠️ DESPUÉS DE ESTO TENDRÁS QUE:\n• Configurar de nuevo todos tus códigos 2FA\n• Crear una nueva contraseña maestra\n• Volver a importar desde otras aplicaciones\n\nEscribe "BORRAR TODO" si realmente quieres continuar:'
      );
      if (secondConfirm !== "BORRAR TODO") {
        console.log("🔒 Clear data cancelled - incorrect confirmation text");
        alert('❌ Cancelado. Para confirmar debes escribir exactamente "BORRAR TODO"');
        return;
      }
      const finalConfirm = confirm(
        '🔥 ÚLTIMA OPORTUNIDAD 🔥\n\nEsta es tu última oportunidad para cancelar.\nUna vez que hagas clic en "Aceptar", NO HAY VUELTA ATRÁS.\n\n¿Proceder con la eliminación TOTAL e IRREVERSIBLE de todos los datos?'
      );
      if (!finalConfirm) {
        console.log("🔒 Clear data cancelled by user (final confirmation)");
        return;
      }
      console.log("🗑️ User confirmed data deletion. Proceeding...");
      alert("🗑️ Eliminando todos los datos... Por favor espera...");
      await this.clearAllApplicationData();
      alert(
        "✅ Datos eliminados exitosamente\n\nTodos los datos han sido eliminados de forma permanente.\nLa página se recargará para reiniciar la aplicación."
      );
      window.location.reload();
    } catch (error) {
      console.error("❌ Error clearing data:", error);
      this.showError("Error al eliminar los datos: " + error.message);
    }
  }
  /**
   * Clear all application data from all storage mechanisms
   */
  async clearAllApplicationData() {
    console.log("🧹 Starting complete data cleanup...");
    try {
      console.log("🗑️ Clearing IndexedDB...");
      if (storageManager) {
        await storageManager.clearAllData();
      }
      console.log("🗑️ Clearing localStorage...");
      localStorage.clear();
      console.log("🗑️ Clearing sessionStorage...");
      sessionStorage.clear();
      this.isLoggedIn = false;
      this.currentCodes = [];
      this.updateInterval = null;
      console.log("✅ All application data cleared successfully");
    } catch (error) {
      console.error("❌ Error during data cleanup:", error);
      throw error;
    }
  }
  /**
   * Export in Google Authenticator format
   */
  async exportGoogleFormat() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const qrCodes = await googleAuthManager.generateExportQRs(secrets, "migration");
      this.displayExportResult(qrCodes, "Google Authenticator Migration");
    } catch (error) {
      console.error("❌ Google format export failed:", error);
      this.showError("Export failed: " + error.message);
    }
  }
  /**
   * Export individual QR codes
   */
  async exportIndividualQR() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const qrCodes = await googleAuthManager.generateExportQRs(secrets, "individual");
      this.displayExportResult(qrCodes, "Individual QR Codes");
    } catch (error) {
      console.error("❌ Individual QR export failed:", error);
      this.showError("Export failed: " + error.message);
    }
  }
  /**
   * Export JSON backup
   */
  async exportJSONBackup() {
    try {
      const secrets = await storageManager.getAllTOTPSecrets();
      const jsonBackup = await googleAuthManager.exportToJSON(secrets);
      const blob = new Blob([jsonBackup], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `personal-2fa-backup-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.json`;
      link.click();
      URL.revokeObjectURL(url);
      this.elements.exportResult.innerHTML = '<div class="success">✅ JSON backup downloaded!</div>';
    } catch (error) {
      console.error("❌ JSON export failed:", error);
      this.showError("Export failed: " + error.message);
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
          <h5>${qr.type === "individual" ? `${qr.issuer}: ${qr.label}` : `Batch ${qr.batchNumber}/${qr.totalBatches}`}</h5>
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
        this.elements.totpList.style.display = "none";
        this.elements.emptyState.style.display = "block";
        return;
      }
      this.elements.totpList.style.display = "block";
      this.elements.emptyState.style.display = "none";
      this.totpTimers.clear();
      let html = "";
      for (const secret of secrets) {
        const totpData = await totpGenerator.generateTOTP(secret.secret, secret);
        html += this.createTOTPItemHTML(secret, totpData);
        this.totpTimers.set(secret.id, {
          secret,
          lastUpdate: Date.now()
        });
      }
      this.elements.totpList.innerHTML = html;
      this.startTOTPRefresh();
    } catch (error) {
      console.error("❌ Failed to refresh TOTP codes:", error);
      this.showError("Failed to load TOTP codes: " + error.message);
    }
  }
  /**
   * Create HTML for TOTP item
   */
  createTOTPItemHTML(secret, totpData) {
    return `
      <div class="totp-item" data-id="${secret.id}">
        <div class="totp-header">
          <div class="totp-service">${secret.issuer}</div>
          <div class="totp-account">${secret.label}</div>
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
    }, 1e3);
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
          const codeElement = element.querySelector(".totp-code");
          if (codeElement.textContent !== totpData.code) {
            codeElement.textContent = totpData.code;
          }
          const timerBar = element.querySelector(".timer-bar");
          const timerText = element.querySelector(".timer-text");
          if (timerBar && timerText) {
            timerBar.style.width = `${totpData.progress}%`;
            timerText.textContent = `${totpData.timeRemaining}s`;
          }
        }
      } catch (error) {
        console.error(`❌ Failed to update TOTP for secret ${secretId}:`, error);
      }
    }
  }
  /**
   * Lock the application
   */
  lockApp() {
    console.log("🔒 Locking application...");
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
    this.totpTimers.clear();
    storageManager.lock();
    this.isUnlocked = false;
    this.elements.totpList.innerHTML = "";
    this.elements.loginPassword.value = "";
    this.showScreen("login");
  }
  /**
   * Show specific screen
   */
  showScreen(screenName) {
    const screens = ["setup", "login", "main"];
    screens.forEach((screen) => {
      const element = document.getElementById(`${screen}-screen`);
      if (element) {
        element.classList.toggle("active", screen === screenName);
      }
    });
    this.currentScreen = screenName;
    console.log(`📱 Showing ${screenName} screen`);
  }
  /**
   * Show error message
   */
  showError(message) {
    console.error("❌", message);
    alert(message);
  }
  /**
   * Show login error
   */
  showLoginError(message) {
    this.elements.loginError.textContent = message;
    this.elements.loginError.classList.add("show");
    setTimeout(() => {
      this.elements.loginError.classList.remove("show");
    }, 5e3);
  }
  /**
   * Perform security checks
   */
  performSecurityChecks() {
    const status = cryptoManager.getSecurityStatus();
    this.elements.cryptoStatus.textContent = status.isSecure ? "🔐 Cifrado: AES-256" : "⚠️ Cifrado: No disponible";
    this.elements.storageStatus.textContent = "🏠 Local";
    this.updateNetworkStatus();
    const checksHtml = Object.entries(status).map(([key, value]) => `<div>${key}: ${value ? "✅" : "❌"}</div>`).join("");
    this.elements.securityChecks.innerHTML = checksHtml;
    if (!status.isSecure) {
      this.showError("Security warning: Web Crypto API not available. Please use HTTPS or localhost.");
    }
  }
  /**
   * Update network status indicator
   */
  updateNetworkStatus() {
    const isOnline = navigator.onLine;
    this.elements.networkStatus.textContent = isOnline ? "📡 Online ⚠️" : "📡 Offline ✅";
    this.elements.networkStatus.className = `indicator ${isOnline ? "warning" : "secure"}`;
  }
  /**
   * Start security monitoring
   */
  startSecurityMonitoring() {
    this.securityCheckInterval = setInterval(() => {
      this.performSecurityChecks();
    }, 3e4);
  }
}
document.addEventListener("DOMContentLoaded", () => {
  const app = new Personal2FAApp();
  app.init();
  window.Personal2FA = app;
});
