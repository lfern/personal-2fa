/**
 * Main Application Controller
 * Coordinates all modules and manages application state
 */

import { cryptoManager } from './crypto.js';
import { storageManager } from './storage.js';
import { totpGenerator } from './totp.js';
import { qrManager } from './qr.js';
import { googleAuthManager } from './googleAuth.js';
import logger from './logger.js';

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
    console.log('🚀 Initializing Personal 2FA App...');
    
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
      
      // Determine initial screen
      const isSetup = await storageManager.isSetup();
      if (isSetup) {
        this.showScreen('login');
      } else {
        this.showScreen('setup');
      }
      
      console.log('✅ App initialization complete');
      
    } catch (error) {
      console.error('❌ App initialization failed:', error);
      this.showError('Failed to initialize app: ' + error.message);
    }
  }

  /**
   * Cache DOM elements for performance
   */
  initDOMElements() {
    this.elements = {
      // Screens
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
    this.elements.cancelManual.addEventListener('click', () => this.hideAllSections());
    
    // Data management
    this.elements.clearAllData.addEventListener('click', () => this.handleClearAllData());
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
    const password = this.elements.masterPassword.value;
    const confirmPassword = this.elements.confirmPassword.value;
    
    if (!password || password.length < 8) {
      this.showError('Password must be at least 8 characters long');
      return;
    }
    
    if (password !== confirmPassword) {
      this.showError('Passwords do not match');
      return;
    }
    
    try {
      console.log('🔐 Setting up master password...');
      await storageManager.setupMasterPassword(password);
      this.isUnlocked = true;
      this.showScreen('main');
      this.refreshTOTPCodes();
      console.log('✅ Master password setup complete');
    } catch (error) {
      console.error('❌ Setup failed:', error);
      this.showError('Setup failed: ' + error.message);
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
      console.log('🔓 Attempting to unlock storage...');
      const success = await storageManager.unlock(password);
      
      if (success) {
        this.isUnlocked = true;
        this.showScreen('main');
        this.refreshTOTPCodes();
        console.log('✅ Storage unlocked successfully');
      } else {
        this.showLoginError('Invalid password');
      }
    } catch (error) {
      console.error('❌ Login failed:', error);
      this.showLoginError('Login failed: ' + error.message);
    }
  }

  /**
   * Show import section and hide others
   */
  showImportSection() {
    this.hideAllSections();
    this.elements.importSection.classList.remove('hidden');
  }

  /**
   * Show export section and hide others
   */
  showExportSection() {
    this.hideAllSections();
    this.elements.exportSection.classList.remove('hidden');
  }

  /**
   * Show manual add section and hide others
   */
  showManualAddSection() {
    this.hideAllSections();
    this.elements.manualAddSection.classList.remove('hidden');
  }

  /**
   * Show data management section
   */
  showDataManagementSection() {
    this.hideAllSections();
    this.elements.dataManagementSection.classList.remove('hidden');
    this.initializeLogsToggle();
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
  }

  /**
   * Start QR code scanning
   */
  async startQRScanning() {
    try {
      console.log('📹 Starting QR scanner...');
      
      this.elements.startCamera.classList.add('hidden');
      this.elements.stopCamera.classList.remove('hidden');
      this.elements.scanResult.innerHTML = '<div class="scanning">🔍 Scanning for QR codes...</div>';
      
      await qrManager.startScanning((qrData) => {
        this.handleQRDetected(qrData);
      });
      
    } catch (error) {
      console.error('❌ Failed to start camera:', error);
      this.elements.scanResult.innerHTML = `<div class="error">❌ Camera Error: ${error.message}</div>`;
      this.elements.startCamera.classList.remove('hidden');
      this.elements.stopCamera.classList.add('hidden');
    }
  }

  /**
   * Stop QR code scanning
   */
  stopQRScanning() {
    console.log('⏹️ Stopping QR scanner...');
    
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
      console.log('🔍 QR Code detected:', qrData);
      
      // Stop scanning
      this.stopQRScanning();
      
      // Check if it's a migration QR
      if (qrData.startsWith('otpauth-migration://')) {
        console.log('📱 Google Authenticator migration QR detected');
        const secrets = await googleAuthManager.importFromGoogleAuth(qrData);
        await this.importTOTPSecrets(secrets);
      } else if (qrData.startsWith('otpauth://')) {
        console.log('🔑 Individual TOTP QR detected');
        const secret = totpGenerator.parseOTPAuthURI(qrData);
        await this.importTOTPSecrets([secret]);
      } else {
        throw new Error('Unrecognized QR code format');
      }
      
    } catch (error) {
      console.error('❌ QR processing failed:', error);
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
      
      // Refresh the TOTP display
      this.refreshTOTPCodes();
      
    } catch (error) {
      console.error('❌ Import failed:', error);
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
      
      console.log(`✅ Added manual TOTP: ${secret.issuer}:${secret.label}`);
      
      // Reset form and hide section
      this.elements.manualAddForm.reset();
      this.hideAllSections();
      
      // Refresh display
      this.refreshTOTPCodes();
      
    } catch (error) {
      console.error('❌ Manual add failed:', error);
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
        console.log('🔒 Clear data cancelled by user (first confirmation)');
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
        console.log('🔒 Clear data cancelled - incorrect confirmation text');
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
        console.log('🔒 Clear data cancelled by user (final confirmation)');
        return;
      }

      console.log('🗑️ User confirmed data deletion. Proceeding...');
      
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
      console.error('❌ Error clearing data:', error);
      this.showError('Error al eliminar los datos: ' + error.message);
    }
  }

  /**
   * Clear all application data from all storage mechanisms
   */
  async clearAllApplicationData() {
    console.log('🧹 Starting complete data cleanup...');
    
    try {
      // 1. Clear IndexedDB (TOTP secrets and encrypted data)
      console.log('🗑️ Clearing IndexedDB...');
      if (storageManager) {
        await storageManager.clearAllData();
      }
      
      // 2. Clear localStorage (settings, cached data)
      console.log('🗑️ Clearing localStorage...');
      localStorage.clear();
      
      // 3. Clear sessionStorage (temporary session data)
      console.log('🗑️ Clearing sessionStorage...');
      sessionStorage.clear();
      
      // 4. Reset application state
      this.isLoggedIn = false;
      this.currentCodes = [];
      this.updateInterval = null;
      
      console.log('✅ All application data cleared successfully');
      
    } catch (error) {
      console.error('❌ Error during data cleanup:', error);
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
      console.error('❌ Google format export failed:', error);
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
      console.error('❌ Individual QR export failed:', error);
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
      console.error('❌ JSON export failed:', error);
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
      console.error('❌ Failed to refresh TOTP codes:', error);
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
        console.error(`❌ Failed to update TOTP for secret ${secretId}:`, error);
      }
    }
  }

  /**
   * Lock the application
   */
  lockApp() {
    console.log('🔒 Locking application...');
    
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
    const screens = ['setup', 'login', 'main'];
    
    screens.forEach(screen => {
      const element = document.getElementById(`${screen}-screen`);
      if (element) {
        element.classList.toggle('active', screen === screenName);
      }
    });
    
    this.currentScreen = screenName;
    console.log(`📱 Showing ${screenName} screen`);
  }

  /**
   * Show error message
   */
  showError(message) {
    console.error('❌', message);
    // TODO: Implement proper error display
    alert(message);
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
  window.Personal2FA = app;
});