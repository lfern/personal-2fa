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
import notificationSystem from './notification.js';



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
      
      // Determine initial screen
      const isSetup = await storageManager.isSetup();
      if (isSetup) {
        this.showScreen('login');
      } else {
        this.showScreen('setup');
      }
      
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
    const screens = ['setup', 'login', 'main'];
    
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