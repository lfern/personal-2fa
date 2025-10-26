/**
 * Internationalization (i18n) Module for Personal 2FA
 * Simple translation system for Spanish and English
 */

class I18n {
  constructor() {
    this.translations = {
      es: {
        // App Title and Headers
        appTitle: 'Personal 2FA - Autenticador Local Seguro',
        appName: '🔒 Personal 2FA',
        
        // Setup Screen
        setupTitle: '🛡️ Configuración Inicial de Seguridad',
        setupSecurity: 'Esta aplicación es completamente segura:',
        setupFeatures: {
          offline: 'Funciona 100% offline - Sin conexiones a internet',
          encrypted: 'Todos los datos se cifran antes de guardarse',
          local: 'Tus códigos nunca salen de tu dispositivo',
          inspectable: 'Código fuente completamente inspecciónable',
          compatible: 'Compatible con Google Authenticator'
        },
        masterPasswordLabel: 'Crear contraseña maestra:',
        masterPasswordPlaceholder: 'Contraseña segura para cifrar tus datos',
        confirmPasswordPlaceholder: 'Confirmar contraseña',
        createVault: '🔒 Crear Almacén Seguro',
        
        // Login Screen
        loginTitle: '🔓 Desbloquear Personal 2FA',
        loginPlaceholder: 'Contraseña maestra',
        unlockButton: 'Desbloquear',
        
        // Main Navigation
        importBtn: '📥 Importar de Google Auth',
        exportBtn: '💾 Exportar Backup',
        addManualBtn: '➕ Añadir Manual',
        manageDataBtn: '🗑️ Gestionar Datos',
        lockBtn: '🔒 Bloquear',
        
        // Import Section
        importTitle: '📱 Importar desde Google Authenticator',
        startCameraBtn: '📹 Activar Cámara',
        stopCameraBtn: '⏹️ Detener Cámara',
        scanningMessage: '🔍 Buscando códigos QR...',
        
        // Export Section
        exportTitle: '📤 Exportar Códigos (Solo Backup)',
        exportGoogleBtn: '📱 Formato Google Auth',
        exportIndividualBtn: '🔗 QR Individuales',
        exportJsonBtn: '💾 Backup JSON',
        
        // Manual Add
        manualTitle: '➕ Añadir Código Manual',
        issuerLabel: 'Servicio:',
        issuerPlaceholder: 'Ej: Google, GitHub, Microsoft',
        accountLabel: 'Cuenta:',
        accountPlaceholder: 'tu-email@ejemplo.com',
        secretLabel: 'Secreto (Base32):',
        secretPlaceholder: 'Código secreto proporcionado por el servicio',
        algorithmLabel: 'Algoritmo:',
        digitsLabel: 'Dígitos:',
        periodLabel: 'Período (segundos):',
        addBtn: '➕ Añadir Código',
        cancelBtn: 'Cancelar',
        
        // Data Management
        dataTitle: '🗑️ Gestión de Datos',
        clearDataBtn: '🧹 Limpiar Todos los Datos',
        factoryResetBtn: '🔄 Factory Reset',
        enableLogsLabel: 'Habilitar logs de depuración',
        
        // Messages
        passwordTooShort: 'La contraseña debe tener al menos 8 caracteres',
        passwordMismatch: 'Las contraseñas no coinciden',
        setupComplete: '✅ Contraseña maestra configurada correctamente',
        invalidPassword: 'Contraseña incorrepta',
        importSuccess: '✅ Códigos importados exitosamente!',
        deleteConfirm: '¿Estás seguro de que quieres eliminar este código 2FA?',
        
        // Dialog titles and buttons
        deleteCodeTitle: 'Eliminar código 2FA',
        deleteAllDataTitle: 'BORRAR TODOS LOS DATOS',
        textConfirmationTitle: 'Confirmación de texto',
        deleteConfirmationTitle: 'Confirmación de eliminación',
        finalConfirmationTitle: 'CONFIRMACIÓN FINAL',
        confirm: 'Confirmar',
        cancel: 'Cancelar',
        accept: 'Aceptar',
        
        // Delete messages
        deleteCodeMessage: '¿Estás seguro de que quieres eliminar este código 2FA?<br><br>Servicio: {issuer}<br>Cuenta: {label}<br><br>⚠️ Esta acción no se puede deshacer.',
        deletePromptMessage: 'Para confirmar la eliminación, escribe: <strong>ELIMINAR</strong><br><br>Servicio: {issuer}<br>Cuenta: {label}',
        deleteTextError: '❌ Texto incorrecto. Debes escribir exactamente "ELIMINAR"',
        deleteSuccessMessage: '✅ Código eliminado: {issuer} - {label}',
        deleteError: '❌ Error al eliminar el código. ID inválido.',
        
        // Clear all data messages
        clearAllWarning: '⚠️ ADVERTENCIA: Estás a punto de eliminar TODOS los códigos 2FA y datos de la aplicación.<br><br>🚨 Esta acción NO se puede deshacer.<br>🚨 Perderás el acceso a todas las cuentas configuradas.<br>🚨 NO podrás recuperar esta información.<br><br>¿Estás absolutamente seguro de que quieres continuar?',
        clearAllFinalConfirm: '🚨 CONFIRMACIÓN FINAL 🚨<br><br>Vas a eliminar permanentemente:<br>• Todos los códigos 2FA guardados<br>• Configuraciones de la aplicación<br>• Datos de IndexedDB y localStorage<br>• Contraseña maestra configurada<br><br>⚠️ DESPUÉS DE ESTO TENDRÁS QUE:<br>• Configurar de nuevo todos tus códigos 2FA<br>• Crear una nueva contraseña maestra<br>• Volver a importar desde otras aplicaciones<br><br>Escribe "BORRAR TODO" si realmente quieres continuar:',
        clearAllLastChance: '🔥 ÚLTIMA OPORTUNIDAD 🔥<br><br>Esta es tu última oportunidad para cancelar.<br>Una vez que hagas clic en "Confirmar", NO HAY VUELTA ATRÁS.<br><br>¿Proceder con la eliminación TOTAL e IRREVERSIBLE de todos los datos?',
        clearAllTextError: '❌ Cancelado. Para confirmar debes escribir exactamente "BORRAR TODO"',
        clearAllProgress: '🗑️ Eliminando todos los datos... Por favor espera...',
        clearAllSuccess: '✅ Datos eliminados exitosamente<br><br>Todos los datos han sido eliminados de forma permanente.<br>La página se recargará para reiniciar la aplicación.',
        
        // Error messages
        initError: 'Error al inicializar la aplicación: ',
        setupError: 'Error en la configuración: ',
        loginError: 'Error de acceso: ',
        deleteError: '❌ Error al eliminar: ',
        clearDataError: 'Error al eliminar los datos: ',
        exportError: 'Error de exportación: ',
        totpLoadError: 'Error al cargar códigos TOTP: ',
        addTotpError: 'Error al añadir TOTP: ',
        securityWarning: 'Advertencia de seguridad: Web Crypto API no disponible. Por favor usa HTTPS o localhost.',
        
        // Login messages
        enterPassword: 'Por favor introduce tu contraseña maestra',
        loginFailed: 'Error de acceso: ',
        
        // Scanner messages
        scanningQR: '🔍 Buscando códigos QR...',
        cameraError: '❌ Error de cámara: ',
        qrError: '❌ Error: ',
        importSuccessMessage: '✅ ¡Códigos importados exitosamente!',
        importFailedMessage: '❌ Error de importación: ',
        
        // Export messages
        jsonDownloaded: '✅ ¡Backup JSON descargado!',
        
        // Setup messages
        configuringPassword: '🔐 Configurando contraseña maestra...',
        
        // Action buttons
        activateCamera: '📹 Activar Cámara',
        stopCamera: '⏹️ Detener',
        
        // Section titles
        codesTitle: '🔢 Códigos de Autenticación',
        importSectionTitle: '📱 Importar desde Google Authenticator',
        exportSectionTitle: '💾 Exportar para Backup',
        dataManagementTitle: '🗑️ Gestión de Datos',
        manualAddTitle: '➕ Añadir Código Manualmente',
        
        // Export messages
        exportNotice: '⚠️ <strong>Importante:</strong> Este export es solo para backup. Los códigos NO se guardarán en esta app, solo se generan para que puedas importarlos en otra aplicación.',
        googleAuthFormat: '📱 Formato Google Authenticator',
        individualQRs: '📄 QR Individuales',
        jsonBackup: '📋 Backup JSON',
        
        // Empty state
        emptyStateMessage: 'No hay códigos configurados.',
        emptyStateSubtext: 'Importa desde Google Authenticator o añade manualmente.',
        
        // Data management
        devOptions: '⚙️ Opciones de Desarrollo',
        showDebugLogs: '📝 Mostrar logs de depuración',
        debugDescription: 'Activa los mensajes de depuración en la consola del navegador (desactivado por defecto). Útil para desarrolladores y resolución de problemas. Los errores críticos siempre se muestran.',
        
        // Danger zone
        deleteAllDataTitle: '⚠️ Eliminar Todos los Datos',
        deleteAllDataWarning: 'Esta acción eliminará <strong>permanentemente</strong> todos los códigos 2FA y datos almacenados, <strong>pero mantiene tu contraseña maestra y configuraciones básicas</strong>.',
        deleteAllDataNotice: '<strong>🚨 NO HAY FORMA DE RECUPERAR LOS CÓDIGOS UNA VEZ ELIMINADOS</strong>',
        deleteAllDataBtn: '🗑️ Eliminar Todos los Datos',
        
        // Factory reset
        factoryResetSectionTitle: '🔄 Reset Completo de la Aplicación',
        factoryResetDescription: 'Esta acción <strong>RESETEA COMPLETAMENTE</strong> la aplicación, eliminando:',
        factoryResetItems: {
          password: '🔐 Contraseña maestra configurada',
          codes: '🗑️ Todos los códigos 2FA y datos',
          settings: '⚙️ Todas las configuraciones y preferencias',
          history: '💾 Todo el historial y caché local'
        },
        factoryResetFinalWarning: '<strong>🚨 LA APLICACIÓN VOLVERÁ AL ESTADO INICIAL COMO SI NUNCA SE HUBIERA USADO</strong>',
        factoryResetBtn: '🔄 Reset Completo',
        
        // Manual add form
        servicePlaceholder: 'Servicio (ej: Google, GitHub)',
        accountPlaceholder: 'Cuenta (ej: user@gmail.com)',
        secretPlaceholder: 'Código secreto (Base32)',
        algorithmLabel: 'Algoritmo:',
        sha1Standard: 'SHA1 (estándar)',
        digitsLabel: 'Dígitos:',
        sixStandard: '6 (estándar)',
        periodLabel: 'Período:',
        addCodeBtn: '✅ Añadir Código',
        manualAddTitle: '➕ Añadir Código Manualmente',
        cancelBtn: '❌ Cancelar',
        
        // Security panel
        securityVerification: '🔍 Verificación de Seguridad',
        
        // Factory Reset messages
        factoryResetTitle: '🔄 FACTORY RESET - ADVERTENCIA CRÍTICA',
        factoryResetWarning: '⚠️ Un Factory Reset ELIMINARÁ COMPLETAMENTE:<br><br>🔐 Tu contraseña maestra configurada<br>🗑️ TODOS los códigos 2FA guardados<br>⚙️ TODAS las configuraciones personalizadas<br>💾 TODO el historial y datos locales<br><br>🚨 <strong>LA APLICACIÓN VOLVERÁ AL ESTADO INICIAL</strong><br>🚨 <strong>COMO SI NUNCA LA HUBIERAS USADO</strong><br><br>¿Estás completamente seguro de que quieres continuar?',
        factoryResetConfirmTitle: 'CONFIRMACIÓN DE FACTORY RESET',
        factoryResetConfirmMessage: 'Para proceder con el reset completo de la aplicación,<br>escribe exactamente: <strong>FACTORY RESET</strong><br><br>⚠️ Esta acción es <strong>COMPLETAMENTE IRREVERSIBLE</strong><br>⚠️ Perderás <strong>TODO</strong> lo configurado en esta aplicación',
        factoryResetPlaceholder: 'Escribe: FACTORY RESET',
        factoryResetTextError: '❌ Texto incorrecto. Debes escribir exactamente: FACTORY RESET',
        factoryResetFinalTitle: '🚨 ÚLTIMA ADVERTENCIA - FACTORY RESET 🚨',
        factoryResetFinalMessage: '⚠️ Estás a punto de realizar un <strong>RESET COMPLETO</strong>.<br>La aplicación volverá al estado inicial.<br><br>❌ <strong>NO PODRÁS RECUPERAR NADA</strong><br>❌ <strong>NO HAY COPIAS DE SEGURIDAD</strong><br>❌ <strong>NO HAY FORMA DE DESHACER ESTA ACCIÓN</strong><br><br>Una vez que hagas clic en "Ejecutar Reset", la aplicación<br>se reseteará completamente como si nunca la hubieras usado.',
        factoryResetProgress: '🔄 Ejecutando Factory Reset... Por favor espera...',
        factoryResetClearing: 'Limpiando almacenamiento local...',
        factoryResetForcing: 'Forzando limpieza...',
        factoryResetComplete: '✅ FACTORY RESET COMPLETADO<br><br>La aplicación ha sido completamente reseteada.<br>🔄 Recargando página...',
        factoryResetError: '❌ Error durante el factory reset: ',
        continueBtn: 'Sí, Continuar',
        executeResetBtn: 'Ejecutar Reset',
        
        // Security Indicators
        encryption: '🔐 Cifrado: AES-256',
        storage: '🏠 Local',
        networkOnline: '📡 Online ⚠️',
        networkOffline: '📡 Offline ✅',
        
        // Time units
        seconds: 's',
        
        // Loading
        loadingTitle: '🔍 Verificando configuración...',
        loadingMessage: 'Comprobando si ya tienes una contraseña maestra configurada'
      },
      
      en: {
        // App Title and Headers
        appTitle: 'Personal 2FA - Secure Local Authenticator',
        appName: '🔒 Personal 2FA',
        
        // Setup Screen
        setupTitle: '🛡️ Initial Security Setup',
        setupSecurity: 'This application is completely secure:',
        setupFeatures: {
          offline: 'Works 100% offline - No internet connections',
          encrypted: 'All data is encrypted before being saved',
          local: 'Your codes never leave your device',
          inspectable: 'Source code is completely inspectable',
          compatible: 'Compatible with Google Authenticator'
        },
        masterPasswordLabel: 'Create master password:',
        masterPasswordPlaceholder: 'Secure password to encrypt your data',
        confirmPasswordPlaceholder: 'Confirm password',
        createVault: '🔒 Create Secure Vault',
        
        // Login Screen
        loginTitle: '🔓 Unlock Personal 2FA',
        loginPlaceholder: 'Master password',
        unlockButton: 'Unlock',
        
        // Main Navigation
        importBtn: '📥 Import from Google Auth',
        exportBtn: '💾 Export Backup',
        addManualBtn: '➕ Add Manual',
        manageDataBtn: '🗑️ Manage Data',
        lockBtn: '🔒 Lock',
        
        // Import Section
        importTitle: '📱 Import from Google Authenticator',
        startCameraBtn: '📹 Start Camera',
        stopCameraBtn: '⏹️ Stop Camera',
        scanningMessage: '🔍 Scanning for QR codes...',
        
        // Export Section
        exportTitle: '📤 Export Codes (Backup Only)',
        exportGoogleBtn: '📱 Google Auth Format',
        exportIndividualBtn: '🔗 Individual QRs',
        exportJsonBtn: '💾 JSON Backup',
        
        // Manual Add
        manualTitle: '➕ Add Manual Code',
        issuerLabel: 'Service:',
        issuerPlaceholder: 'e.g., Google, GitHub, Microsoft',
        accountLabel: 'Account:',
        accountPlaceholder: 'your-email@example.com',
        secretLabel: 'Secret (Base32):',
        secretPlaceholder: 'Secret code provided by the service',
        algorithmLabel: 'Algorithm:',
        digitsLabel: 'Digits:',
        periodLabel: 'Period (seconds):',
        addBtn: '➕ Add Code',
        cancelBtn: 'Cancel',
        
        // Data Management
        dataTitle: '🗑️ Data Management',
        clearDataBtn: '🧹 Clear All Data',
        factoryResetBtn: '🔄 Factory Reset',
        enableLogsLabel: 'Enable debug logs',
        
        // Messages
        passwordTooShort: 'Password must be at least 8 characters',
        passwordMismatch: 'Passwords do not match',
        setupComplete: '✅ Master password configured successfully',
        invalidPassword: 'Invalid password',
        importSuccess: '✅ Codes imported successfully!',
        deleteConfirm: 'Are you sure you want to delete this 2FA code?',
        
        // Dialog titles and buttons
        deleteCodeTitle: 'Delete 2FA Code',
        deleteAllDataTitle: 'DELETE ALL DATA',
        textConfirmationTitle: 'Text Confirmation',
        deleteConfirmationTitle: 'Delete Confirmation',
        finalConfirmationTitle: 'FINAL CONFIRMATION',
        confirm: 'Confirm',
        cancel: 'Cancel',
        accept: 'Accept',
        
        // Delete messages
        deleteCodeMessage: 'Are you sure you want to delete this 2FA code?<br><br>Service: {issuer}<br>Account: {label}<br><br>⚠️ This action cannot be undone.',
        deletePromptMessage: 'To confirm deletion, type: <strong>DELETE</strong><br><br>Service: {issuer}<br>Account: {label}',
        deleteTextError: '❌ Incorrect text. You must type exactly "DELETE"',
        deleteSuccessMessage: '✅ Code deleted: {issuer} - {label}',
        deleteError: '❌ Error deleting code. Invalid ID.',
        
        // Clear all data messages
        clearAllWarning: '⚠️ WARNING: You are about to delete ALL 2FA codes and application data.<br><br>🚨 This action CANNOT be undone.<br>🚨 You will lose access to all configured accounts.<br>🚨 You will NOT be able to recover this information.<br><br>Are you absolutely sure you want to continue?',
        clearAllFinalConfirm: '🚨 FINAL CONFIRMATION 🚨<br><br>You are about to permanently delete:<br>• All saved 2FA codes<br>• Application configurations<br>• IndexedDB and localStorage data<br>• Configured master password<br><br>⚠️ AFTER THIS YOU WILL HAVE TO:<br>• Set up all your 2FA codes again<br>• Create a new master password<br>• Re-import from other applications<br><br>Type "DELETE ALL" if you really want to continue:',
        clearAllLastChance: '🔥 LAST CHANCE 🔥<br><br>This is your last chance to cancel.<br>Once you click "Confirm", there is NO GOING BACK.<br><br>Proceed with TOTAL and IRREVERSIBLE deletion of all data?',
        clearAllTextError: '❌ Cancelled. To confirm you must type exactly "DELETE ALL"',
        clearAllProgress: '🗑️ Deleting all data... Please wait...',
        clearAllSuccess: '✅ Data deleted successfully<br><br>All data has been permanently deleted.<br>The page will reload to restart the application.',
        
        // Error messages
        initError: 'Failed to initialize app: ',
        setupError: 'Setup error: ',
        loginError: 'Login error: ',
        deleteError: '❌ Error deleting: ',
        clearDataError: 'Error clearing data: ',
        exportError: 'Export failed: ',
        totpLoadError: 'Failed to load TOTP codes: ',
        addTotpError: 'Failed to add TOTP: ',
        securityWarning: 'Security warning: Web Crypto API not available. Please use HTTPS or localhost.',
        
        // Login messages
        enterPassword: 'Please enter your master password',
        loginFailed: 'Login failed: ',
        
        // Scanner messages
        scanningQR: '🔍 Scanning for QR codes...',
        cameraError: '❌ Camera Error: ',
        qrError: '❌ Error: ',
        importSuccessMessage: '✅ Codes imported successfully!',
        importFailedMessage: '❌ Import failed: ',
        
        // Export messages
        jsonDownloaded: '✅ JSON backup downloaded!',
        
        // Setup messages
        configuringPassword: '🔐 Setting up master password...',
        
        // Action buttons
        activateCamera: '📹 Start Camera',
        stopCamera: '⏹️ Stop',
        
        // Section titles
        codesTitle: '🔢 Authentication Codes',
        importSectionTitle: '📱 Import from Google Authenticator',
        exportSectionTitle: '💾 Export for Backup',
        dataManagementTitle: '🗑️ Data Management',
        manualAddTitle: '➕ Add Code Manually',
        
        // Export messages
        exportNotice: '⚠️ <strong>Important:</strong> This export is for backup only. The codes will NOT be saved in this app, they are only generated so you can import them into another application.',
        googleAuthFormat: '📱 Google Authenticator Format',
        individualQRs: '📄 Individual QRs',
        jsonBackup: '📋 JSON Backup',
        
        // Empty state
        emptyStateMessage: 'No codes configured.',
        emptyStateSubtext: 'Import from Google Authenticator or add manually.',
        
        // Data management
        devOptions: '⚙️ Development Options',
        showDebugLogs: '📝 Show debug logs',
        debugDescription: 'Enable debug messages in browser console (disabled by default). Useful for developers and troubleshooting. Critical errors are always shown.',
        
        // Danger zone
        deleteAllDataTitle: '⚠️ Delete All Data',
        deleteAllDataWarning: 'This action will <strong>permanently</strong> delete all 2FA codes and stored data, <strong>but keeps your master password and basic settings</strong>.',
        deleteAllDataNotice: '<strong>🚨 THERE IS NO WAY TO RECOVER THE CODES ONCE DELETED</strong>',
        deleteAllDataBtn: '🗑️ Delete All Data',
        
        // Factory reset
        factoryResetSectionTitle: '🔄 Complete Application Reset',
        factoryResetDescription: 'This action <strong>COMPLETELY RESETS</strong> the application, deleting:',
        factoryResetItems: {
          password: '🔐 Configured master password',
          codes: '🗑️ All 2FA codes and data',
          settings: '⚙️ All configurations and preferences',
          history: '💾 All history and local cache'
        },
        factoryResetFinalWarning: '<strong>🚨 THE APPLICATION WILL RETURN TO INITIAL STATE AS IF IT WAS NEVER USED</strong>',
        factoryResetBtn: '🔄 Complete Reset',
        
        // Manual add form
        servicePlaceholder: 'Service (e.g., Google, GitHub)',
        accountPlaceholder: 'Account (e.g., user@gmail.com)',
        secretPlaceholder: 'Secret code (Base32)',
        algorithmLabel: 'Algorithm:',
        sha1Standard: 'SHA1 (standard)',
        digitsLabel: 'Digits:',
        sixStandard: '6 (standard)',
        periodLabel: 'Period:',
        addCodeBtn: '✅ Add Code',
        manualAddTitle: '➕ Add Code Manually',
        cancelBtn: '❌ Cancel',
        
        // Security panel
        securityVerification: '🔍 Security Verification',
        
        // Factory Reset messages
        factoryResetTitle: '🔄 FACTORY RESET - CRITICAL WARNING',
        factoryResetWarning: '⚠️ A Factory Reset will COMPLETELY DELETE:<br><br>🔐 Your configured master password<br>🗑️ ALL saved 2FA codes<br>⚙️ ALL personalized settings<br>💾 ALL history and local data<br><br>🚨 <strong>THE APPLICATION WILL RETURN TO INITIAL STATE</strong><br>🚨 <strong>AS IF YOU NEVER USED IT</strong><br><br>Are you completely sure you want to continue?',
        factoryResetConfirmTitle: 'FACTORY RESET CONFIRMATION',
        factoryResetConfirmMessage: 'To proceed with the complete application reset,<br>type exactly: <strong>FACTORY RESET</strong><br><br>⚠️ This action is <strong>COMPLETELY IRREVERSIBLE</strong><br>⚠️ You will lose <strong>EVERYTHING</strong> configured in this application',
        factoryResetPlaceholder: 'Type: FACTORY RESET',
        factoryResetTextError: '❌ Incorrect text. You must type exactly: FACTORY RESET',
        factoryResetFinalTitle: '🚨 LAST WARNING - FACTORY RESET 🚨',
        factoryResetFinalMessage: '⚠️ You are about to perform a <strong>COMPLETE RESET</strong>.<br>The application will return to initial state.<br><br>❌ <strong>YOU WILL NOT BE ABLE TO RECOVER ANYTHING</strong><br>❌ <strong>THERE ARE NO BACKUPS</strong><br>❌ <strong>THERE IS NO WAY TO UNDO THIS ACTION</strong><br><br>Once you click "Execute Reset", the application<br>will be completely reset as if you never used it.',
        factoryResetProgress: '🔄 Executing Factory Reset... Please wait...',
        factoryResetClearing: 'Clearing local storage...',
        factoryResetForcing: 'Forcing cleanup...',
        factoryResetComplete: '✅ FACTORY RESET COMPLETED<br><br>The application has been completely reset.<br>🔄 Reloading page...',
        factoryResetError: '❌ Error during factory reset: ',
        continueBtn: 'Yes, Continue',
        executeResetBtn: 'Execute Reset',
        
        // Security Indicators
        encryption: '🔐 Encryption: AES-256',
        storage: '🏠 Local',
        networkOnline: '📡 Online ⚠️',
        networkOffline: '📡 Offline ✅',
        
        // Time units
        seconds: 's',
        
        // Loading
        loadingTitle: '🔍 Checking configuration...',
        loadingMessage: 'Checking if you already have a master password configured'
      }
    };
    
    // Initialize language after translations are defined
    this.currentLanguage = this.detectLanguage();
  }

  /**
   * Detect user's preferred language
   */
  detectLanguage() {
    // Check localStorage first (user preference)
    const saved = localStorage.getItem('personal-2fa-language');
    if (saved && this.translations[saved]) {
      return saved;
    }
    
    // Check browser language
    const browserLang = navigator.language || navigator.languages?.[0];
    if (browserLang?.startsWith('es')) {
      return 'es';
    }
    
    // Default to English
    return 'en';
  }

  /**
   * Get translation for a key
   */
  t(key, fallback = null) {
    const keys = key.split('.');
    let value = this.translations[this.currentLanguage];
    
    for (const k of keys) {
      value = value?.[k];
      if (value === undefined) break;
    }
    
    // Fallback to English if not found in current language
    if (value === undefined && this.currentLanguage !== 'en') {
      value = this.translations.en;
      for (const k of keys) {
        value = value?.[k];
        if (value === undefined) break;
      }
    }
    
    return value || fallback || `[${key}]`;
  }

  /**
   * Set current language
   */
  setLanguage(lang) {
    if (this.translations[lang]) {
      this.currentLanguage = lang;
      localStorage.setItem('personal-2fa-language', lang);
      this.updateUI();
    }
  }

  /**
   * Get current language
   */
  getCurrentLanguage() {
    return this.currentLanguage;
  }

  /**
   * Get available languages
   */
  getAvailableLanguages() {
    return [
      { code: 'es', name: 'Español', flag: '🇪🇸' },
      { code: 'en', name: 'English', flag: '🇺🇸' }
    ];
  }

  /**
   * Update UI elements with current language
   */
  updateUI() {
    // Update document title
    document.title = this.t('appTitle');
    
    // Update all elements with data-i18n attribute
    const elements = document.querySelectorAll('[data-i18n]');
    
    elements.forEach(element => {
      const key = element.getAttribute('data-i18n');
      const translation = this.t(key);
      
      if (element.tagName === 'INPUT' && element.type !== 'submit') {
        element.placeholder = translation;
      } else {
        element.textContent = translation;
      }
    });
    
    // Update elements with data-i18n-html (allows HTML content)
    document.querySelectorAll('[data-i18n-html]').forEach(element => {
      const key = element.getAttribute('data-i18n-html');
      const translation = this.t(key);
      element.innerHTML = translation;
    });
    
    // Update language selector to match current language if it exists
    const languageSelect = document.getElementById('language-select');
    if (languageSelect && languageSelect.value !== this.currentLanguage) {
      languageSelect.value = this.currentLanguage;
    }
  }
}

// Export singleton instance
const i18n = new I18n();

// Make available globally for other modules (both dev and build modes)
window.i18n = i18n;

// Auto-update UI when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => i18n.updateUI());
} else {
  i18n.updateUI();
}

// Export both as default and named export for global access
export default i18n;
export { i18n };