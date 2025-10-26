
/* ====================================
   Personal 2FA - Secure Local 2FA App
   Generated: 2025-10-26T15:05:04.610Z
   
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

  // Export to global scope
  window.logger = logger;

})();


/* ============= i18n.js ============= */
(function() {
  'use strict';
  
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
        showCodesBtn: '🔢 Ver Códigos',
        importBtn: '📥 Importar',
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
        clearCodesProgress: '🧹 Borrando códigos TOTP...',
        clearCodesSuccess: '✅ Códigos TOTP eliminados<br><br>Todos los códigos han sido borrados exitosamente.<br>Tu configuración y contraseña se han preservado.',
        
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
        importSectionTitle: '📱 Importar Códigos 2FA',
        exportSectionTitle: '💾 Exportar para Backup',
        dataManagementTitle: '🗑️ Gestión de Datos',
        manualAddTitle: '➕ Añadir Código Manualmente',
        
        // Export messages
        exportNotice: '⚠️ <strong>Importante:</strong> Este export es solo para backup. Los códigos NO se guardarán en esta app, solo se generan para que puedas importarlos en otra aplicación.',
        googleAuthFormat: '📱 Formato Google Authenticator',
        individualQRs: '📄 QR Individuales',
        jsonBackup: '📋 Backup JSON',
        noCodesForExport: '⚠️ No hay códigos para exportar. Agrega algunos códigos primero.',
        googleAuthMigrationTitle: '📱 Migración Google Authenticator',
        individualQRTitle: '📄 Códigos QR Individuales', 
        noQRGenerated: '⚠️ No se pudieron generar códigos QR.',
        batchLabel: 'Lote',
        qrCodeInstruction: 'Escanea este código QR con tu aplicación de autenticación',
        
        // Import messages
        jsonImportTitle: '📋 Importar desde JSON',
        jsonImportDesc: 'Importa códigos desde un archivo JSON exportado previamente.',
        qrImportTitle: '📱 Importar desde QR',
        qrImportDesc: 'Escanea códigos QR de Google Authenticator u otras apps.',
        selectJSONFile: '📂 Seleccionar Archivo JSON',
        invalidFileType: '❌ Por favor selecciona un archivo JSON válido.',
        invalidJSONFormat: '❌ El archivo no contiene JSON válido.',
        invalidJSONStructure: '❌ La estructura del archivo JSON no es válida para importar códigos 2FA.',
        importConfirmTitle: '📥 Confirmar Importación',
        importConfirmMessage: '¿Estás seguro de que quieres importar {count} códigos desde este archivo JSON?',
        importResultMessage: '📊 Importación completada: {imported} importados, {duplicates} duplicados omitidos, {errors} errores.',
        importError: '❌ Error al importar: ',
        
        // Encrypted export/import
        encryptedBackup: '🔒 Backup Cifrado',
        encryptedImportTitle: '🔒 Importar desde Backup Cifrado',
        encryptedImportDesc: 'Importa códigos desde un archivo cifrado (compatible con OpenSSL AES-256-CBC).',
        selectEncryptedFile: '📂 Seleccionar Archivo Cifrado',
        encryptedExportTitle: '🔒 Exportar Backup Cifrado',
        encryptedExportPasswordChoice: '¿Qué contraseña quieres usar para cifrar el backup?',
        useCurrentPassword: '🔐 Usar contraseña maestra actual',
        useCustomPassword: '🔑 Usar contraseña personalizada',
        customPasswordTitle: '🔑 Contraseña Personalizada',
        enterCustomPasswordPrompt: 'Introduce una contraseña para cifrar el backup (mínimo 8 caracteres):',
        confirmPasswordTitle: '🔐 Confirmar Contraseña',
        confirmCustomPasswordPrompt: 'Confirma la contraseña:',
        noMasterPasswordAvailable: '❌ No hay contraseña maestra disponible para el cifrado.',
        encryptedBackupDownloaded: '✅ ¡Backup cifrado descargado! Compatible con OpenSSL AES-256-CBC.',
        decryptionPasswordTitle: '🔓 Contraseña de Descifrado',
        enterDecryptionPassword: 'Introduce la contraseña para descifrar el archivo:',
        decryptionFailed: '❌ Error al descifrar el archivo. Verifica la contraseña.',
        invalidEncryptedFileType: '❌ Por favor selecciona un archivo cifrado válido (.enc, .dat, .bin).',
        enterPassword: 'Introducir contraseña',
        confirmPassword: 'Confirmar contraseña',
        enterConfirmPassword: 'Confirma la contraseña',
        passwordsMatch: 'Las contraseñas coinciden',
        
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
        showCodesBtn: '🔢 View Codes',
        importBtn: '📥 Import',
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
        clearCodesProgress: '🧹 Clearing TOTP codes...',
        clearCodesSuccess: '✅ TOTP codes cleared<br><br>All codes have been successfully deleted.<br>Your configuration and password have been preserved.',
        
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
        importSectionTitle: '📱 Import 2FA Codes',
        exportSectionTitle: '💾 Export for Backup',
        dataManagementTitle: '🗑️ Data Management',
        manualAddTitle: '➕ Add Code Manually',
        
        // Export messages
        exportNotice: '⚠️ <strong>Important:</strong> This export is for backup only. The codes will NOT be saved in this app, they are only generated so you can import them into another application.',
        googleAuthFormat: '📱 Google Authenticator Format',
        individualQRs: '📄 Individual QRs',
        jsonBackup: '📋 JSON Backup',
        noCodesForExport: '⚠️ No codes available for export. Add some codes first.',
        googleAuthMigrationTitle: '📱 Google Authenticator Migration',
        individualQRTitle: '📄 Individual QR Codes',
        noQRGenerated: '⚠️ Could not generate QR codes.',
        batchLabel: 'Batch',
        qrCodeInstruction: 'Scan this QR code with your authentication app',
        
        // Import messages
        jsonImportTitle: '📋 Import from JSON',
        jsonImportDesc: 'Import codes from a previously exported JSON file.',
        qrImportTitle: '📱 Import from QR',
        qrImportDesc: 'Scan QR codes from Google Authenticator or other apps.',
        selectJSONFile: '📂 Select JSON File',
        invalidFileType: '❌ Please select a valid JSON file.',
        invalidJSONFormat: '❌ The file does not contain valid JSON.',
        invalidJSONStructure: '❌ The JSON file structure is not valid for importing 2FA codes.',
        importConfirmTitle: '📥 Confirm Import',
        importConfirmMessage: 'Are you sure you want to import {count} codes from this JSON file?',
        importResultMessage: '📊 Import completed: {imported} imported, {duplicates} duplicates skipped, {errors} errors.',
        importError: '❌ Import error: ',
        
        // Encrypted export/import
        encryptedBackup: '🔒 Encrypted Backup',
        encryptedImportTitle: '🔒 Import from Encrypted Backup',
        encryptedImportDesc: 'Import codes from an encrypted file (OpenSSL AES-256-CBC compatible).',
        selectEncryptedFile: '📂 Select Encrypted File',
        encryptedExportTitle: '🔒 Export Encrypted Backup',
        encryptedExportPasswordChoice: 'Which password do you want to use to encrypt the backup?',
        useCurrentPassword: '🔐 Use current master password',
        useCustomPassword: '🔑 Use custom password',
        customPasswordTitle: '🔑 Custom Password',
        enterCustomPasswordPrompt: 'Enter a password to encrypt the backup (minimum 8 characters):',
        confirmPasswordTitle: '🔐 Confirm Password',
        confirmCustomPasswordPrompt: 'Confirm the password:',
        noMasterPasswordAvailable: '❌ No master password available for encryption.',
        encryptedBackupDownloaded: '✅ Encrypted backup downloaded! Compatible with OpenSSL AES-256-CBC.',
        decryptionPasswordTitle: '🔓 Decryption Password',
        enterDecryptionPassword: 'Enter the password to decrypt the file:',
        decryptionFailed: '❌ Failed to decrypt file. Please check the password.',
        invalidEncryptedFileType: '❌ Please select a valid encrypted file (.enc, .dat, .bin).',
        enterPassword: 'Enter password',
        confirmPassword: 'Confirm password',
        enterConfirmPassword: 'Confirm the password',
        passwordsMatch: 'Passwords match',
        
        // Empty state
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

  // Export to global scope
  window.i18n = i18n;
  window.i18n = i18n;

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
                    <button class="btn-cancel">${cancelText}</button>
                    <button class="btn-confirm">${confirmText}</button>
                </div>
            </div>
        `;

        // Add event listeners
        const cancelBtn = confirmDialog.querySelector('.btn-cancel');
        const confirmBtn = confirmDialog.querySelector('.btn-confirm');
        
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
     * Simple confirm dialog - returns Promise
     */
    async confirm(message, title = '') {
        return new Promise((resolve) => {
            const confirmId = `confirm-${Date.now()}`;
            
            const notification = document.createElement('div');
            notification.id = confirmId;
            notification.className = 'notification notification-confirm';
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-icon">⚠️</span>
                    <div class="notification-message">
                        ${title ? `<strong>${title}</strong><br><br>` : ''}
                        ${message}
                        <div class="confirm-buttons">
                            <button class="btn-cancel">${window.i18n?.t?.('cancel') || 'Cancelar'}</button>
                            <button class="btn-confirm">${window.i18n?.t?.('confirm') || 'Confirmar'}</button>
                        </div>
                    </div>
                </div>
            `;

            // Add to container
            if (this.container) {
                this.container.appendChild(notification);
            } else {
                document.body.appendChild(notification);
            }

            const cancelBtn = notification.querySelector('.btn-cancel');
            const confirmBtn = notification.querySelector('.btn-confirm');

            const cleanup = () => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            };

            cancelBtn.onclick = () => {
                cleanup();
                resolve(false);
            };

            confirmBtn.onclick = () => {
                cleanup();
                resolve(true);
            };

            // Animate in
            requestAnimationFrame(() => {
                notification.classList.add('notification-show');
            });

            // Focus confirm button
            setTimeout(() => confirmBtn.focus(), 100);
        });
    }

    /**
     * Simple prompt dialog - returns Promise
     */
    async prompt(message, defaultValue = '', title = '', inputType = 'text') {
        return new Promise((resolve) => {
            const promptId = `prompt-${Date.now()}`;
            
            const notification = document.createElement('div');
            notification.id = promptId;
            notification.className = 'notification notification-prompt';
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-icon">💬</span>
                    <div class="notification-message">
                        ${title ? `<strong>${title}</strong><br><br>` : ''}
                        ${message}
                        <input type="${inputType}" class="prompt-input" value="${defaultValue}" style="width: 100%; margin: 10px 0; padding: 8px; border: 2px solid #ddd; border-radius: 4px; font-size: 14px;">
                        <div class="confirm-buttons">
                            <button class="btn-cancel">${window.i18n?.t?.('cancel') || 'Cancelar'}</button>
                            <button class="btn-confirm">${window.i18n?.t?.('accept') || 'Aceptar'}</button>
                        </div>
                    </div>
                </div>
            `;

            // Add to container
            if (this.container) {
                this.container.appendChild(notification);
            } else {
                document.body.appendChild(notification);
            }

            const input = notification.querySelector('.prompt-input');
            const cancelBtn = notification.querySelector('.btn-cancel');
            const confirmBtn = notification.querySelector('.btn-confirm');

            const cleanup = () => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            };

            cancelBtn.onclick = () => {
                cleanup();
                resolve(null);
            };

            confirmBtn.onclick = () => {
                cleanup();
                resolve(input.value);
            };

            // Enter key submits
            input.onkeypress = (e) => {
                if (e.key === 'Enter') {
                    cleanup();
                    resolve(input.value);
                }
            };

            // Animate in and focus
            requestAnimationFrame(() => {
                notification.classList.add('notification-show');
                input.focus();
            });
        });
    }

    /**
     * Alias for showNotification
     */
    show(message, type = 'info', duration = 3000) {
        return this.showNotification(message, type, duration);
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
     * Prompt for password with confirmation (double entry)
     * @param {string} message - The message to display
     * @param {string} title - Optional dialog title
     * @returns {Promise<string|null>} - The password if confirmed, null if cancelled
     */
    async promptPasswordConfirm(message, title = '') {
        return new Promise((resolve) => {
            const promptId = `prompt-password-${Date.now()}`;
            
            const notification = document.createElement('div');
            notification.id = promptId;
            notification.className = 'notification notification-prompt notification-password-confirm';
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-icon">🔐</span>
                    <div class="notification-message">
                        ${title ? `<strong>${title}</strong><br><br>` : ''}
                        ${message}
                        <div style="margin: 15px 0;">
                            <label style="display: block; margin-bottom: 5px; font-weight: bold;">Contraseña:</label>
                            <input type="password" class="prompt-input-1" placeholder="${window.i18n?.t?.('enterPassword') || 'Introducir contraseña'}" style="width: 100%; margin-bottom: 10px; padding: 8px; border: 2px solid #ddd; border-radius: 4px; font-size: 14px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: bold;">Confirmar contraseña:</label>
                            <input type="password" class="prompt-input-2" placeholder="${window.i18n?.t?.('confirmPassword') || 'Confirmar contraseña'}" style="width: 100%; padding: 8px; border: 2px solid #ddd; border-radius: 4px; font-size: 14px;">
                            <div class="password-status" style="margin-top: 8px; font-size: 12px; min-height: 16px;"></div>
                        </div>
                        <div class="confirm-buttons">
                            <button class="btn-cancel">${window.i18n?.t?.('cancel') || 'Cancelar'}</button>
                            <button class="btn-confirm" disabled>${window.i18n?.t?.('accept') || 'Aceptar'}</button>
                        </div>
                    </div>
                </div>
            `;

            // Add to container
            if (this.container) {
                this.container.appendChild(notification);
            } else {
                document.body.appendChild(notification);
            }

            const input1 = notification.querySelector('.prompt-input-1');
            const input2 = notification.querySelector('.prompt-input-2');
            const statusDiv = notification.querySelector('.password-status');
            const cancelBtn = notification.querySelector('.btn-cancel');
            const confirmBtn = notification.querySelector('.btn-confirm');

            // Password validation function
            const validatePasswords = () => {
                const pass1 = input1.value;
                const pass2 = input2.value;
                
                if (pass1.length === 0 && pass2.length === 0) {
                    statusDiv.textContent = '';
                    statusDiv.style.color = '';
                    confirmBtn.disabled = true;
                    return;
                }

                if (pass1.length < 8) {
                    statusDiv.textContent = window.i18n?.t?.('passwordTooShort') || 'La contraseña debe tener al menos 8 caracteres';
                    statusDiv.style.color = '#dc3545';
                    confirmBtn.disabled = true;
                    return;
                }

                if (pass2.length === 0) {
                    statusDiv.textContent = window.i18n?.t?.('enterConfirmPassword') || 'Confirma la contraseña';
                    statusDiv.style.color = '#6c757d';
                    confirmBtn.disabled = true;
                    return;
                }

                if (pass1 !== pass2) {
                    statusDiv.textContent = window.i18n?.t?.('passwordMismatch') || 'Las contraseñas no coinciden';
                    statusDiv.style.color = '#dc3545';
                    confirmBtn.disabled = true;
                    return;
                }

                statusDiv.textContent = '✅ ' + (window.i18n?.t?.('passwordsMatch') || 'Las contraseñas coinciden');
                statusDiv.style.color = '#28a745';
                confirmBtn.disabled = false;
            };

            // Add event listeners for real-time validation
            input1.oninput = validatePasswords;
            input2.oninput = validatePasswords;

            const cleanup = () => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            };

            cancelBtn.onclick = () => {
                cleanup();
                resolve(null);
            };

            confirmBtn.onclick = () => {
                if (!confirmBtn.disabled) {
                    cleanup();
                    resolve(input1.value);
                }
            };

            // Enter key on second input submits if valid
            input2.onkeypress = (e) => {
                if (e.key === 'Enter' && !confirmBtn.disabled) {
                    cleanup();
                    resolve(input1.value);
                }
            };

            // Tab navigation
            input1.onkeydown = (e) => {
                if (e.key === 'Tab') {
                    e.preventDefault();
                    input2.focus();
                }
            };

            // Escape key cancels
            const handleKeydown = (e) => {
                if (e.key === 'Escape') {
                    document.removeEventListener('keydown', handleKeydown);
                    cleanup();
                    resolve(null);
                }
            };
            document.addEventListener('keydown', handleKeydown);

            // Animate in and focus
            requestAnimationFrame(() => {
                notification.classList.add('notification-show');
                input1.focus();
            });
        });
    }

    /**
     * Show options dialog with multiple choices
     * @param {string} message - The message to display
     * @param {Array} options - Array of option objects with {key, text} properties
     * @param {string} title - Optional dialog title
     * @returns {Promise<string>} - The key of the selected option
     */
    async showOptions(message, options, title = '') {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'modal-overlay';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
            `;

            const dialog = document.createElement('div');
            dialog.className = 'modal-dialog';
            dialog.style.cssText = `
                background: white;
                border-radius: 12px;
                padding: 24px;
                max-width: 400px;
                width: 90%;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                text-align: center;
            `;

            const titleElement = title ? `<h3 style="margin: 0 0 16px 0; color: #333;">${title}</h3>` : '';
            const messageElement = `<p style="margin: 0 0 20px 0; color: #666; line-height: 1.4;">${message}</p>`;
            
            const optionsHTML = options.map(option => 
                `<button class="option-btn" data-key="${option.key}" style="
                    display: block;
                    width: 100%;
                    padding: 12px 16px;
                    margin: 8px 0;
                    border: 2px solid #ddd;
                    border-radius: 8px;
                    background: white;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    font-size: 14px;
                    text-align: left;
                ">${option.text}</button>`
            ).join('');

            const cancelBtn = `
                <button class="btn-cancel" style="
                    padding: 10px 24px;
                    margin-top: 16px;
                    border: 2px solid #ccc;
                    border-radius: 6px;
                    background: #f8f9fa;
                    cursor: pointer;
                    font-size: 14px;
                    color: #666;
                ">${window.i18n?.t('cancelBtn') || 'Cancelar'}</button>
            `;

            dialog.innerHTML = titleElement + messageElement + optionsHTML + cancelBtn;
            modal.appendChild(dialog);

            // Add hover effects
            dialog.addEventListener('mouseover', (e) => {
                if (e.target.classList.contains('option-btn')) {
                    e.target.style.borderColor = '#007bff';
                    e.target.style.background = '#f8f9ff';
                }
            });

            dialog.addEventListener('mouseout', (e) => {
                if (e.target.classList.contains('option-btn')) {
                    e.target.style.borderColor = '#ddd';
                    e.target.style.background = 'white';
                }
            });

            // Handle clicks
            dialog.addEventListener('click', (e) => {
                if (e.target.classList.contains('option-btn')) {
                    const key = e.target.getAttribute('data-key');
                    document.body.removeChild(modal);
                    resolve(key);
                } else if (e.target.classList.contains('btn-cancel')) {
                    document.body.removeChild(modal);
                    resolve(null);
                }
            });

            // Handle escape key
            const handleKeydown = (e) => {
                if (e.key === 'Escape') {
                    document.removeEventListener('keydown', handleKeydown);
                    document.body.removeChild(modal);
                    resolve(null);
                }
            };
            document.addEventListener('keydown', handleKeydown);

            document.body.appendChild(modal);

            // Focus the first option
            setTimeout(() => {
                const firstOption = dialog.querySelector('.option-btn');
                if (firstOption) firstOption.focus();
            }, 100);
        });
    }

    /**
     * Get icon for notification type
     * @param {string} type - Notification type
     * @returns {string} - Icon string
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

  // Export to global scope
  window.NotificationSystem = NotificationSystem;
  window.notificationSystem = notificationSystem;

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
   * Clear only TOTP secrets but keep configuration and master password
   * @returns {Promise<void>}
   */
  async clearAllTOTPSecrets() {
    // Fallback to localStorage if IndexedDB is not available
    if (!this.db) {
      try {
        // Clear only TOTP secrets from localStorage, keep config
        localStorage.removeItem('personal-2fa-secrets');
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(new Error('Failed to clear TOTP secrets from localStorage'));
      }
    }

    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const clearRequest = store.clear();
      
      clearRequest.onsuccess = () => {
        // Don't reset encryptionKey or isInitialized - keep them for continued use
        resolve();
      };
      
      clearRequest.onerror = () => {
        reject(new Error('Failed to clear TOTP secrets'));
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
      
      // Initialize language selector
      this.initializeLanguageSelector();
      
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
      this.showError(i18n.t('initError') + error.message);
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
      showCodesBtn: document.getElementById('show-codes-btn'),
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
      
      // JSON Import
      jsonFileInput: document.getElementById('json-file-input'),
      selectJSONFile: document.getElementById('select-json-file'),
      selectedFileName: document.getElementById('selected-file-name'),

      // Encrypted Import
      encryptedFileInput: document.getElementById('encrypted-file-input'),
      selectEncryptedFile: document.getElementById('select-encrypted-file'),
      selectedEncryptedFileName: document.getElementById('selected-encrypted-file-name'),

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
      exportEncryptedBackup: document.getElementById('export-encrypted-backup'),
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
      cancelImport: document.getElementById('cancel-import'),
      cancelExport: document.getElementById('cancel-export'),
      
      // Data Management
      clearAllData: document.getElementById('clear-all-data'),
      factoryReset: document.getElementById('factory-reset'),
      logsEnabledToggle: document.getElementById('logs-enabled-toggle'),
      
      // Security indicators
      cryptoStatus: document.getElementById('crypto-status'),
      storageStatus: document.getElementById('storage-status'),
      networkStatus: document.getElementById('network-status'),
      securityChecks: document.getElementById('security-checks'),
      
      // Language selector
      languageSelect: document.getElementById('language-select')
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
    this.elements.showCodesBtn.addEventListener('click', () => this.showCodesSection());
    this.elements.importBtn.addEventListener('click', () => this.showImportSection());
    this.elements.exportBtn.addEventListener('click', () => this.showExportSection());
    this.elements.addManualBtn.addEventListener('click', () => this.showManualAddSection());
    this.elements.manageDataBtn.addEventListener('click', () => this.showDataManagementSection());
    this.elements.lockBtn.addEventListener('click', () => this.lockApp());
    
    // JSON Import
    this.elements.selectJSONFile.addEventListener('click', () => this.elements.jsonFileInput.click());
    this.elements.jsonFileInput.addEventListener('change', (e) => this.handleJSONFileSelect(e));

    // Encrypted Import
    this.elements.selectEncryptedFile.addEventListener('click', () => this.elements.encryptedFileInput.click());
    this.elements.encryptedFileInput.addEventListener('change', (e) => this.handleEncryptedFileSelect(e));

    // QR Scanner
    this.elements.startCamera.addEventListener('click', () => this.startQRScanning());
    this.elements.stopCamera.addEventListener('click', () => this.stopQRScanning());
    
    // Export buttons
    this.elements.exportGoogleFormat.addEventListener('click', () => this.exportGoogleFormat());
    this.elements.exportIndividualQR.addEventListener('click', () => this.exportIndividualQR());
    this.elements.exportJSONBackup.addEventListener('click', () => this.exportJSONBackup());
    this.elements.exportEncryptedBackup.addEventListener('click', () => this.exportEncryptedBackup());
    
    // Manual add form
    this.elements.manualAddForm.addEventListener('submit', (e) => this.handleManualAdd(e));
    this.elements.cancelManual.addEventListener('click', () => {
      this.showCodesSection(); // Show codes section when canceling
    });
    
    // Cancel buttons for import/export
    this.elements.cancelImport.addEventListener('click', () => {
      this.showCodesSection(); // Show codes section when canceling
    });
    
    this.elements.cancelExport.addEventListener('click', () => {
      this.showCodesSection(); // Show codes section when canceling
    });
    
    // Data management
    this.elements.clearAllData.addEventListener('click', () => this.handleClearAllData());
    this.elements.factoryReset.addEventListener('click', () => this.handleFactoryReset());
    this.elements.logsEnabledToggle.addEventListener('change', (e) => this.handleLogsToggle(e));
    
    // Language selector
    this.elements.languageSelect.addEventListener('change', (e) => this.handleLanguageChange(e));
    
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
        this.showError(i18n.t('passwordTooShort'));
        return;
      }
      
      if (password !== confirmPassword) {
        this.showError(i18n.t('passwordMismatch'));
        return;
      }
      
      logger.log('🔐 Setting up master password...');
      
      // Show progress notification
      const progressId = notificationSystem.showNotification(
        i18n.t('configuringPassword'),
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
      this.showSuccess(i18n.t('setupComplete'));
      
    } catch (error) {
      logger.error('❌ Setup failed:', error);
      this.showError(i18n.t('setupError') + error.message);
    }
  }

  /**
   * Handle login with master password
   */
  async handleLogin() {
    const password = this.elements.loginPassword.value;
    
    if (!password) {
      this.showLoginError(i18n.t('enterPassword'));
      return;
    }
    
    try {
      logger.log('🔓 Attempting to unlock storage...');
      const success = await storageManager.unlock(password);
      
      if (success) {
        this.isUnlocked = true;
        // Store password for export functionality
        cryptoManager.setMasterPassword(password);
        this.showScreen('main');
        this.showCodesSection(); // Show codes section by default
        this.refreshTOTPCodes();
        logger.log('✅ Storage unlocked successfully');
      } else {
        this.showLoginError(i18n.t('invalidPassword'));
      }
    } catch (error) {
      logger.error('❌ Login failed:', error);
      this.showLoginError(i18n.t('loginFailed') + error.message);
    }
  }

  /**
   * Update active button state
   */
  updateActiveButton(activeButton) {
    // Remove active class from all navigation buttons
    const navButtons = [
      this.elements.showCodesBtn,
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
    
    // No automatic scroll - sections are positioned naturally after codes
  }

  /**
   * Show export section and hide others
   */
  showExportSection() {
    this.hideAllSections();
    this.updateActiveButton(this.elements.exportBtn);
    this.elements.exportSection.classList.remove('hidden');
    
    // No automatic scroll - sections are positioned naturally after codes
  }

  /**
   * Show manual add section and hide others
   */
  showManualAddSection() {
    this.hideAllSections();
    this.updateActiveButton(this.elements.addManualBtn);
    this.elements.manualAddSection.classList.remove('hidden');
    
    // No automatic scroll - sections are positioned naturally after codes
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
    
    // No automatic scroll - sections are positioned naturally after codes
  }

  /**
   * Hide all sections
   */
  hideAllSections() {
    const sections = [
      this.elements.importSection,
      this.elements.exportSection,
      this.elements.manualAddSection,
      this.elements.dataManagementSection,
      this.elements.codesSection
    ];
    
    sections.forEach(section => section.classList.add('hidden'));
    
    // Clear active states when hiding sections via other means (like cancel buttons)
    // Note: This will be overridden by updateActiveButton when showing a new section
  }

  /**
   * Show only the codes section (default view)
   */
  showCodesSection() {
    this.hideAllSections();
    this.elements.codesSection.classList.remove('hidden');
    this.updateActiveButton(this.elements.showCodesBtn); // Mark "Ver Códigos" button as active
  }

  /**
   * Start QR code scanning
   */
  async startQRScanning() {
    try {
      logger.log('📹 Starting QR scanner...');
      
      this.elements.startCamera.classList.add('hidden');
      this.elements.stopCamera.classList.remove('hidden');
      this.elements.scanResult.innerHTML = `<div class="scanning">${i18n.t('scanningQR')}</div>`;
      
      await qrManager.startScanning((qrData) => {
        this.handleQRDetected(qrData);
      });
      
    } catch (error) {
      logger.error('❌ Failed to start camera:', error);
      this.elements.scanResult.innerHTML = `<div class="error">${i18n.t('cameraError')}${error.message}</div>`;
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
      this.elements.scanResult.innerHTML = `<div class="error">${i18n.t('qrError')}${error.message}</div>`;
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
          ${i18n.t('importSuccessMessage')} (${importedCount})
        </div>
      `;
      
      // Refresh the TOTP display
      this.refreshTOTPCodes();
      
    } catch (error) {
      logger.error('❌ Import failed:', error);
      this.elements.scanResult.innerHTML = `<div class="error">${i18n.t('importFailedMessage')}${error.message}</div>`;
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
      
      // Reset form and show codes section
      this.elements.manualAddForm.reset();
      this.showCodesSection();
      
      // Refresh display
      this.refreshTOTPCodes();
      
    } catch (error) {
      logger.error('❌ Manual add failed:', error);
      this.showError(i18n.t('addTotpError') + error.message);
    }
  }

  /**
   * Handle JSON file selection for import
   */
  handleJSONFileSelect(event) {
    const file = event.target.files[0];
    if (!file) {
      this.elements.selectedFileName.textContent = '';
      return;
    }

    if (!file.name.toLowerCase().endsWith('.json')) {
      notificationSystem.showNotification(i18n.t('invalidFileType'), 'error');
      this.elements.selectedFileName.textContent = '';
      return;
    }

    this.elements.selectedFileName.textContent = file.name;
    this.importJSONFile(file);
  }

  /**
   * Import TOTP codes from JSON file
   */
  async importJSONFile(file) {
    try {
      logger.log(`📥 Starting import from JSON file: ${file.name}`);

      // Read file content
      const fileContent = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsText(file);
      });

      // Parse JSON
      let jsonData;
      try {
        jsonData = JSON.parse(fileContent);
      } catch (parseError) {
        throw new Error(i18n.t('invalidJSONFormat'));
      }

      // Validate JSON structure
      if (!this.validateJSONImport(jsonData)) {
        throw new Error(i18n.t('invalidJSONStructure'));
      }

      // Show confirmation dialog
      const importConfirm = await notificationSystem.confirm(
        i18n.t('importConfirmMessage').replace('{count}', jsonData.secrets?.length || 0),
        i18n.t('importConfirmTitle')
      );

      if (!importConfirm) {
        logger.log('🔒 JSON import cancelled by user');
        return;
      }

      // Import secrets
      let importedCount = 0;
      let duplicateCount = 0;
      let errorCount = 0;

      for (const secretData of jsonData.secrets || []) {
        try {
          // Check if secret already exists
          const existingSecrets = await storageManager.getAllTOTPSecrets();
          const isDuplicate = existingSecrets.some(existing => 
            existing.issuer === secretData.issuer && 
            existing.label === secretData.label
          );

          if (isDuplicate) {
            duplicateCount++;
            logger.log(`⚠️ Skipping duplicate: ${secretData.issuer}:${secretData.label}`);
            continue;
          }

          // Add secret to storage
          await storageManager.storeTOTPSecret(secretData);
          importedCount++;
          logger.log(`✅ Imported: ${secretData.issuer}:${secretData.label}`);

        } catch (error) {
          errorCount++;
          logger.error(`❌ Failed to import ${secretData.issuer}:${secretData.label}:`, error);
        }
      }

      // Show results
      const resultMessage = i18n.t('importResultMessage')
        .replace('{imported}', importedCount)
        .replace('{duplicates}', duplicateCount)
        .replace('{errors}', errorCount);

      notificationSystem.showNotification(resultMessage, importedCount > 0 ? 'success' : 'warning');

      if (importedCount > 0) {
        // Refresh display and show codes section
        this.refreshTOTPCodes();
        this.showCodesSection();
      }

      // Clear file input
      this.elements.jsonFileInput.value = '';
      this.elements.selectedFileName.textContent = '';

    } catch (error) {
      logger.error('❌ JSON import failed:', error);
      notificationSystem.showNotification(i18n.t('importError') + error.message, 'error');
      
      // Clear file input
      this.elements.jsonFileInput.value = '';
      this.elements.selectedFileName.textContent = '';
    }
  }

  /**
   * Validate JSON import structure
   */
  validateJSONImport(jsonData) {
    if (!jsonData || typeof jsonData !== 'object') {
      return false;
    }

    if (!Array.isArray(jsonData.secrets)) {
      return false;
    }

    // Validate each secret
    for (const secret of jsonData.secrets) {
      if (!secret.issuer || !secret.label || !secret.secret) {
        return false;
      }
    }

    return true;
  }

  /**
   * Handle encrypted file selection for import
   */
  handleEncryptedFileSelect(event) {
    const file = event.target.files[0];
    if (!file) {
      this.elements.selectedEncryptedFileName.textContent = '';
      return;
    }

    const allowedExtensions = ['.enc', '.dat', '.bin'];
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
    
    if (!allowedExtensions.includes(fileExtension)) {
      notificationSystem.showNotification(i18n.t('invalidEncryptedFileType'), 'error');
      this.elements.selectedEncryptedFileName.textContent = '';
      return;
    }

    this.elements.selectedEncryptedFileName.textContent = file.name;
    this.importEncryptedFile(file);
  }

  /**
   * Import TOTP codes from encrypted file
   */
  async importEncryptedFile(file) {
    try {
      logger.log(`📥 Starting import from encrypted file: ${file.name}`);

      // Read file content as ArrayBuffer
      const fileContent = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(file);
      });

      // Ask for decryption password
      const decryptionPassword = await notificationSystem.prompt(
        i18n.t('enterDecryptionPassword'),
        '',
        i18n.t('decryptionPasswordTitle'),
        'password'
      );

      if (!decryptionPassword) {
        logger.log('🔒 Encrypted import cancelled by user');
        return;
      }

      // Decrypt the data
      let jsonData;
      try {
        const decryptedData = await cryptoManager.decryptFromImport(fileContent, decryptionPassword);
        jsonData = JSON.parse(decryptedData);
      } catch (decryptError) {
        throw new Error(i18n.t('decryptionFailed'));
      }

      // Validate JSON structure
      if (!this.validateJSONImport(jsonData)) {
        throw new Error(i18n.t('invalidJSONStructure'));
      }

      // Show confirmation dialog
      const importConfirm = await notificationSystem.confirm(
        i18n.t('importConfirmMessage').replace('{count}', jsonData.secrets?.length || 0),
        i18n.t('importConfirmTitle')
      );

      if (!importConfirm) {
        logger.log('🔒 Encrypted import cancelled by user');
        return;
      }

      // Import secrets (reuse the same logic as JSON import)
      let importedCount = 0;
      let duplicateCount = 0;
      let errorCount = 0;

      for (const secretData of jsonData.secrets || []) {
        try {
          // Check if secret already exists
          const existingSecrets = await storageManager.getAllTOTPSecrets();
          const isDuplicate = existingSecrets.some(existing => 
            existing.issuer === secretData.issuer && 
            existing.label === secretData.label
          );

          if (isDuplicate) {
            duplicateCount++;
            logger.log(`⚠️ Skipping duplicate: ${secretData.issuer}:${secretData.label}`);
            continue;
          }

          // Add secret to storage
          await storageManager.storeTOTPSecret(secretData);
          importedCount++;
          logger.log(`✅ Imported: ${secretData.issuer}:${secretData.label}`);

        } catch (error) {
          errorCount++;
          logger.error(`❌ Failed to import ${secretData.issuer}:${secretData.label}:`, error);
        }
      }

      // Show results
      const resultMessage = i18n.t('importResultMessage')
        .replace('{imported}', importedCount)
        .replace('{duplicates}', duplicateCount)
        .replace('{errors}', errorCount);

      notificationSystem.showNotification(resultMessage, importedCount > 0 ? 'success' : 'warning');

      if (importedCount > 0) {
        // Refresh display and show codes section
        this.refreshTOTPCodes();
        this.showCodesSection();
      }

      // Clear file input
      this.elements.encryptedFileInput.value = '';
      this.elements.selectedEncryptedFileName.textContent = '';

    } catch (error) {
      logger.error('❌ Encrypted import failed:', error);
      notificationSystem.showNotification(i18n.t('importError') + error.message, 'error');
      
      // Clear file input
      this.elements.encryptedFileInput.value = '';
      this.elements.selectedEncryptedFileName.textContent = '';
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
      // Ensure ID is a number (it comes as string from HTML onclick)
      const numericId = parseInt(secretId, 10);
      if (isNaN(numericId)) {
        logger.error('❌ Invalid secret ID:', secretId);
        notificationSystem.showNotification(i18n.t('deleteError'), 'error');
        return;
      }

      // First confirmation dialog
      const firstConfirm = await notificationSystem.confirm(
        i18n.t('deleteCodeMessage').replace('{issuer}', issuer).replace('{label}', label),
        i18n.t('deleteCodeTitle')
      );

      if (!firstConfirm) {
        logger.log('🔒 Delete cancelled by user (first confirmation)');
        return;
      }

      // Second confirmation with text input for safety
      const deleteWord = i18n.getCurrentLanguage() === 'es' ? 'ELIMINAR' : 'DELETE';
      const confirmText = await notificationSystem.prompt(
        i18n.t('deletePromptMessage').replace('{issuer}', issuer).replace('{label}', label),
        '',
        i18n.t('deleteConfirmationTitle')
      );

      if (confirmText !== deleteWord) {
        logger.log('🔒 Delete cancelled - incorrect confirmation text');
        notificationSystem.showNotification(i18n.t('deleteTextError'), 'error');
        return;
      }

      logger.log(`🗑️ Deleting TOTP: ${issuer}:${label} (ID: ${numericId})`);

      // Delete from storage first
      await storageManager.deleteTOTPSecret(numericId);

      logger.log(`✅ Successfully deleted TOTP: ${issuer}:${label}`);

      // Add animation to element if it exists
      const totpElement = document.querySelector(`[data-id="${numericId}"]`);
      if (totpElement) {
        totpElement.classList.add('deleting');
        
        // Wait for animation to complete before refreshing
        setTimeout(() => {
          this.refreshTOTPCodes();
        }, 500); // Animation duration
      } else {
        // If element not found, refresh immediately
        this.refreshTOTPCodes();
      }

      // Show success message
      notificationSystem.showNotification(
        i18n.t('deleteSuccessMessage').replace('{issuer}', issuer).replace('{label}', label),
        'success'
      );

    } catch (error) {
      logger.error('❌ Failed to delete TOTP:', error);
      this.showError(i18n.t('deleteError') + error.message);
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
      const firstConfirm = await notificationSystem.confirm(
        i18n.t('clearAllWarning'),
        i18n.t('deleteAllDataTitle')
      );
      
      if (!firstConfirm) {
        logger.log('🔒 Clear data cancelled by user (first confirmation)');
        return;
      }

      // Second confirmation - Text input required
      const deleteAllPhrase = i18n.getCurrentLanguage() === 'es' ? 'BORRAR TODO' : 'DELETE ALL';
      const secondConfirm = await notificationSystem.prompt(
        i18n.t('clearAllFinalConfirm'),
        '',
        i18n.t('textConfirmationTitle')
      );
      
      if (secondConfirm !== deleteAllPhrase) {
        logger.log('🔒 Clear data cancelled - incorrect confirmation text');
        notificationSystem.showNotification(i18n.t('clearAllTextError'), 'error');
        return;
      }

      // Third and final confirmation
      const finalConfirm = await notificationSystem.confirm(
        i18n.t('clearAllLastChance'),
        i18n.t('finalConfirmationTitle')
      );
      
      if (!finalConfirm) {
        logger.log('🔒 Clear data cancelled by user (final confirmation)');
        return;
      }

      logger.log('🗑️ User confirmed data deletion. Proceeding...');
      
      // Show progress message
      const progressId = notificationSystem.showNotification(i18n.t('clearCodesProgress'), 'progress', 0);
      
      // Clear only TOTP codes (keep configuration and master password)
      await this.clearOnlyTOTPCodes();
      
      // Remove progress notification
      notificationSystem.removeNotification(progressId);
      
      // Show success message
      notificationSystem.showNotification(
        i18n.t('clearCodesSuccess'),
        'success',
        3000
      );
      
      // Refresh the display without reloading the page
      this.refreshTOTPCodes();
      
    } catch (error) {
      logger.error('❌ Error clearing data:', error);
      this.showError(i18n.t('clearDataError') + error.message);
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
          i18n.t('factoryResetTitle'),
          i18n.t('factoryResetWarning'),
          () => {
            // If confirmed, show second confirmation with text input
            this.showFactoryResetTextConfirmation(resolve);
          },
          () => {
            logger.log('🔒 Factory reset cancelled by user (first confirmation)');
            resolve();
          },
          i18n.t('continueBtn'),
          i18n.t('cancel')
        );
      });
    } catch (error) {
      logger.error('❌ Factory reset failed:', error);
      notificationSystem.showNotification(
        i18n.t('factoryResetError') + error.message,
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
          <strong class="confirm-title">${i18n.t('factoryResetConfirmTitle')}</strong>
        </div>
        <div class="confirm-message">
          ${i18n.t('factoryResetConfirmMessage')}
        </div>
        <div class="factory-reset-input">
          <input type="text" id="factory-reset-text" placeholder="${i18n.t('factoryResetPlaceholder')}" 
                 style="width: 100%; padding: 10px; margin: 10px 0; font-size: 14px; border: 2px solid #ccc; border-radius: 4px;">
        </div>
        <div class="confirm-buttons">
          <button class="btn-confirm-cancel">${i18n.t('cancel')}</button>
          <button class="btn-confirm-ok">${i18n.t('continueBtn')}</button>
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
        notificationSystem.showNotification(i18n.t('factoryResetTextError'), 'error');
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
      i18n.t('factoryResetFinalTitle'),
      i18n.t('factoryResetFinalMessage'),
      async () => {
        logger.log('🔄 User confirmed factory reset. Proceeding with complete reset...');
        
        // Show progress notification
        const progressId = notificationSystem.showNotification(
          i18n.t('factoryResetProgress'),
          'progress',
          0 // No auto-hide
        );

        try {
          // Update progress
          notificationSystem.updateProgress(progressId, i18n.t('factoryResetClearing'), 25);
          
          // Perform complete factory reset
          await this.performFactoryReset();
          
          // Update progress
          notificationSystem.updateProgress(progressId, 'Factory Reset completado', 100);
          
        } catch (error) {
          // Even if factory reset fails, force clear and continue
          logger.error('Factory reset error, forcing cleanup:', error);
          localStorage.clear();
          sessionStorage.clear();
          notificationSystem.updateProgress(progressId, i18n.t('factoryResetForcing'), 90);
        }
        
        // Always remove progress notification and reload
        setTimeout(() => {
          notificationSystem.removeNotification(progressId);
          
          // Show completion and reload immediately
          notificationSystem.showNotification(
            i18n.t('factoryResetComplete'),
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
      i18n.t('executeResetBtn'),
      i18n.t('cancel')
    );
  }

  /**
   * Clear all application data from all storage mechanisms
   */
  /**
   * Clear only TOTP codes but keep master password and app configuration
   */
  async clearOnlyTOTPCodes() {
    logger.log('🧹 Starting TOTP codes cleanup (keeping config)...');
    
    try {
      // Only clear TOTP secrets from IndexedDB, keep other data
      logger.log('🗑️ Clearing TOTP codes from storage...');
      if (storageManager) {
        await storageManager.clearAllTOTPSecrets();
      }
      
      // Reset display state but keep authentication
      this.currentCodes = [];
      
      logger.log('✅ TOTP codes cleared successfully (configuration preserved)');
      
    } catch (error) {
      logger.error('❌ Error during TOTP cleanup:', error);
      throw error;
    }
  }

  /**
   * Clear all application data including configuration and master password
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
   * Clear only TOTP codes while preserving configuration and master password
   */
  async clearOnlyTOTPCodes() {
    logger.log('🧹 Starting TOTP codes cleanup...');
    
    try {
      // Only clear TOTP secrets from storage
      if (storageManager) {
        await storageManager.clearAllTOTPSecrets();
      }
      
      // Reset application state for TOTP codes
      this.currentCodes = [];
      
      logger.log('✅ TOTP codes cleared successfully (configuration preserved)');
      
    } catch (error) {
      logger.error('❌ Error during TOTP codes cleanup:', error);
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
      logger.log('🚀 Starting Google format export...');
      const secrets = await storageManager.getAllTOTPSecrets();
      logger.log(`📊 Found ${secrets.length} secrets to export`);
      
      if (secrets.length === 0) {
        notificationSystem.showNotification(i18n.t('noCodesForExport'), 'warning');
        return;
      }

      const qrCodes = await googleAuthManager.generateExportQRs(secrets, 'migration');
      logger.log(`📱 Generated ${qrCodes.length} QR codes`);
      this.displayExportResult(qrCodes, i18n.t('googleAuthMigrationTitle'));
    } catch (error) {
      logger.error('❌ Google format export failed:', error);
      this.showError(i18n.t('exportError') + error.message);
    }
  }

  /**
   * Export individual QR codes
   */
  async exportIndividualQR() {
    try {
      logger.log('🚀 Starting individual QR export...');
      const secrets = await storageManager.getAllTOTPSecrets();
      logger.log(`📊 Found ${secrets.length} secrets to export`);
      
      if (secrets.length === 0) {
        notificationSystem.showNotification(i18n.t('noCodesForExport'), 'warning');
        return;
      }

      const qrCodes = await googleAuthManager.generateExportQRs(secrets, 'individual');
      logger.log(`📱 Generated ${qrCodes.length} QR codes`);
      this.displayExportResult(qrCodes, i18n.t('individualQRTitle'));
    } catch (error) {
      logger.error('❌ Individual QR export failed:', error);
      this.showError(i18n.t('exportError') + error.message);
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
      
      this.elements.exportResult.innerHTML = `<div class="success">${i18n.t('jsonDownloaded')}</div>`;
      
    } catch (error) {
      logger.error('❌ JSON export failed:', error);
      this.showError(i18n.t('exportError') + error.message);
    }
  }

  /**
   * Export encrypted backup (OpenSSL compatible)
   */
  async exportEncryptedBackup() {
    try {
      logger.log('🚀 Starting encrypted backup export...');
      const secrets = await storageManager.getAllTOTPSecrets();
      
      if (secrets.length === 0) {
        notificationSystem.showNotification(i18n.t('noCodesForExport'), 'warning');
        return;
      }

      // Show password dialog
      const exportOptions = [
        { key: 'useCurrentPassword', text: i18n.t('useCurrentPassword') },
        { key: 'useCustomPassword', text: i18n.t('useCustomPassword') }
      ];

      const passwordChoice = await notificationSystem.showOptions(
        i18n.t('encryptedExportPasswordChoice'),
        exportOptions,
        i18n.t('encryptedExportTitle')
      );

      let encryptionPassword;
      if (passwordChoice === 'useCurrentPassword') {
        // Use current master password
        encryptionPassword = cryptoManager.getMasterPassword();
        if (!encryptionPassword) {
          throw new Error(i18n.t('noMasterPasswordAvailable'));
        }
      } else if (passwordChoice === 'useCustomPassword') {
        // Ask for custom password with confirmation
        encryptionPassword = await notificationSystem.promptPasswordConfirm(
          i18n.t('enterCustomPasswordPrompt'),
          i18n.t('customPasswordTitle')
        );
        
        if (!encryptionPassword) {
          logger.log('🔒 Encrypted export cancelled by user');
          return;
        }
      } else {
        logger.log('🔒 Encrypted export cancelled by user');
        return;
      }

      // Create JSON data
      const jsonData = await googleAuthManager.exportToJSON(secrets);
      
      // Encrypt the data
      const encryptedData = await cryptoManager.encryptForExport(jsonData, encryptionPassword);
      
      // Create download link
      const blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `personal-2fa-backup-${new Date().toISOString().split('T')[0]}.enc`;
      link.click();
      
      URL.revokeObjectURL(url);
      
      this.elements.exportResult.innerHTML = `<div class="success">${i18n.t('encryptedBackupDownloaded')}</div>`;
      logger.log('✅ Encrypted backup exported successfully');
      
    } catch (error) {
      logger.error('❌ Encrypted export failed:', error);
      this.showError(i18n.t('exportError') + error.message);
    }
  }

  /**
   * Display export results
   */
  displayExportResult(qrCodes, title) {
    if (!qrCodes || qrCodes.length === 0) {
      this.elements.exportResult.innerHTML = `<p>${i18n.t('noQRGenerated')}</p>`;
      return;
    }

    let html = `<h4>${title}</h4>`;
    
    qrCodes.forEach((qr, index) => {
      const qrTitle = qr.type === 'individual' 
        ? `${qr.issuer}: ${qr.label}` 
        : `${i18n.t('batchLabel')} ${qr.batchNumber}/${qr.totalBatches}`;
      
      html += `
        <div class="export-qr">
          <h5>${qrTitle}</h5>
          <img src="${qr.qrCode}" alt="QR Code ${index + 1}" style="max-width: 300px; border: 1px solid #ccc; padding: 10px;">
          <br>
          <small>${i18n.t('qrCodeInstruction')}</small>
        </div>
      `;
    });
    
    this.elements.exportResult.innerHTML = html;
    logger.log(`✅ Displayed ${qrCodes.length} QR codes in export result`);
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
      this.showError(i18n.t('totpLoadError') + error.message);
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
      this.showError(i18n.t('securityWarning'));
    }
  }

  /**
   * Update network status indicator
   */
  updateNetworkStatus() {
    const isOnline = navigator.onLine;
    if (window.i18n) {
      this.elements.networkStatus.textContent = isOnline ? window.i18n.t('networkOnline') : window.i18n.t('networkOffline');
    } else {
      this.elements.networkStatus.textContent = isOnline ? '📡 Online ⚠️' : '📡 Offline ✅';
    }
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

  /**
   * Initialize language selector
   */
  initializeLanguageSelector() {
    // Wait for i18n to be available with a short polling interval
    const waitForI18n = () => {
      if (this.elements.languageSelect && window.i18n) {
        // Set current language in selector to match what's stored
        const currentLang = window.i18n.getCurrentLanguage();
        this.elements.languageSelect.value = currentLang;
        
        // Also update the selector whenever language changes programmatically
        this.updateLanguageSelectorValue = () => {
          if (this.elements.languageSelect && window.i18n) {
            this.elements.languageSelect.value = window.i18n.getCurrentLanguage();
          }
        };
        
        logger.log('🌐 Language selector initialized with:', currentLang);
      } else if (this.elements.languageSelect) {
        // Try again in a few milliseconds
        setTimeout(waitForI18n, 10);
      }
    };
    waitForI18n();
  }

  /**
   * Handle language change
   */
  handleLanguageChange(event) {
    const newLanguage = event.target.value;
    logger.log(`🌐 Language change requested: ${newLanguage}`);
    
    if (window.i18n) {
      window.i18n.setLanguage(newLanguage);
      logger.log(`🌐 Language changed to: ${newLanguage}`);
      
      // Ensure the selector shows the correct value
      this.elements.languageSelect.value = newLanguage;
      
      // Update dynamic content that's not handled by data-i18n attributes
      this.updateDynamicTranslations();
      
      // Force a manual check to ensure all translations are updated
      setTimeout(() => {
        if (window.i18n && window.i18n.updateUI) {
          window.i18n.updateUI();
          // Double-check selector value is correct
          if (this.elements.languageSelect.value !== newLanguage) {
            this.elements.languageSelect.value = newLanguage;
          }
          logger.log('🌐 Forced UI update completed');
        }
      }, 100);
    } else {
      logger.error('❌ window.i18n not available for language change');
    }
  }

  /**
   * Update dynamic translations that can't use data-i18n attributes
   */
  updateDynamicTranslations() {
    if (!window.i18n) return;
    
    // Update security indicators that are set dynamically
    const status = cryptoManager.getSecurityStatus();
    this.elements.cryptoStatus.textContent = status.isSecure ? window.i18n.t('encryption') : '⚠️ ' + window.i18n.t('encryption');
    this.elements.storageStatus.textContent = window.i18n.t('storage');
    this.updateNetworkStatus();
    
    // Update notification buttons if any are currently visible
    document.querySelectorAll('.btn-confirm').forEach(btn => {
      if (btn.textContent === 'Confirmar' || btn.textContent === 'Confirm') {
        btn.textContent = window.i18n.t('confirm');
      }
    });
    
    document.querySelectorAll('.btn-cancel').forEach(btn => {
      if (btn.textContent === 'Cancelar' || btn.textContent === 'Cancel') {
        btn.textContent = window.i18n.t('cancel');
      }
    });
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
  
  // Make i18n available globally if it exists
  if (typeof i18n !== 'undefined') {
    window.i18n = i18n;
    console.log('🌐 i18n made available globally via build script');
  }
  
  // App will be initialized by main.js
  if (typeof Personal2FAApp !== 'undefined') {
    const app = new Personal2FAApp();
    app.init();
    window.Personal2FA = app;
  }
});
