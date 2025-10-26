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
        
        // Clear all data messages
        clearAllWarning: '⚠️ ADVERTENCIA: Estás a punto de eliminar TODOS los códigos 2FA y datos de la aplicación.<br><br>🚨 Esta acción NO se puede deshacer.<br>🚨 Perderás el acceso a todas las cuentas configuradas.<br>🚨 NO podrás recuperar esta información.<br><br>¿Estás absolutamente seguro de que quieres continuar?',
        clearAllFinalConfirm: '🚨 CONFIRMACIÓN FINAL 🚨<br><br>Vas a eliminar permanentemente:<br>• Todos los códigos 2FA guardados<br>• Configuraciones de la aplicación<br>• Datos de IndexedDB y localStorage<br>• Contraseña maestra configurada<br><br>⚠️ DESPUÉS DE ESTO TENDRÁS QUE:<br>• Configurar de nuevo todos tus códigos 2FA<br>• Crear una nueva contraseña maestra<br>• Volver a importar desde otras aplicaciones<br><br>Escribe "BORRAR TODO" si realmente quieres continuar:',
        clearAllLastChance: '🔥 ÚLTIMA OPORTUNIDAD 🔥<br><br>Esta es tu última oportunidad para cancelar.<br>Una vez que hagas clic en "Confirmar", NO HAY VUELTA ATRÁS.<br><br>¿Proceder con la eliminación TOTAL e IRREVERSIBLE de todos los datos?',
        clearAllTextError: '❌ Cancelado. Para confirmar debes escribir exactamente "BORRAR TODO"',
        clearAllProgress: '🗑️ Eliminando todos los datos... Por favor espera...',
        clearAllSuccess: '✅ Datos eliminados exitosamente<br><br>Todos los datos han sido eliminados de forma permanente.<br>La página se recargará para reiniciar la aplicación.',
        
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
        
        // Clear all data messages
        clearAllWarning: '⚠️ WARNING: You are about to delete ALL 2FA codes and application data.<br><br>🚨 This action CANNOT be undone.<br>🚨 You will lose access to all configured accounts.<br>🚨 You will NOT be able to recover this information.<br><br>Are you absolutely sure you want to continue?',
        clearAllFinalConfirm: '🚨 FINAL CONFIRMATION 🚨<br><br>You are about to permanently delete:<br>• All saved 2FA codes<br>• Application configurations<br>• IndexedDB and localStorage data<br>• Configured master password<br><br>⚠️ AFTER THIS YOU WILL HAVE TO:<br>• Set up all your 2FA codes again<br>• Create a new master password<br>• Re-import from other applications<br><br>Type "DELETE ALL" if you really want to continue:',
        clearAllLastChance: '🔥 LAST CHANCE 🔥<br><br>This is your last chance to cancel.<br>Once you click "Confirm", there is NO GOING BACK.<br><br>Proceed with TOTAL and IRREVERSIBLE deletion of all data?',
        clearAllTextError: '❌ Cancelled. To confirm you must type exactly "DELETE ALL"',
        clearAllProgress: '🗑️ Deleting all data... Please wait...',
        clearAllSuccess: '✅ Data deleted successfully<br><br>All data has been permanently deleted.<br>The page will reload to restart the application.',
        
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