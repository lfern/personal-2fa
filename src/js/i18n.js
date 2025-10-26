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