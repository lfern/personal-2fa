/**
 * Personal 2FA - Logger Configuration
 * Centralized logging system with configurable output
 */

class Logger {
  constructor() {
    // Default to enabled logs, but check localStorage for user preference
    this.logsEnabled = this.getLogPreference();
  }

  /**
   * Get log preference from localStorage
   * @returns {boolean}
   */
  getLogPreference() {
    try {
      const saved = localStorage.getItem('personal-2fa-logs-enabled');
      // Default to true if no preference saved
      return saved !== null ? JSON.parse(saved) : true;
    } catch (error) {
      // If localStorage fails, default to true
      return true;
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