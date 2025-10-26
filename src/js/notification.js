import logger from './logger.js';

export class NotificationSystem {
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
export default notificationSystem;