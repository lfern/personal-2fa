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
                    <button class="btn-confirm-cancel">${cancelText}</button>
                    <button class="btn-confirm-ok">${confirmText}</button>
                </div>
            </div>
        `;

        // Add event listeners
        const cancelBtn = confirmDialog.querySelector('.btn-confirm-cancel');
        const confirmBtn = confirmDialog.querySelector('.btn-confirm-ok');
        
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
    async prompt(message, defaultValue = '', title = '') {
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
                        <input type="text" class="prompt-input" value="${defaultValue}" style="width: 100%; margin: 10px 0; padding: 5px;">
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
     * Get icon for notification type
     * @param {string} type - Notification type
     * @returns {string} - Icon emoji
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