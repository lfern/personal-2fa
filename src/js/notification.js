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