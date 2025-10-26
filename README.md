# Personal 2FA - Secure Local Authenticator

🔒 **Una aplicación 2FA completamente offline y segura** que importa desde Google Authenticator, permite exportar para backup y funciona como generador TOTP independiente.

## ✨ Características Principales

### 🛡️ **Seguridad Máxima**
- ✅ **100% Offline** - Sin conexiones a internet
- ✅ **Cifrado AES-256-GCM** con Web Crypto API
- ✅ **Almacenamiento local** cifrado con IndexedDB
- ✅ **Contraseña maestra** con PBKDF2 (100,000 iteraciones)
- ✅ **Código fuente legible** e inspecciónable

### 📱 **Compatibilidad Google Authenticator**
- 📥 **Importar** códigos QR de exportación de Google Auth
- 📤 **Exportar** para backup (QR individuales o formato migración)
- 🔄 **Uso directo** como aplicación 2FA independiente

### 🚀 **Funcionalidades**
- 📹 **Escáner QR** via cámara web
- ⏰ **Códigos TOTP** con temporizadores visuales
- ➕ **Añadir manualmente** códigos TOTP
- 💾 **Backup JSON** cifrado
- 🔒 **Auto-bloqueo** configurable

## 📋 Requisitos

- **Navegador moderno** con Web Crypto API (Chrome 37+, Firefox 34+, Safari 11+)
- **HTTPS o localhost** (requerido para Web Crypto y cámara)
- **Cámara web** (opcional, para escanear QR codes)

## 🚀 Instalación y Uso

### Opción 1: Desarrollo Local
```bash
# Clonar o descargar el proyecto
cd personal-2fa

# Instalar dependencias
npm install

# Ejecutar en modo desarrollo
npm run dev

# Abrir http://localhost:3000
```

### Opción 2: Build para Distribución
```bash
# Generar archivos finales legibles (sin minificar)
npm run build

# Los archivos estaran en dist/
# - index.html (archivo principal)
# - personal-2fa.js (JavaScript legible)
# - *.css (estilos)
```

### Opción 3: Archivo Único Portable
```bash
# TODO: Script para generar un solo HTML con todo incluido
npm run build:single
```

## 🔐 Flujo de Seguridad

### Primera Ejecución
1. **Crear contraseña maestra** (mínimo 8 caracteres)
2. **Verificación de seguridad** automática
3. **Inicialización** del almacén cifrado

### Uso Normal
1. **Desbloquear** con contraseña maestra
2. **Importar** desde Google Authenticator (QR)
3. **Ver códigos TOTP** con temporizadores
4. **Exportar** para backup (sin almacenar en app)

### Funciones de Export (Solo Backup)
⚠️ **Importante**: Los exports son solo para backup. Los códigos NO se guardan permanentemente en esta app, solo se generan para transferir a otras aplicaciones.

## 📖 Guía de Uso

### 📥 Importar desde Google Authenticator

1. En Google Authenticator: **Menú → Exportar cuentas**
2. En Personal 2FA: **Importar → Activar Cámara**
3. **Escanear el QR** de Google Auth
4. **Códigos importados** automáticamente

### 📤 Exportar para Backup

#### QR Individual (recomendado)
- Genera un QR por cada código
- Compatible con cualquier app 2FA
- Escanea cada QR en la app destino

#### QR Migración (Google Auth)
- Formato nativo de Google Authenticator
- Múltiples códigos en un QR
- Importa directo en Google Auth

#### Backup JSON
- Archivo cifrado con todos los códigos
- Para restaurar en Personal 2FA
- Incluye metadatos completos

### ➕ Añadir Códigos Manualmente

1. **Añadir Manual** → Completar formulario
2. **Servicio**: Nombre del servicio (ej: Google, GitHub)
3. **Cuenta**: Tu usuario/email
4. **Secreto**: Código Base32 del servicio
5. **Opciones avanzadas**: Algoritmo, dígitos, período

## 🔍 Verificación de Seguridad

La app incluye indicadores de seguridad en tiempo real:

- 🔐 **Cifrado**: Estado del Web Crypto API
- 🏠 **Almacenamiento**: Confirmación local
- 📡 **Red**: Estado de conexión (offline = ✅)

### Panel de Verificación (Modo Debug)
```javascript
// En consola del navegador
Personal2FA.performSecurityChecks()
```

## 🛠️ Arquitectura Técnica

### **Stack de Seguridad**
- **Web Crypto API**: Cifrado hardware-acelerado
- **AES-256-GCM**: Cifrado autenticado
- **PBKDF2**: Derivación segura de claves
- **IndexedDB**: Base de datos local persistente

### **Módulos Principales**
```
src/js/
├── crypto.js         # Criptografía (AES-256-GCM)
├── storage.js        # Almacenamiento seguro (IndexedDB)  
├── totp.js          # Generación TOTP (RFC 6238)
├── qr.js            # Escáner y generador QR
├── googleAuth.js    # Import/Export Google Auth
└── main.js          # Controlador principal
```

### **Build System**
- **Vite**: Bundler moderno
- **ES Modules**: Módulos nativos
- **Sin minificación**: Código legible
- **Desarrollo rápido**: Hot reload

## 🔧 Configuración Build

El archivo `vite.config.js` está configurado para generar código legible:

```javascript
export default defineConfig({
  build: {
    minify: false,      // ❌ Sin minificar
    rollupOptions: {
      output: {
        compact: false,  // Mantener espaciado
        indent: '  '     // Indentación legible
      }
    }
  }
})
```

## 🚨 Advertencias de Seguridad

### ✅ **Buenas Prácticas**
- Usa contraseñas maestras fuertes
- Mantén backups cifrados seguros  
- Verifica el código fuente antes de usar
- Solo usa en HTTPS o localhost

### ⚠️ **Limitaciones**
- Requiere navegador moderno
- Cámara web para importar QR
- Sin sincronización entre dispositivos
- Backups manuales únicamente

### ❌ **Nunca Hagas Esto**
- No uses en HTTP público
- No compartas la contraseña maestra
- No confíes en código modificado
- No uses con navegadores obsoletos

## 🔄 Compatibilidad con Apps 2FA

| Aplicación | Import | Export | Notas |
|-----------|--------|---------|-------|
| Google Authenticator | ✅ | ✅ | Soporte completo |
| Microsoft Authenticator | ❌ | ✅ | Solo export |
| Authy | ❌ | ❌ | Sin soporte estándar |
| Aegis Authenticator | ✅ | ✅ | Soporte completo |
| andOTP | ✅ | ✅ | Via QR individual |
| Bitwarden | ❌ | ✅ | Via QR individual |
| LastPass | ❌ | ⚠️ | Solo SHA1, 6 dígitos |

## 📝 Scripts Disponibles

```bash
npm run dev         # Servidor desarrollo (localhost:3000)
npm run build       # Build producción (dist/)
npm run preview     # Vista previa del build
npm run serve       # Servir build en local
```

## 🤝 Contribuir

1. **Fork** el repositorio
2. **Crear rama** para tu feature
3. **Mantener código legible** (sin minificar)
4. **Documentar cambios de seguridad**
5. **Pull request** con descripción detallada

## 📄 Licencia

MIT License - Usa bajo tu responsabilidad

## ❓ FAQ

### ¿Es seguro usar esta app?
Sí, si verificas el código fuente y usas HTTPS/localhost. Todo funciona offline y se cifra localmente.

### ¿Puedo confiar en el código?
El código está diseñado para ser 100% legible e inspecciónable. Revisa especialmente los módulos `crypto.js` y `storage.js`.

### ¿Qué pasa si olvido la contraseña maestra?
Los datos se pierden permanentemente. Mantén backups seguros.

### ¿Funciona en móviles?
Sí, en navegadores móviles modernos. Para mejor experiencia, considera una PWA.

### ¿Los datos salen del dispositivo?
NO. Todo funciona offline. Los exports son solo para que tú los uses en otras apps.

---

**🔒 Personal 2FA - Tu seguridad, tu control, tu dispositivo.**