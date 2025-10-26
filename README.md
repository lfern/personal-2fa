# Personal 2FA - Secure Local Authenticator

� **[¡PRUEBA LA APLICACIÓN DIRECTAMENTE AQUÍ!](https://lfern.github.io/personal-2fa/dist/personal-2fa-standalone.html)** 🚀

�🔒 **Una aplicación 2FA completamente offline y segura** que importa desde Google Authenticator, permite exportar para backup y funciona como generador TOTP independiente.

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

## � Almacenamiento de Datos y Verificación

### 🗃️ **Dónde se Guardan los Datos**

La aplicación utiliza **almacenamiento local del navegador** con cifrado:

#### **Almacenamiento Principal: IndexedDB**
- **Ubicación**: Base de datos `Personal2FA` en IndexedDB del navegador
- **Datos**: Secretos TOTP cifrados con AES-256-GCM
- **Persistencia**: Permanente hasta factory reset manual

#### **Almacenamiento Fallback: localStorage** 
- **Ubicación**: localStorage del navegador con prefijo `personal-2fa-`
- **Uso**: Solo si IndexedDB falla o no está disponible
- **Datos**: Misma estructura cifrada que IndexedDB

### 🔍 **Cómo Verificar los Datos Manualmente**

#### **Opción 1: Herramientas de Desarrollador (F12)**
```
1. Abrir DevTools (F12)
2. Ir a pestaña "Application" 
3. Sección "Storage":
   - IndexedDB → Personal2FA → secrets (datos principales)
   - Local Storage → buscar claves "personal-2fa-*" (fallback)
```

#### **Opción 2: Consola del Navegador**
```javascript
// Ver estado de IndexedDB
console.log('IndexedDB disponible:', !!window.indexedDB);

// Ver datos en localStorage (si existe)
Object.keys(localStorage).filter(key => key.startsWith('personal-2fa')).forEach(key => {
  console.log(key + ':', localStorage.getItem(key));
});

// Verificar base de datos Personal2FA
const request = indexedDB.open('Personal2FA');
request.onsuccess = (event) => {
  console.log('Base de datos Personal2FA existe:', !!event.target.result);
};
```

### 🗑️ **Verificar Borrado Completo (Factory Reset)**

#### **Después del Factory Reset, verificar que NO existan:**

1. **IndexedDB**: No debe existir base de datos `Personal2FA`
2. **localStorage**: No deben existir claves con prefijo `personal-2fa-`
3. **sessionStorage**: Debe estar limpio de datos de la app

#### **Script de Verificación Completa:**
```javascript
// Ejecutar en consola del navegador DESPUÉS del factory reset
console.log('=== VERIFICACIÓN POST FACTORY RESET ===');

// Verificar localStorage
const localKeys = Object.keys(localStorage).filter(k => k.includes('personal') || k.includes('2fa'));
console.log('localStorage keys restantes:', localKeys.length === 0 ? '✅ LIMPIO' : '❌ ' + localKeys);

// Verificar sessionStorage  
const sessionKeys = Object.keys(sessionStorage).filter(k => k.includes('personal') || k.includes('2fa'));
console.log('sessionStorage keys restantes:', sessionKeys.length === 0 ? '✅ LIMPIO' : '❌ ' + sessionKeys);

// Verificar IndexedDB
indexedDB.databases().then(dbs => {
  const personal2faDB = dbs.find(db => db.name === 'Personal2FA');
  console.log('IndexedDB Personal2FA:', !personal2faDB ? '✅ ELIMINADA' : '❌ AÚN EXISTE');
});

console.log('=== Si todo muestra ✅, el borrado fue exitoso ===');
```

### 📱 **Ubicaciones por Navegador**

- **Chrome/Edge**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\IndexedDB\`
- **Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\[profile]\storage\default\`
- **Safari**: `~/Library/Safari/Databases/`

⚠️ **Nota**: Los datos están cifrados, incluso accediendo a los archivos directamente son ilegibles sin la contraseña maestra.

## �🛠️ Arquitectura Técnica

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

## 🌐 GitHub Pages y Acceso Directo

### **Enlaces de Acceso Directo**

- **🚀 [Aplicación Completa (Standalone)](https://lfern.github.io/personal-2fa/dist/personal-2fa-standalone.html)** - Archivo único con todo incluido
- **📱 [Aplicación Modular](https://lfern.github.io/personal-2fa/dist/index.html)** - Versión con archivos separados
- **📂 [Repositorio](https://github.com/lfern/personal-2fa)** - Código fuente completo

### **Cómo Funciona GitHub Pages**

GitHub Pages sirve automáticamente los archivos estáticos desde:
- **URL base**: `https://lfern.github.io/personal-2fa/`
- **Archivos servidos**: Todo lo que esté en la rama `main`
- **Carpeta dist/**: Los builds de producción están disponibles directamente

### **Ventajas del Enlace Directo**

✅ **Sin instalación**: Funciona inmediatamente desde el navegador  
✅ **Siempre actualizado**: Refleja la última versión del repositorio  
✅ **HTTPS garantizado**: GitHub Pages siempre usa HTTPS  
✅ **Código verificable**: Puedes inspeccionar el código fuente en el repositorio  
✅ **Completamente funcional**: Incluye todas las características  

### **Seguridad del Enlace Directo**

⚠️ **Importante**: Aunque el enlace es conveniente, para máxima seguridad:

1. **Verifica el código**: Revisa el repositorio antes de usar
2. **Descarga local**: Para uso sensible, descarga y ejecuta localmente
3. **Inspecciona la red**: Confirma que no hay requests externos (F12 → Network)
4. **Hash del archivo**: Compara checksums si quieres estar 100% seguro

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

## 🔧 Configuración GitHub Pages (Para Desarrolladores)

Si eres fork/colaborador y quieres habilitar GitHub Pages en tu repositorio:

### **Activar GitHub Pages**
1. Ve a tu repositorio en GitHub
2. **Settings** → **Pages** (en el menú lateral)  
3. **Source**: Deploy from a branch
4. **Branch**: `main` 
5. **Folder**: `/ (root)`
6. **Save** → Esperar 1-2 minutos

### **Tu Enlace Personal Será**
```
https://[tu-usuario].github.io/personal-2fa/dist/personal-2fa-standalone.html
```

### **Verificar que Funciona**
```bash
# Verificar que el enlace responde
curl -I https://[tu-usuario].github.io/personal-2fa/dist/personal-2fa-standalone.html

# Debe retornar HTTP 200 OK
```

---

**🔒 Personal 2FA - Tu seguridad, tu control, tu dispositivo.**