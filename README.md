# 🔐 Firmador Electrónico K12/P12 - Ecuador

Firmador y validador de documentos compatible con certificados **PKCS#12 (.p12/.pfx/.k12)**
emitidos por el BCE, Security Data, ANF, Uanataca y otras CAs acreditadas en Ecuador.

---

## 📁 Estructura del proyecto

```
firmador/
├── app.py              ← Servidor Flask + lógica de firma/verificación
├── requirements.txt    ← Dependencias Python
├── README.md
└── static/
    └── index.html      ← Interfaz web
```

---

## ⚙️ Instalación y ejecución

### 1. Requisitos previos

- Python 3.9 o superior
- pip

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

O directamente:

```bash
pip install flask cryptography pypdf reportlab
```

### 3. Ejecutar el servidor

```bash
python app.py
```

Verás:
```
🔐 Firmador Electrónico K12/P12 iniciando en http://localhost:5000
```

### 4. Abrir en el navegador

```
http://localhost:5000
```

---

## 🖥️ Uso de la interfaz

### Pestaña "Certificado" — Leer tu P12
1. Arrastra o selecciona tu archivo `.p12` / `.pfx` / `.k12`
2. Ingresa la contraseña del certificado
3. Haz clic en **Leer Certificado**
4. Verás: titular, entidad emisora, vigencia, algoritmo, huella digital, usos de clave

### Pestaña "Firmar" — Firmar un documento
1. Sube tu certificado `.p12` y su contraseña
2. Sube el documento a firmar (si es PDF, se firma directamente; si es otro formato como DOCX/TXT/imagen, se genera un PDF-comprobante con los datos)
3. Elige el algoritmo (SHA-256 recomendado)
4. Haz clic en **Firmar Documento**
5. Descarga el **PDF firmado**, que incluye:
   - Un **sello visual de firma** (recuadro azul) incrustado en la última página, con nombre del firmante, organización, fecha, algoritmo y hash
   - **Metadatos embebidos** en el propio PDF (`/FirmadoPor`, `/FechaFirma`, `/HashDocumento`, `/CertificadoDER`, etc.) verificables con cualquier lector de metadatos PDF
6. Descarga también el **`.firma.json`** (botón secundario) — es el paquete de verificación criptográfica que debes conservar junto al documento **original** para poder validarlo después

### Pestaña "Verificar" — Validar una firma
1. Sube el documento **original sin firmar** (el mismo que subiste para firmar, no el PDF firmado)
2. Sube el archivo `.firma.json` generado al firmar
3. Haz clic en **Verificar Firma**
4. El sistema revisa: integridad del documento, vigencia del certificado, firma criptográfica RSA/ECDSA

### Pestaña "Demo" — Certificado de prueba
- Genera un certificado P12 temporal para probar la aplicación sin tu certificado real

---

## 🔌 API REST

También puedes usar la API directamente con `curl` o cualquier cliente HTTP:

### Leer certificado
```bash
curl -X POST http://localhost:5000/api/leer-certificado \
  -F "certificado=@mi_cert.p12" \
  -F "password=mi_contraseña"
```

### Firmar documento
```bash
curl -X POST http://localhost:5000/api/firmar \
  -F "certificado=@mi_cert.p12" \
  -F "documento=@contrato.pdf" \
  -F "password=mi_contraseña" \
  -F "algoritmo=SHA256" \
  -o contrato.firma.json
```

### Verificar firma
```bash
curl -X POST http://localhost:5000/api/verificar \
  -F "documento=@contrato.pdf" \
  -F "firma=@contrato.firma.json"
```

### Generar certificado demo
```bash
curl -X POST http://localhost:5000/api/generar-certificado-prueba \
  -H "Content-Type: application/json" \
  -d '{"nombre":"Juan Pérez","organizacion":"Mi Empresa","password":"clave123"}'
```

---

## 🔐 Seguridad

- La clave privada **nunca se almacena** en disco — se usa en memoria y se descarta
- Los archivos de firma (`.firma.json`) contienen el certificado público, hash y firma criptográfica
- La contraseña viaja solo en la request y no se guarda

## ⚠️ Nota legal

Para documentos con validez legal en Ecuador, usa tu certificado emitido por una
Entidad de Certificación acreditada ante el **MINTEL** (Ministerio de Telecomunicaciones).
