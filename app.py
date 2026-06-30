"""
Firmador Electrónico de Documentos - Ecuador
Soporte para certificados K12/P12 (PKCS#12)
Output: PDF firmado con sello visual + firma criptográfica embebida en metadatos
"""

import os, json, base64, hashlib, datetime, io
from pathlib import Path
from flask import Flask, request, jsonify, send_file, send_from_directory

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_der_x509_certificate

from pypdf import PdfWriter, PdfReader, Transformation
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.units import mm

app = Flask(__name__, static_folder="static")

UPLOAD_FOLDER = Path("/tmp/firmador")
UPLOAD_FOLDER.mkdir(exist_ok=True)
SIGNED_FOLDER = UPLOAD_FOLDER / "firmados"
SIGNED_FOLDER.mkdir(exist_ok=True)


# ──────────────────────────────────────────────────────────
#  Utilidades de Certificado
# ──────────────────────────────────────────────────────────

def load_p12(p12_bytes: bytes, password: str):
    pwd = password.encode() if isinstance(password, str) else password
    try:
        return pkcs12.load_key_and_certificates(p12_bytes, pwd, default_backend())
    except Exception as e:
        raise ValueError(f"No se pudo cargar el certificado P12: {e}")


def get_cert_info(cert: x509.Certificate) -> dict:
    def ga(obj, oid):
        a = obj.get_attributes_for_oid(oid)
        return a[0].value if a else None

    now = datetime.datetime.now(datetime.timezone.utc)
    nva = cert.not_valid_after_utc
    nvb = cert.not_valid_before_utc
    is_valid = nvb <= now <= nva

    key_usage = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        for u in ["digital_signature","content_commitment","key_encipherment","data_encipherment"]:
            try:
                if getattr(ku.value, u): key_usage.append(u.replace("_"," ").title())
            except: pass
    except: pass

    return {
        "titular":      ga(cert.subject, NameOID.COMMON_NAME),
        "organizacion": ga(cert.subject, NameOID.ORGANIZATION_NAME),
        "unidad":       ga(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "pais":         ga(cert.subject, NameOID.COUNTRY_NAME),
        "provincia":    ga(cert.subject, NameOID.STATE_OR_PROVINCE_NAME),
        "ciudad":       ga(cert.subject, NameOID.LOCALITY_NAME),
        "email":        ga(cert.subject, NameOID.EMAIL_ADDRESS),
        "emisor":       ga(cert.issuer,  NameOID.COMMON_NAME),
        "emisor_org":   ga(cert.issuer,  NameOID.ORGANIZATION_NAME),
        "serie":        str(cert.serial_number),
        "valido_desde": nvb.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "valido_hasta": nva.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dias_restantes": max(0, (nva - now).days),
        "estado":       "VÁLIDO" if is_valid else ("EXPIRADO" if now > nva else "AÚN NO VÁLIDO"),
        "es_valido":    is_valid,
        "algoritmo":    cert.signature_algorithm_oid.dotted_string,
        "key_usage":    key_usage,
        "version":      cert.version.name,
        "huella_sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


# ──────────────────────────────────────────────────────────
#  Sello visual de firma (stamp) en PDF con ReportLab
# ──────────────────────────────────────────────────────────

def make_signature_stamp(signer_name: str, org: str, date_str: str,
                          doc_hash: str, alg: str, serial: str,
                          emisor: str = "") -> bytes:
    """Genera una página PDF con el sello de firma (170mm x 38mm)."""
    buf = io.BytesIO()
    W, H = 170 * mm, 38 * mm
    c = rl_canvas.Canvas(buf, pagesize=(W, H))

    # Fondo y borde
    c.setFillColorRGB(0.95, 0.97, 1.0)
    c.setStrokeColorRGB(0.10, 0.30, 0.70)
    c.setLineWidth(1.5)
    c.roundRect(1.5, 1.5, W - 3, H - 3, 6, fill=1, stroke=1)

    # Franja izquierda azul
    c.setFillColorRGB(0.10, 0.30, 0.70)
    c.roundRect(4, 4, 32, H - 8, 4, fill=1, stroke=0)

    # Texto franja
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 6)
    c.drawCentredString(20, H - 13, "FIRMA")
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(20, H / 2 - 3, "EC")
    c.setFont("Helvetica-Bold", 5.5)
    c.drawCentredString(20, 9, "DIGITAL")

    # Contenido textual
    x = 42
    c.setFillColorRGB(0.05, 0.05, 0.30)
    c.setFont("Helvetica-Bold", 7.5)
    line1 = f"Firmado digitalmente por: {signer_name}"
    c.drawString(x, H - 11, line1[:72])

    c.setFillColorRGB(0.15, 0.15, 0.15)
    c.setFont("Helvetica", 6.2)
    c.drawString(x, H - 20, f"Organizacion: {(org or 'N/A')[:55]}  |  Serie: {serial[:20]}")
    c.drawString(x, H - 28, f"Fecha: {date_str}  |  Algoritmo: {alg}")
    hash_short = doc_hash[:44] + "..." if len(doc_hash) > 44 else doc_hash
    c.drawString(x, H - 36, f"Hash SHA-256: {hash_short}")

    c.save()
    return buf.getvalue()


# ──────────────────────────────────────────────────────────
#  Incrustar sello en PDF existente
# ──────────────────────────────────────────────────────────

def _safe_read_pdf(pdf_bytes: bytes) -> "PdfReader":
    """
    Intenta leer un PDF de forma tolerante. Si pypdf falla por estar
    mal formado (falta %%EOF, xref roto, etc.), intenta repararlo
    con pikepdf antes de reintentar.
    """
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)
        _ = len(reader.pages)  # fuerza el parseo completo
        return reader
    except Exception:
        pass

    # Fallback: reparar con pikepdf (re-escribe el PDF de forma válida)
    import pikepdf
    with pikepdf.open(io.BytesIO(pdf_bytes)) as p:
        repaired = io.BytesIO()
        p.save(repaired)
    repaired.seek(0)
    return PdfReader(repaired, strict=False)


def embed_stamp_in_pdf(pdf_bytes: bytes, stamp_bytes: bytes,
                        sig_json: dict, signer_info: dict) -> bytes:
    """
    Toma el PDF original, agrega el sello visual en la última página
    (esquina inferior izquierda) e incrusta los metadatos de firma.
    """
    # Leer PDF original (tolerante a archivos mal formados)
    reader = _safe_read_pdf(pdf_bytes)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    # Leer sello
    stamp_reader = PdfReader(io.BytesIO(stamp_bytes))
    stamp_page   = stamp_reader.pages[0]

    # Posición: esquina inferior izquierda de la última página, con margen
    last_page = writer.pages[-1]
    last_page.merge_transformed_page(
        stamp_page,
        Transformation().translate(tx=28, ty=20),
        expand=False,
    )

    # Metadatos PDF (DocInfo)
    titular = signer_info.get("cn", "")
    org     = signer_info.get("org", "")
    writer.add_metadata({
        "/Author":   titular,
        "/Subject":  "Documento Firmado Electrónicamente - Ecuador",
        "/Keywords": f"firma-electronica;{sig_json.get('signature_algorithm','')};PKI;K12",
        "/Creator":  "Firmador Electrónico K12/P12 v1.0 - Ecuador",
        "/FirmadoPor":       titular,
        "/FirmadoOrg":       org,
        "/FechaFirma":       sig_json.get("signing_time", ""),
        "/Algoritmo":        sig_json.get("signature_algorithm", ""),
        "/HashDocumento":    sig_json.get("document_hash", ""),
        "/FirmaBase64":      sig_json.get("signature_value", "")[:200],  # parcial en meta
        "/CertificadoDER":   sig_json.get("signer_certificate", "")[:500],
    })

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def build_non_pdf_signed_package(doc_bytes: bytes, doc_name: str,
                                  sig_json: dict) -> bytes:
    """
    Para documentos que NO son PDF, genera un PDF contenedor
    con el sello + referencia al archivo original.
    """
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    W, H = A4

    # Encabezado
    c.setFillColorRGB(0.10, 0.30, 0.70)
    c.rect(0, H - 60, W, 60, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, H - 35, "Comprobante de Firma Electrónica")
    c.setFont("Helvetica", 9)
    c.drawString(30, H - 52, "República del Ecuador — Firma Digital PKI PKCS#12")

    # Cuerpo
    si = sig_json.get("signer_info", {})
    y = H - 100
    c.setFillColorRGB(0.1, 0.1, 0.1)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(30, y, "Datos del documento firmado")
    c.setFont("Helvetica", 9)
    y -= 18
    for label, val in [
        ("Documento original:", doc_name),
        ("Tamaño:", f"{len(doc_bytes):,} bytes"),
        ("Hash SHA-256 del documento:", sig_json.get("document_hash", "")),
        ("Algoritmo de firma:", sig_json.get("signature_algorithm", "")),
        ("Fecha y hora UTC:", sig_json.get("signing_time", "")),
    ]:
        c.setFont("Helvetica-Bold", 8)
        c.drawString(40, y, label)
        c.setFont("Helvetica", 8)
        c.drawString(200, y, str(val)[:80])
        y -= 14

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(30, y, "Datos del firmante")
    y -= 18
    c.setFont("Helvetica", 9)
    for label, val in [
        ("Titular:", si.get("cn", "")),
        ("Organización:", si.get("org", "")),
        ("Emisor del certificado:", si.get("issuer", "")),
        ("N° de serie:", si.get("serial", "")),
    ]:
        c.setFont("Helvetica-Bold", 8)
        c.drawString(40, y, label)
        c.setFont("Helvetica", 8)
        c.drawString(200, y, str(val)[:80])
        y -= 14

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(30, y, "Firma criptográfica (Base64, parcial)")
    y -= 14
    sig_b64 = sig_json.get("signature_value", "")
    chunk = 90
    for i in range(0, min(len(sig_b64), 360), chunk):
        c.setFont("Courier", 6.5)
        c.drawString(40, y, sig_b64[i:i+chunk])
        y -= 11

    c.save()

    # Ahora crea writer y agrega sello
    base_pdf = buf.getvalue()
    reader = PdfReader(io.BytesIO(base_pdf))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    # Agregar sello
    signer_name = si.get("cn", "Firmante")
    org         = si.get("org", "")
    date_str    = sig_json.get("signing_time", "")[:19]
    doc_hash    = sig_json.get("document_hash", "")
    alg         = sig_json.get("signature_algorithm", "")
    serial      = si.get("serial", "")

    stamp_bytes = make_signature_stamp(signer_name, org, date_str, doc_hash, alg, serial)
    stamp_reader = PdfReader(io.BytesIO(stamp_bytes))
    stamp_page   = stamp_reader.pages[0]
    last_page = writer.pages[-1]
    last_page.merge_transformed_page(
        stamp_page, Transformation().translate(tx=28, ty=20), expand=False
    )

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# ──────────────────────────────────────────────────────────
#  Lógica de firma criptográfica
# ──────────────────────────────────────────────────────────

def sign_document(doc_bytes: bytes, private_key, cert: x509.Certificate,
                  algorithm: str = "SHA256") -> dict:
    hash_alg_map = {
        "SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()
    }
    alg_obj = hash_alg_map[algorithm]

    h = hashlib.new(algorithm.lower(), doc_bytes)
    doc_hash = h.hexdigest()

    ts = datetime.datetime.now(datetime.timezone.utc)
    cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_list[0].value if cn_list else "Desconocido"

    signed_attrs = json.dumps({
        "document_hash": doc_hash,
        "hash_algorithm": algorithm,
        "signing_time": ts.isoformat(),
        "signer_cn": cn,
        "cert_serial": str(cert.serial_number),
    }, sort_keys=True).encode()

    key_type = type(private_key).__name__.lower()
    if "ec" in key_type:
        sig_bytes = private_key.sign(signed_attrs, ec.ECDSA(alg_obj))
        sig_alg = f"ECDSA-{algorithm}"
    else:
        sig_bytes = private_key.sign(signed_attrs, padding.PKCS1v15(), alg_obj)
        sig_alg = f"RSA-{algorithm}"

    def ga(obj, oid):
        a = obj.get_attributes_for_oid(oid)
        return a[0].value if a else ""

    return {
        "version": "1.0",
        "signature_algorithm": sig_alg,
        "hash_algorithm": algorithm,
        "document_hash": doc_hash,
        "document_size": len(doc_bytes),
        "signing_time": ts.isoformat(),
        "signed_attributes": base64.b64encode(signed_attrs).decode(),
        "signature_value": base64.b64encode(sig_bytes).decode(),
        "signer_certificate": base64.b64encode(
            cert.public_bytes(serialization.Encoding.DER)).decode(),
        "signer_info": {
            "cn":     ga(cert.subject, NameOID.COMMON_NAME),
            "org":    ga(cert.subject, NameOID.ORGANIZATION_NAME),
            "serial": str(cert.serial_number),
            "issuer": ga(cert.issuer, NameOID.COMMON_NAME),
        },
    }


def verify_signature(doc_bytes: bytes, sig_package: dict) -> dict:
    errors, warnings, checks = [], [], {}

    try:
        alg = sig_package.get("hash_algorithm", "SHA256").lower()
        computed = hashlib.new(alg, doc_bytes).hexdigest()
        expected = sig_package.get("document_hash", "")
        hash_ok = computed == expected
        checks["integridad_documento"] = hash_ok
        if not hash_ok:
            errors.append("❌ El documento ha sido MODIFICADO después de la firma")

        cert = load_der_x509_certificate(
            base64.b64decode(sig_package["signer_certificate"]), default_backend())
        checks["certificado_cargado"] = True

        signing_time = datetime.datetime.fromisoformat(sig_package["signing_time"])
        cert_valid_at = cert.not_valid_before_utc <= signing_time <= cert.not_valid_after_utc
        checks["certificado_vigente_al_firmar"] = cert_valid_at
        if not cert_valid_at:
            errors.append(f"❌ Certificado no vigente al momento de firma")

        now = datetime.datetime.now(datetime.timezone.utc)
        cert_valid_now = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        checks["certificado_vigente_ahora"] = cert_valid_now
        if not cert_valid_now:
            warnings.append("⚠️ El certificado está actualmente expirado")

        signed_attrs = base64.b64decode(sig_package["signed_attributes"])
        sig_value    = base64.b64decode(sig_package["signature_value"])
        sig_alg      = sig_package.get("signature_algorithm", "RSA-SHA256")
        hash_part    = sig_alg.split("-")[-1]
        h_obj = {"SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()}.get(hash_part, hashes.SHA256())
        pub = cert.public_key()
        try:
            if "ECDSA" in sig_alg:
                pub.verify(sig_value, signed_attrs, ec.ECDSA(h_obj))
            else:
                pub.verify(sig_value, signed_attrs, padding.PKCS1v15(), h_obj)
            checks["firma_criptografica"] = True
        except InvalidSignature:
            checks["firma_criptografica"] = False
            errors.append("❌ La firma criptográfica es INVÁLIDA")

        try:
            attrs = json.loads(signed_attrs.decode())
            ok = attrs.get("document_hash") == expected
            checks["atributos_firmados_coherentes"] = ok
            if not ok: errors.append("❌ Atributos firmados incoherentes")
        except:
            checks["atributos_firmados_coherentes"] = False

        cert_info = get_cert_info(cert)

    except Exception as e:
        errors.append(f"❌ Error: {e}")
        cert_info = {}

    is_valid = not errors and checks.get("firma_criptografica", False)
    return {
        "valido": is_valid,
        "estado": "✅ FIRMA VÁLIDA" if is_valid else "❌ FIRMA INVÁLIDA",
        "errores": errors, "advertencias": warnings, "verificaciones": checks,
        "firmante": sig_package.get("signer_info", {}),
        "fecha_firma": sig_package.get("signing_time", ""),
        "algoritmo":   sig_package.get("signature_algorithm", ""),
        "hash_documento": sig_package.get("document_hash", ""),
        "certificado": cert_info,
    }


# ──────────────────────────────────────────────────────────
#  Rutas Flask
# ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/leer-certificado", methods=["POST"])
def leer_certificado():
    if "certificado" not in request.files:
        return jsonify({"error": "No se envió el archivo de certificado"}), 400
    try:
        p12_bytes = request.files["certificado"].read()
        password  = request.form.get("password", "")
        priv_key, cert, chain = load_p12(p12_bytes, password)
        info = get_cert_info(cert)
        chain_info = []
        if chain:
            for cc in chain:
                a = cc.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                b = cc.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                chain_info.append({"cn": a[0].value if a else "CA", "org": b[0].value if b else ""})
        return jsonify({"exito": True, "certificado": info, "cadena": chain_info,
                        "tiene_clave_privada": priv_key is not None})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/firmar", methods=["POST"])
def firmar_documento():
    if "certificado" not in request.files or "documento" not in request.files:
        return jsonify({"error": "Faltan archivos requeridos"}), 400

    p12_file  = request.files["certificado"]
    doc_file  = request.files["documento"]
    password  = request.form.get("password", "")
    algorithm = request.form.get("algoritmo", "SHA256").upper()

    if algorithm not in ("SHA256", "SHA384", "SHA512"):
        return jsonify({"error": "Algoritmo no válido"}), 400

    try:
        p12_bytes = p12_file.read()
        doc_bytes = doc_file.read()
        doc_name  = doc_file.filename or "documento"

        priv_key, cert, chain = load_p12(p12_bytes, password)
        if priv_key is None:
            return jsonify({"error": "El certificado no contiene clave privada"}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        if now > cert.not_valid_after_utc:
            return jsonify({"error": "El certificado ha expirado"}), 400

        # Firma criptográfica sobre el documento original
        sig_json = sign_document(doc_bytes, priv_key, cert, algorithm)
        sig_json["document_name"] = doc_name

        si          = sig_json["signer_info"]
        signer_name = si.get("cn", "Firmante")
        org         = si.get("org", "")
        date_str    = sig_json["signing_time"][:19].replace("T", " ")
        doc_hash    = sig_json["document_hash"]
        alg         = sig_json["signature_algorithm"]
        serial      = si.get("serial", "")
        emisor      = si.get("issuer", "")

        # Sello visual
        stamp_bytes = make_signature_stamp(signer_name, org, date_str,
                                           doc_hash, alg, serial, emisor)

        # Determinar si el documento es PDF
        is_pdf = (doc_bytes[:4] == b"%PDF" or doc_name.lower().endswith(".pdf"))

        if is_pdf:
            try:
                signed_pdf = embed_stamp_in_pdf(doc_bytes, stamp_bytes, sig_json, si)
            except Exception as embed_err:
                # El PDF original está corrupto/mal formado y no se pudo reparar.
                # En vez de fallar, generamos el PDF-comprobante como respaldo.
                print(f"[WARN] No se pudo incrustar sello en el PDF original ({embed_err}); "
                      f"generando PDF-comprobante de respaldo.")
                signed_pdf = build_non_pdf_signed_package(doc_bytes, doc_name, sig_json)
                is_pdf = False
        else:
            signed_pdf = build_non_pdf_signed_package(doc_bytes, doc_name, sig_json)

        # Guardar PDF firmado
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in doc_name)
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"{ts}_{safe}_FIRMADO.pdf"
        out_path = SIGNED_FOLDER / out_name

        with open(out_path, "wb") as f:
            f.write(signed_pdf)

        cert_info = get_cert_info(cert)
        return jsonify({
            "exito": True,
            "mensaje": "Documento firmado exitosamente",
            "archivo_firmado": out_name,
            "es_pdf": is_pdf,
            "hash_documento":  sig_json["document_hash"],
            "algoritmo":       sig_json["signature_algorithm"],
            "fecha_firma":     sig_json["signing_time"],
            "firmante":        cert_info["titular"],
            "firma_base64":    sig_json["signature_value"][:64] + "...",
            "paquete_json":    sig_json,   # para uso en verificación
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": f"Error al firmar: {e}"}), 500


@app.route("/api/verificar", methods=["POST"])
def verificar_firma():
    if "documento" not in request.files:
        return jsonify({"error": "Falta el documento original"}), 400

    doc_bytes = request.files["documento"].read()
    sig_package = None

    if "firma" in request.files:
        try:
            sig_package = json.loads(request.files["firma"].read().decode("utf-8"))
        except:
            return jsonify({"error": "Archivo de firma JSON inválido"}), 400
    elif "firma_json" in request.form:
        try:
            sig_package = json.loads(request.form["firma_json"])
        except:
            return jsonify({"error": "JSON de firma inválido"}), 400
    else:
        return jsonify({"error": "Proporciona el archivo .firma.json o el JSON de firma"}), 400

    try:
        return jsonify(verify_signature(doc_bytes, sig_package))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/descargar/<nombre>")
def descargar(nombre):
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in nombre)
    path = SIGNED_FOLDER / safe
    if not path.exists():
        return jsonify({"error": "Archivo no encontrado"}), 404
    mime = "application/pdf" if safe.endswith(".pdf") else "application/json"
    return send_file(path, as_attachment=True, download_name=safe, mimetype=mime)


@app.route("/api/generar-certificado-prueba", methods=["POST"])
def generar_certificado_prueba():
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    data    = request.get_json() or {}
    nombre  = data.get("nombre", "Usuario Prueba")
    org     = data.get("organizacion", "Empresa Demo S.A.")
    password = data.get("password", "prueba123")

    key = rsa_mod.generate_private_key(65537, 2048, default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pichincha"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quito"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DEMO"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256(), default_backend()))

    p12 = pkcs12.serialize_key_and_certificates(
        nombre.encode(), key, cert, None,
        serialization.BestAvailableEncryption(password.encode()))

    return jsonify({
        "exito": True,
        "p12_base64": base64.b64encode(p12).decode(),
        "password": password,
        "info": get_cert_info(cert),
        "mensaje": "⚠️ Certificado DEMO — Solo para pruebas.",
    })


if __name__ == "__main__":
    print("🔐 Firmador Electrónico K12/P12 → http://localhost:5000")
    app.run(debug=True, port=5000)