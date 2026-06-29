"""
Firmador Electrónico de Documentos - Ecuador
Soporte para certificados K12/P12 (PKCS#12)
Compatible con certificados del BCE, Security Data, ANF, etc.
"""

import os
import json
import base64
import hashlib
import datetime
import struct
import io
from pathlib import Path
from flask import Flask, request, jsonify, send_file, send_from_directory

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

app = Flask(__name__, static_folder="static")

UPLOAD_FOLDER = Path("/tmp/firmador")
UPLOAD_FOLDER.mkdir(exist_ok=True)
SIGNED_FOLDER = UPLOAD_FOLDER / "firmados"
SIGNED_FOLDER.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  Utilidades de Certificado
# ─────────────────────────────────────────────────────────────

def load_p12_certificate(p12_bytes: bytes, password: str):
    """Carga un certificado P12/K12 y retorna (private_key, cert, chain)."""
    pwd = password.encode() if isinstance(password, str) else password
    try:
        return pkcs12.load_key_and_certificates(p12_bytes, pwd, default_backend())
    except Exception as e:
        raise ValueError(f"No se pudo cargar el certificado P12: {e}")


def get_cert_info(cert: x509.Certificate) -> dict:
    """Extrae información legible del certificado X.509."""

    def get_attr(name_obj, oid):
        attrs = name_obj.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    is_valid = not_before <= now <= not_after

    # Extensiones opcionales
    key_usage = None
    ext_key_usage = []
    san = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        usages = []
        for u in ["digital_signature", "content_commitment", "key_encipherment",
                  "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"]:
            try:
                if getattr(ku.value, u):
                    usages.append(u.replace("_", " ").title())
            except Exception:
                pass
        key_usage = usages
    except x509.ExtensionNotFound:
        pass

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        for usage in eku.value:
            ext_key_usage.append(usage.dotted_string)
    except x509.ExtensionNotFound:
        pass

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(n) for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    return {
        "titular": get_attr(cert.subject, NameOID.COMMON_NAME),
        "organizacion": get_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "unidad": get_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "pais": get_attr(cert.subject, NameOID.COUNTRY_NAME),
        "provincia": get_attr(cert.subject, NameOID.STATE_OR_PROVINCE_NAME),
        "ciudad": get_attr(cert.subject, NameOID.LOCALITY_NAME),
        "email": get_attr(cert.subject, NameOID.EMAIL_ADDRESS),
        "emisor": get_attr(cert.issuer, NameOID.COMMON_NAME),
        "emisor_org": get_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "serie": str(cert.serial_number),
        "valido_desde": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "valido_hasta": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dias_restantes": max(0, (not_after - now).days),
        "estado": "VÁLIDO" if is_valid else ("EXPIRADO" if now > not_after else "AÚN NO VÁLIDO"),
        "es_valido": is_valid,
        "algoritmo": cert.signature_algorithm_oid.dotted_string,
        "key_usage": key_usage,
        "ext_key_usage": ext_key_usage,
        "san": san,
        "version": cert.version.name,
        "huella_sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


# ─────────────────────────────────────────────────────────────
#  Firma de Documentos
# ─────────────────────────────────────────────────────────────

def sign_document(doc_bytes: bytes, private_key, cert: x509.Certificate,
                  algorithm: str = "SHA256") -> dict:
    """
    Firma un documento y retorna el paquete de firma en JSON (CMS-like simplificado).
    Formato compatible con verificación posterior.
    """
    hash_alg = {"SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()}
    if algorithm not in hash_alg:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")

    # Hash del documento
    h = hashlib.new(algorithm.lower(), doc_bytes)
    doc_hash = h.hexdigest()

    # Determinar tipo de clave y firmar
    key_type = type(private_key).__name__
    ts = datetime.datetime.now(datetime.timezone.utc)

    # Datos firmados incluyen hash + timestamp + info del certificado
    signed_attrs = json.dumps({
        "document_hash": doc_hash,
        "hash_algorithm": algorithm,
        "signing_time": ts.isoformat(),
        "signer_cn": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "Desconocido",
        "cert_serial": str(cert.serial_number),
    }, sort_keys=True).encode()

    if "RSA" in key_type or "rsa" in key_type.lower():
        sig_bytes = private_key.sign(signed_attrs, padding.PKCS1v15(), hash_alg[algorithm])
        sig_alg = f"RSA-{algorithm}"
    elif "EC" in key_type or "ec" in key_type.lower():
        sig_bytes = private_key.sign(signed_attrs, ec.ECDSA(hash_alg[algorithm]))
        sig_alg = f"ECDSA-{algorithm}"
    else:
        sig_bytes = private_key.sign(signed_attrs, padding.PKCS1v15(), hash_alg[algorithm])
        sig_alg = f"UNKNOWN-{algorithm}"

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

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
            cert.public_bytes(serialization.Encoding.DER)
        ).decode(),
        "signer_info": {
            "cn": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "",
            "org": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "",
            "serial": str(cert.serial_number),
            "issuer": cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) else "",
        }
    }


def verify_signature(doc_bytes: bytes, sig_package: dict) -> dict:
    """Verifica la firma de un documento contra su paquete de firma."""
    errors = []
    warnings = []
    checks = {}

    try:
        # 1. Verificar hash del documento
        alg = sig_package.get("hash_algorithm", "SHA256").lower()
        h = hashlib.new(alg, doc_bytes)
        computed_hash = h.hexdigest()
        expected_hash = sig_package.get("document_hash", "")
        hash_ok = computed_hash == expected_hash
        checks["integridad_documento"] = hash_ok
        if not hash_ok:
            errors.append("❌ El documento ha sido MODIFICADO después de la firma")
        else:
            checks["integridad_mensaje"] = "El documento no ha sido alterado"

        # 2. Cargar certificado del paquete
        cert_der = base64.b64decode(sig_package["signer_certificate"])
        cert = load_der_x509_certificate(cert_der, default_backend())
        checks["certificado_cargado"] = True

        # 3. Verificar vigencia del certificado al momento de la firma
        signing_time = datetime.datetime.fromisoformat(sig_package["signing_time"])
        nv_before = cert.not_valid_before_utc
        nv_after = cert.not_valid_after_utc
        cert_valid_at_signing = nv_before <= signing_time <= nv_after
        checks["certificado_vigente_al_firmar"] = cert_valid_at_signing
        if not cert_valid_at_signing:
            errors.append(f"❌ Certificado no vigente al momento de la firma ({signing_time.date()})")

        # 4. Verificar vigencia actual
        now = datetime.datetime.now(datetime.timezone.utc)
        cert_valid_now = nv_before <= now <= nv_after
        checks["certificado_vigente_ahora"] = cert_valid_now
        if not cert_valid_now:
            warnings.append(f"⚠️ El certificado está {'expirado' if now > nv_after else 'aún no activo'}")

        # 5. Verificar firma criptográfica
        signed_attrs = base64.b64decode(sig_package["signed_attributes"])
        sig_value = base64.b64decode(sig_package["signature_value"])
        sig_alg = sig_package.get("signature_algorithm", "RSA-SHA256")
        hash_alg_map = {
            "SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()
        }
        hash_part = sig_alg.split("-")[-1] if "-" in sig_alg else "SHA256"
        hash_alg_obj = hash_alg_map.get(hash_part, hashes.SHA256())

        pub_key = cert.public_key()
        try:
            if "ECDSA" in sig_alg:
                pub_key.verify(sig_value, signed_attrs, ec.ECDSA(hash_alg_obj))
            else:
                pub_key.verify(sig_value, signed_attrs, padding.PKCS1v15(), hash_alg_obj)
            checks["firma_criptografica"] = True
        except InvalidSignature:
            checks["firma_criptografica"] = False
            errors.append("❌ La firma criptográfica es INVÁLIDA")

        # 6. Coherencia de atributos firmados
        try:
            attrs_data = json.loads(signed_attrs.decode())
            attrs_match = attrs_data.get("document_hash") == expected_hash
            checks["atributos_firmados_coherentes"] = attrs_match
            if not attrs_match:
                errors.append("❌ Los atributos firmados no coinciden con el documento")
        except Exception:
            checks["atributos_firmados_coherentes"] = False
            warnings.append("⚠️ No se pudieron parsear los atributos firmados")

        cert_info = get_cert_info(cert)

    except Exception as e:
        errors.append(f"❌ Error durante verificación: {str(e)}")
        cert_info = {}
        checks["error_general"] = str(e)

    is_valid = len(errors) == 0 and checks.get("firma_criptografica", False)

    return {
        "valido": is_valid,
        "estado": "✅ FIRMA VÁLIDA" if is_valid else "❌ FIRMA INVÁLIDA",
        "errores": errors,
        "advertencias": warnings,
        "verificaciones": checks,
        "firmante": sig_package.get("signer_info", {}),
        "fecha_firma": sig_package.get("signing_time", ""),
        "algoritmo": sig_package.get("signature_algorithm", ""),
        "hash_documento": sig_package.get("document_hash", ""),
        "certificado": cert_info,
    }


# ─────────────────────────────────────────────────────────────
#  Rutas Flask
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/leer-certificado", methods=["POST"])
def leer_certificado():
    """Lee un certificado P12/K12 y retorna su información."""
    if "certificado" not in request.files:
        return jsonify({"error": "No se envió el archivo de certificado"}), 400

    p12_file = request.files["certificado"]
    password = request.form.get("password", "")

    try:
        p12_bytes = p12_file.read()
        priv_key, cert, chain = load_p12_certificate(p12_bytes, password)
        info = get_cert_info(cert)

        chain_info = []
        if chain:
            for c in chain:
                chain_info.append({
                    "cn": c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        if c.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "CA",
                    "org": c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                        if c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "",
                })

        return jsonify({
            "exito": True,
            "certificado": info,
            "cadena": chain_info,
            "tiene_clave_privada": priv_key is not None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/firmar", methods=["POST"])
def firmar_documento():
    """Firma un documento con un certificado P12/K12."""
    if "certificado" not in request.files or "documento" not in request.files:
        return jsonify({"error": "Faltan archivos requeridos"}), 400

    p12_file = request.files["certificado"]
    doc_file = request.files["documento"]
    password = request.form.get("password", "")
    algorithm = request.form.get("algoritmo", "SHA256").upper()

    if algorithm not in ("SHA256", "SHA384", "SHA512"):
        return jsonify({"error": "Algoritmo no válido. Use SHA256, SHA384 o SHA512"}), 400

    try:
        p12_bytes = p12_file.read()
        doc_bytes = doc_file.read()
        doc_name = doc_file.filename

        priv_key, cert, chain = load_p12_certificate(p12_bytes, password)

        if priv_key is None:
            return jsonify({"error": "El certificado no contiene clave privada"}), 400

        # Verificar vigencia
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > cert.not_valid_after_utc:
            return jsonify({"error": "El certificado ha expirado y no puede usarse para firmar"}), 400

        sig_package = sign_document(doc_bytes, priv_key, cert, algorithm)
        sig_package["document_name"] = doc_name

        # Guardar documento firmado + firma
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in doc_name)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"{ts}_{safe_name}.firma.json"
        out_path = SIGNED_FOLDER / out_name

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sig_package, f, ensure_ascii=False, indent=2)

        cert_info = get_cert_info(cert)

        return jsonify({
            "exito": True,
            "mensaje": f"Documento firmado exitosamente",
            "archivo_firma": out_name,
            "hash_documento": sig_package["document_hash"],
            "algoritmo": sig_package["signature_algorithm"],
            "fecha_firma": sig_package["signing_time"],
            "firmante": cert_info["titular"],
            "firma_base64": sig_package["signature_value"][:64] + "...",
            "paquete": sig_package,
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error al firmar: {str(e)}"}), 500


@app.route("/api/verificar", methods=["POST"])
def verificar_firma():
    """Verifica la firma de un documento."""
    if "documento" not in request.files:
        return jsonify({"error": "Falta el documento original"}), 400

    doc_file = request.files["documento"]
    doc_bytes = doc_file.read()

    # El paquete de firma puede venir como archivo o como JSON en el form
    sig_package = None

    if "firma" in request.files:
        firma_file = request.files["firma"]
        try:
            sig_package = json.loads(firma_file.read().decode("utf-8"))
        except Exception:
            return jsonify({"error": "El archivo de firma no es JSON válido"}), 400
    elif "firma_json" in request.form:
        try:
            sig_package = json.loads(request.form["firma_json"])
        except Exception:
            return jsonify({"error": "JSON de firma inválido"}), 400
    else:
        return jsonify({"error": "Debe proporcionar el archivo de firma (.firma.json)"}), 400

    try:
        result = verify_signature(doc_bytes, sig_package)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error en verificación: {str(e)}"}), 500


@app.route("/api/descargar-firma/<nombre>")
def descargar_firma(nombre):
    """Descarga el archivo de firma generado."""
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in nombre)
    path = SIGNED_FOLDER / safe
    if not path.exists():
        return jsonify({"error": "Archivo no encontrado"}), 404
    return send_file(path, as_attachment=True, download_name=safe)


@app.route("/api/generar-certificado-prueba", methods=["POST"])
def generar_certificado_prueba():
    """Genera un certificado P12 de prueba (solo para desarrollo/demo)."""
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    data = request.get_json() or {}
    nombre = data.get("nombre", "Usuario Prueba")
    org = data.get("organizacion", "Empresa Demo S.A.")
    password = data.get("password", "prueba123")

    key = rsa_mod.generate_private_key(65537, 2048, default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pichincha"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quito"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DEMO"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
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
        "mensaje": "⚠️ Certificado DEMO - Solo para pruebas. Use su certificado real del BCE o Security Data.",
    })


if __name__ == "__main__":
    print("🔐 Firmador Electrónico K12/P12 iniciando en http://localhost:5000")
    app.run(debug=True, port=5000)
