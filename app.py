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
from pypdf.generic import RectangleObject
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.units import mm
from PIL import Image, ImageDraw, ImageFont

from qrgen import qr_to_image

app = Flask(__name__, static_folder="static")

UPLOAD_FOLDER = Path("/tmp/firmador")
UPLOAD_FOLDER.mkdir(exist_ok=True)
SIGNED_FOLDER = UPLOAD_FOLDER / "firmados"
SIGNED_FOLDER.mkdir(exist_ok=True)

LOGO_PATH = Path(__file__).parent / "static" / "logo_empresa.png"
# Base URL pública usada para construir el enlace de verificación dentro del QR.
# Ajusta esto a tu dominio real en producción (variable de entorno recomendado).
BASE_VERIFY_URL = os.environ.get("BASE_VERIFY_URL", "http://localhost:5000/verificar")


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
#  Sello visual de firma (stamp) — PNG transparente con
#  logo institucional + código QR de verificación
# ──────────────────────────────────────────────────────────

def _get_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = (
        ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"] if bold else
        ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    )
    for fp in candidates:
        try:
            return ImageFont.truetype(fp, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _fit_text(draw: ImageDraw.ImageDraw, s: str, font, max_w: float) -> str:
    if draw.textlength(s, font=font) <= max_w:
        return s
    while s and draw.textlength(s + "…", font=font) > max_w:
        s = s[:-1]
    return s + "…"


def make_signature_stamp(signer_name: str, org: str, date_str: str,
                          doc_hash: str, alg: str, serial: str,
                          emisor: str = "", verify_url: str = "",
                          logo_path=None, scale: int = 2) -> Image.Image:
    """
    Genera el sello de firma como imagen PNG (RGBA, fondo transparente).
    Diseño compacto: logo institucional | datos del firmante | QR de verificación.
    scale=2 produce 680×190 px — nítido a 150 dpi sin inflar el PDF.
    """
    W, H = 340 * scale, 95 * scale
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = 6 * scale
    border_color = (25, 70, 160, 255)
    bg_color = (247, 250, 255, 235)

    draw.rounded_rectangle(
        [1, 1, W - 2, H - 2], radius=8 * scale,
        fill=bg_color, outline=border_color, width=max(1, scale)
    )

    x = pad

    # ── Logo institucional: pre-escalar al tamaño real de uso ──
    logo_box = H - 2 * pad       # cuadrado, mismo alto que el QR
    if logo_path and Path(logo_path).exists():
        try:
            logo = Image.open(logo_path).convert("RGBA")
            # Pre-reducir AL TAMAÑO DE USO antes de componer
            ratio = min(logo_box / logo.width, logo_box / logo.height)
            new_w = max(1, int(logo.width * ratio))
            new_h = max(1, int(logo.height * ratio))
            logo = logo.resize((new_w, new_h), Image.LANCZOS)
            ly = pad + (logo_box - new_h) // 2
            img.paste(logo, (int(x) + (logo_box - new_w) // 2, int(ly)), logo)
            x += logo_box + pad
        except Exception:
            pass  # sin logo si falla

    # Separador vertical
    draw.line([(x, pad), (x, H - pad)], fill=(190, 198, 215, 255), width=max(1, scale // 2))
    x += pad * 1.3

    # ── QR de verificación (a la derecha) ──
    qr_size = H - 2 * pad
    qr_x = W - pad  # fallback sin QR
    if verify_url:
        try:
            qr_img = qr_to_image(verify_url, box_size=max(2, scale), border=1)
            qr_img = qr_img.resize((qr_size, qr_size), Image.LANCZOS)
            qr_x = W - pad - qr_size
            img.paste(qr_img, (int(qr_x), int(pad)), qr_img)
        except Exception:
            pass

    # ── Texto central ──
    text_x     = x
    avail_w    = max(10, qr_x - pad - text_x)

    f_title = _get_font(11 * scale // 2, bold=True)
    f_label = _get_font(9  * scale // 2, bold=True)
    f_small = _get_font(7  * scale // 2)

    ty     = pad + 1 * scale
    r      = 4 * scale
    draw.ellipse([text_x, ty, text_x + r * 2, ty + r * 2], fill=(25, 140, 70, 255))
    cx, cy = text_x + r, ty + r
    draw.line(
        [(cx - r * 0.45, cy), (cx - r * 0.1, cy + r * 0.4), (cx + r * 0.5, cy - r * 0.4)],
        fill=(255, 255, 255, 255), width=max(1, scale // 2), joint="curve",
    )
    draw.text((text_x + r * 2 + 4 * scale, ty - 1 * scale),
               "FIRMADO DIGITALMENTE", font=f_title, fill=(20, 45, 100, 255))
    ty += 11 * scale

    line_gap = 9.5 * scale
    draw.text((text_x, ty), _fit_text(draw, signer_name, f_label, avail_w),
               font=f_label, fill=(15, 15, 15, 255))
    ty += line_gap
    draw.text((text_x, ty), _fit_text(draw, org or "N/A", f_small, avail_w),
               font=f_small, fill=(75, 80, 95, 255))
    ty += line_gap - 1.5 * scale
    draw.text((text_x, ty), _fit_text(draw, f"{date_str}  ·  {alg}", f_small, avail_w),
               font=f_small, fill=(75, 80, 95, 255))
    ty += line_gap - 1.5 * scale
    draw.text((text_x, ty), _fit_text(draw, f"Serie: {serial}", f_small, avail_w),
               font=f_small, fill=(100, 105, 120, 255))
    ty += line_gap - 1.5 * scale
    draw.text((text_x, ty), _fit_text(draw, f"Hash: {doc_hash}", f_small, avail_w),
               font=f_small, fill=(120, 125, 140, 255))

    return img


# ──────────────────────────────────────────────────────────
#  Incrustar sello en PDF existente
# ──────────────────────────────────────────────────────────

def _build_stamp_pdf(signer_name: str, org: str, date_str: str,
                      doc_hash: str, alg: str, serial: str,
                      verify_url: str, logo_path=None,
                      width_pt: float = 210) -> bytes:
    """
    Genera el sello de firma directamente como página PDF vectorial con
    ReportLab — sin PIL intermedio, sin pikepdf XObject, sin SMask.
    Compatible 100 % en Windows, Linux y macOS.

    Layout (izquierda → derecha):
      [Logo]  |  [Texto de firma]  |  [QR]
    """
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.utils import ImageReader
    from reportlab.lib import colors

    ASPECT   = 190 / 680          # ratio ancho/alto del sello
    H        = width_pt * ASPECT
    pad      = width_pt * 0.018   # ~3.8 pt para width=210

    buf = io.BytesIO()
    c   = rl_canvas.Canvas(buf, pagesize=(width_pt, H))

    # ── Fondo con borde redondeado ──────────────────────────────
    c.setFillColorRGB(0.96, 0.97, 1.0)
    c.setStrokeColorRGB(0.10, 0.27, 0.63)
    c.setLineWidth(0.8)
    c.roundRect(0.5, 0.5, width_pt - 1, H - 1, 4, fill=1, stroke=1)

    x = pad  # cursor X izquierdo

    # ── Logo institucional ──────────────────────────────────────
    logo_box = H - 2 * pad          # cuadrado disponible para el logo
    logo_drawn = 0
    if logo_path and Path(logo_path).exists():
        try:
            logo_pil = Image.open(logo_path).convert("RGBA")
            # Componer sobre blanco para eliminar canal alpha
            bg_logo  = Image.new("RGB", logo_pil.size, (255, 255, 255))
            bg_logo.paste(logo_pil, mask=logo_pil.split()[3])
            # Calcular dimensiones manteniendo proporción
            ratio    = min(logo_box / bg_logo.width, logo_box / bg_logo.height)
            lw       = bg_logo.width  * ratio
            lh       = bg_logo.height * ratio
            # Centrar verticalmente en el espacio disponible
            ly       = pad + (logo_box - lh) / 2
            lx       = x   + (logo_box - lw) / 2
            # Convertir a ImageReader que ReportLab acepta
            jpg_buf  = io.BytesIO()
            bg_logo.save(jpg_buf, "JPEG", quality=85, optimize=True)
            jpg_buf.seek(0)
            c.drawImage(ImageReader(jpg_buf), lx, ly,
                        width=lw, height=lh, mask="auto")
            logo_drawn = logo_box
        except Exception:
            pass

    x += logo_drawn + pad

    # ── Separador vertical ──────────────────────────────────────
    c.setStrokeColorRGB(0.75, 0.80, 0.88)
    c.setLineWidth(0.5)
    c.line(x, pad, x, H - pad)
    x += pad * 1.2

    # ── QR de verificación (a la derecha) ───────────────────────
    qr_size    = H - 2 * pad
    qr_x       = width_pt - pad - qr_size
    qr_drawn   = False
    if verify_url:
        try:
            from qrgen import qr_to_image
            qr_pil = qr_to_image(verify_url, box_size=3, border=1,
                                  fg=(0,0,0,255), bg=(255,255,255,255))
            qr_buf = io.BytesIO()
            qr_pil.convert("RGB").save(qr_buf, "PNG", optimize=True)
            qr_buf.seek(0)
            c.drawImage(ImageReader(qr_buf), qr_x, pad,
                        width=qr_size, height=qr_size)
            qr_drawn = True
        except Exception:
            pass

    # ── Texto central ────────────────────────────────────────────
    text_x     = x
    text_right = (qr_x - pad) if qr_drawn else (width_pt - pad)
    text_w     = text_right - text_x

    def trunc(s, max_w, font, size):
        """Trunca texto para que quepa en max_w puntos."""
        from reportlab.pdfbase.pdfmetrics import stringWidth
        if not s:
            return ""
        while s and stringWidth(s + "…", font, size) > max_w:
            s = s[:-1]
        if stringWidth(s, font, size) <= max_w:
            return s
        return s + "…"

    # Ícono de check verde
    ck_r   = min(H * 0.10, 4.5)
    ck_x   = text_x + ck_r
    ck_y   = H - pad - ck_r * 1.4
    c.setFillColorRGB(0.10, 0.55, 0.27)
    c.circle(ck_x, ck_y, ck_r, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setLineWidth(0.8)
    c.setStrokeColorRGB(1, 1, 1)
    # Checkmark (✓) dibujado a mano
    ck_s = ck_r * 0.5
    c.setLineWidth(max(0.7, ck_r * 0.25))
    c.setLineCap(1)
    from reportlab.graphics.shapes import Drawing
    c.lines([
        (ck_x - ck_s * 0.6, ck_y,
         ck_x - ck_s * 0.1, ck_y - ck_s * 0.5),
        (ck_x - ck_s * 0.1, ck_y - ck_s * 0.5,
         ck_x + ck_s * 0.7, ck_y + ck_s * 0.6),
    ])

    # Cabecera "FIRMADO DIGITALMENTE"
    fs_title = max(5, H * 0.13)
    c.setFillColorRGB(0.08, 0.18, 0.42)
    c.setFont("Helvetica-Bold", fs_title)
    tx_header = text_x + ck_r * 2.4
    c.drawString(tx_header, H - pad - fs_title * 0.9, "FIRMADO DIGITALMENTE")

    # Resto de líneas
    fs_name  = max(4.5, H * 0.115)
    fs_small = max(3.5, H * 0.090)
    line_gap = H * 0.135

    ty = H - pad - fs_title * 1.05 - line_gap * 0.7

    c.setFont("Helvetica-Bold", fs_name)
    c.setFillColorRGB(0.05, 0.05, 0.05)
    c.drawString(text_x, ty, trunc(signer_name, text_w, "Helvetica-Bold", fs_name))
    ty -= line_gap * 0.90

    c.setFont("Helvetica", fs_small)
    c.setFillColorRGB(0.25, 0.28, 0.35)
    for line in [
        trunc(org or "", text_w, "Helvetica", fs_small),
        trunc(f"{date_str}  ·  {alg}", text_w, "Helvetica", fs_small),
        trunc(f"Serie: {serial}", text_w, "Helvetica", fs_small),
        trunc(f"Hash: {doc_hash}", text_w, "Helvetica", fs_small),
    ]:
        c.drawString(text_x, ty, line)
        ty -= line_gap * 0.82

    c.save()
    return buf.getvalue()


def _safe_read_pdf(pdf_bytes: bytes) -> "PdfReader":
    """Lee un PDF de forma tolerante; repara con pikepdf si falla."""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)
        _ = len(reader.pages)
        return reader
    except Exception:
        pass
    try:
        import pikepdf
        with pikepdf.open(io.BytesIO(pdf_bytes)) as p:
            repaired = io.BytesIO()
            p.save(repaired)
        repaired.seek(0)
        return PdfReader(repaired, strict=False)
    except Exception:
        pass
    return PdfReader(io.BytesIO(pdf_bytes), strict=False)


def embed_stamp_in_pdf(pdf_bytes: bytes, stamp_img: Image.Image,
                        sig_json: dict, signer_info: dict) -> bytes:
    """
    Fusiona el sello de firma (generado por ReportLab como página PDF)
    sobre la última página del documento usando pypdf.
    Estrategia 100 % compatible con Windows.
    """
    si          = signer_info
    date_str    = sig_json.get("signing_time", "")[:19].replace("T", " ")
    verify_url  = sig_json.get("_verify_url", "")

    # Leer PDF original
    reader  = _safe_read_pdf(pdf_bytes)
    page_w  = float(reader.pages[-1].mediabox.width)

    stamp_w_pt = max(150, min(230, page_w * 0.42))

    # Generar sello como página PDF con ReportLab
    stamp_pdf = _build_stamp_pdf(
        signer_name = si.get("cn",     ""),
        org         = si.get("org",    ""),
        date_str    = date_str,
        doc_hash    = sig_json.get("document_hash", ""),
        alg         = sig_json.get("signature_algorithm", ""),
        serial      = si.get("serial", ""),
        verify_url  = verify_url,
        logo_path   = str(LOGO_PATH),
        width_pt    = stamp_w_pt,
    )

    # Fusionar con pypdf
    writer      = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    stamp_reader = PdfReader(io.BytesIO(stamp_pdf))
    last_page    = writer.pages[-1]
    last_page.merge_transformed_page(
        stamp_reader.pages[0],
        Transformation().translate(tx=18, ty=18),
        expand=False,
    )

    # Metadatos
    titular = si.get("cn", "")
    writer.add_metadata({
        "/Author":        titular,
        "/Subject":       "Documento Firmado Electrónicamente - Ecuador",
        "/Keywords":      f"firma-electronica;{sig_json.get('signature_algorithm','')};K12",
        "/Creator":       "Firmador Electrónico K12/P12 v1.0",
        "/FirmadoPor":    titular,
        "/FirmadoOrg":    si.get("org", ""),
        "/FechaFirma":    sig_json.get("signing_time", ""),
        "/Algoritmo":     sig_json.get("signature_algorithm", ""),
        "/HashDocumento": sig_json.get("document_hash", ""),
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

    # Logo institucional en el encabezado (si existe)
    title_x = 30
    if LOGO_PATH.exists():
        try:
            logo_img = Image.open(LOGO_PATH).convert("RGBA")
            logo_h_pt = 42
            ratio = logo_h_pt / logo_img.height
            logo_w_pt = logo_img.width * ratio
            from reportlab.lib.utils import ImageReader
            logo_buf = io.BytesIO()
            logo_img.save(logo_buf, format="PNG")
            logo_buf.seek(0)
            c.drawImage(ImageReader(logo_buf), 30, H - 51, width=logo_w_pt,
                        height=logo_h_pt, mask="auto")
            title_x = 30 + logo_w_pt + 14
        except Exception:
            pass

    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(title_x, H - 35, "Comprobante de Firma Electrónica")
    c.setFont("Helvetica", 9)
    c.drawString(title_x, H - 52, "República del Ecuador — Firma Digital PKI PKCS#12")

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

    # Agregar sello con ReportLab (compatible Windows)
    signer_name = si.get("cn", "Firmante")
    org         = si.get("org", "")
    date_str    = sig_json.get("signing_time", "")[:19].replace("T", " ")
    doc_hash    = sig_json.get("document_hash", "")
    alg         = sig_json.get("signature_algorithm", "")
    serial      = si.get("serial", "")
    verify_url  = sig_json.get("_verify_url",
                   f"{BASE_VERIFY_URL}?serial={serial}&hash={doc_hash[:16]}")

    stamp_w_pt  = max(150, min(230, float(writer.pages[-1].mediabox.width) * 0.42))
    stamp_pdf_b = _build_stamp_pdf(
        signer_name=signer_name, org=org, date_str=date_str,
        doc_hash=doc_hash, alg=alg, serial=serial,
        verify_url=verify_url, logo_path=str(LOGO_PATH),
        width_pt=stamp_w_pt,
    )
    stamp_reader = PdfReader(io.BytesIO(stamp_pdf_b))
    writer.pages[-1].merge_transformed_page(
        stamp_reader.pages[0],
        Transformation().translate(tx=18, ty=18),
        expand=False,
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

        # URL de verificación incrustada en el QR del sello
        verify_url = f"{BASE_VERIFY_URL}?serial={serial}&hash={doc_hash[:16]}"
        sig_json["_verify_url"] = verify_url   # lo necesita embed_stamp_in_pdf

        # Determinar si el documento es PDF
        is_pdf = (doc_bytes[:4] == b"%PDF" or doc_name.lower().endswith(".pdf"))

        if is_pdf:
            try:
                signed_pdf = embed_stamp_in_pdf(doc_bytes, None, sig_json, si)
            except Exception as embed_err:
                print(f"[WARN] embed_stamp falló ({embed_err}); usando comprobante.")
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
