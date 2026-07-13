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

def _stamp_image_to_pdf_page(stamp_img: Image.Image, width_pt: float) -> bytes:
    """
    Convierte imagen PIL RGBA → página PDF mínima usando pikepdf.
    RGB → JPEG (q=80) + Alpha → FlateDecode grayscale = ~25–35 KB total.
    """
    import pikepdf, zlib

    sw, sh   = stamp_img.size
    height_pt = width_pt * sh / sw

    # ── Comprimir canal RGB como JPEG ──
    rgb = Image.new("RGB", stamp_img.size, (255, 255, 255))
    rgb.paste(stamp_img.convert("RGB"))
    jpeg_buf = io.BytesIO()
    rgb.save(jpeg_buf, "JPEG", quality=80, optimize=True, progressive=False)
    jpeg_bytes = jpeg_buf.getvalue()

    # ── Comprimir canal Alpha como grayscale FlateDecode ──
    alpha      = stamp_img.split()[3]           # canal alpha (L)
    alpha_raw  = alpha.tobytes()
    alpha_z    = zlib.compress(alpha_raw, 9)

    pdf = pikepdf.Pdf.new()

    # SMask (canal alpha)
    smask = pikepdf.Stream(pdf, alpha_z)
    smask.stream_dict.update(pikepdf.Dictionary(
        Type            = pikepdf.Name.XObject,
        Subtype         = pikepdf.Name.Image,
        Width           = sw,
        Height          = sh,
        ColorSpace      = pikepdf.Name.DeviceGray,
        BitsPerComponent= 8,
        Filter          = pikepdf.Name.FlateDecode,
    ))

    # Imagen principal (JPEG + SMask)
    xobj = pikepdf.Stream(pdf, jpeg_bytes)
    xobj.stream_dict.update(pikepdf.Dictionary(
        Type             = pikepdf.Name.XObject,
        Subtype          = pikepdf.Name.Image,
        Width            = sw,
        Height           = sh,
        ColorSpace       = pikepdf.Name.DeviceRGB,
        BitsPerComponent = 8,
        Filter           = pikepdf.Name.DCTDecode,
        SMask            = smask,
    ))

    # Página vacía del tamaño exacto del sello
    page_dict = pikepdf.Dictionary(
        Type     = pikepdf.Name.Page,
        MediaBox = pikepdf.Array([0, 0, width_pt, height_pt]),
        Resources= pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(Im0=xobj)
        ),
        Contents = pikepdf.Stream(
            pdf,
            f"q {width_pt:.4f} 0 0 {height_pt:.4f} 0 0 cm /Im0 Do Q\n".encode()
        ),
    )
    pdf.pages.append(pikepdf.Page(page_dict))

    out = io.BytesIO()
    pdf.save(out, compress_streams=True,
             object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return out.getvalue()


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


def embed_stamp_in_pdf(pdf_bytes: bytes, stamp_img: Image.Image,
                        sig_json: dict, signer_info: dict) -> bytes:
    """
    Incrusta el sello directamente como XObject JPEG+SMask en la última
    página del PDF usando pikepdf.  Sin pypdf overlay — evita el bug del
    contenido vacío y produce archivos ~40-50 KB.
    """
    import pikepdf, zlib

    # Abrir PDF con pikepdf (tolerante a PDFs malformados)
    try:
        pdf = pikepdf.open(io.BytesIO(pdf_bytes))
    except Exception:
        # Intentar reparar via pypdf y re-abrir
        reader = _safe_read_pdf(pdf_bytes)
        writer = PdfWriter()
        for p in reader.pages:
            writer.add_page(p)
        buf = io.BytesIO(); writer.write(buf)
        pdf = pikepdf.open(io.BytesIO(buf.getvalue()))

    page   = pdf.pages[-1]
    page_w = float(page.mediabox[2])

    sw, sh        = stamp_img.size
    stamp_w_pt    = max(130, min(220, page_w * 0.40))
    stamp_h_pt    = stamp_w_pt * sh / sw
    margin        = 18  # puntos PDF

    # ── Comprimir imagen ──
    # RGB como JPEG
    rgb      = Image.new("RGB", stamp_img.size, (255, 255, 255))
    rgb.paste(stamp_img.convert("RGB"))
    jpeg_buf = io.BytesIO()
    rgb.save(jpeg_buf, "JPEG", quality=80, optimize=True)
    jpeg_bytes = jpeg_buf.getvalue()

    # Alpha como FlateDecode grayscale
    alpha_z = zlib.compress(stamp_img.split()[3].tobytes(), 9)

    # ── XObjects ──
    smask = pikepdf.Stream(pdf, alpha_z)
    smask.stream_dict.update(pikepdf.Dictionary(
        Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Image,
        Width=sw, Height=sh, ColorSpace=pikepdf.Name.DeviceGray,
        BitsPerComponent=8, Filter=pikepdf.Name.FlateDecode,
    ))

    xobj = pikepdf.Stream(pdf, jpeg_bytes)
    xobj.stream_dict.update(pikepdf.Dictionary(
        Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Image,
        Width=sw, Height=sh, ColorSpace=pikepdf.Name.DeviceRGB,
        BitsPerComponent=8, Filter=pikepdf.Name.DCTDecode,
        SMask=smask,
    ))

    # ── Registrar XObject en Resources de la página ──
    if "/Resources" not in page.obj:
        page.obj["/Resources"] = pikepdf.Dictionary()
    res = page.obj["/Resources"]
    if "/XObject" not in res:
        res["/XObject"] = pikepdf.Dictionary()
    xname = "/FirmaSello"
    res["/XObject"][xname] = xobj

    # ── Content stream: dibujar el sello ──
    # IMPORTANTE: debe ser un objeto INDIRECTO para que pikepdf lo
    # serialice correctamente al guardar.
    stamp_cmd = (
        f"q "
        f"{stamp_w_pt:.3f} 0 0 {stamp_h_pt:.3f} "
        f"{margin:.3f} {margin:.3f} cm "
        f"{xname} Do "
        f"Q\n"
    ).encode()

    new_s = pdf.make_indirect(pikepdf.Stream(pdf, stamp_cmd))

    existing = page.obj.get("/Contents")
    if existing is None:
        page.obj["/Contents"] = new_s
    elif isinstance(existing, pikepdf.Array):
        existing.append(new_s)
    else:
        # Convertir el stream existente a indirecto si no lo es
        if not existing.is_indirect:
            existing = pdf.make_indirect(existing)
        page.obj["/Contents"] = pikepdf.Array([existing, new_s])

    # ── Metadatos ──
    titular = signer_info.get("cn", "")
    org     = signer_info.get("org", "")
    try:
        with pdf.open_metadata() as meta:
            meta["dc:creator"]     = [titular]
            meta["dc:description"] = (
                f"Firmado digitalmente · {sig_json.get('signing_time','')}"
            )
    except Exception:
        pass
    pdf.docinfo.update({
        "/Author":        titular,
        "/Subject":       "Documento Firmado Electrónicamente - Ecuador",
        "/Keywords":      f"firma-electronica;{sig_json.get('signature_algorithm','')};K12",
        "/Creator":       "Firmador Electrónico K12/P12 v1.0",
        "/FirmadoPor":    titular,
        "/FirmadoOrg":    org,
        "/FechaFirma":    sig_json.get("signing_time", ""),
        "/Algoritmo":     sig_json.get("signature_algorithm", ""),
        "/HashDocumento": sig_json.get("document_hash", ""),
    })

    out = io.BytesIO()
    pdf.save(out, compress_streams=True,
             object_stream_mode=pikepdf.ObjectStreamMode.generate)
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

    # Agregar sello
    signer_name = si.get("cn", "Firmante")
    org         = si.get("org", "")
    date_str    = sig_json.get("signing_time", "")[:19].replace("T", " ")
    doc_hash    = sig_json.get("document_hash", "")
    alg         = sig_json.get("signature_algorithm", "")
    serial      = si.get("serial", "")
    verify_url  = f"{BASE_VERIFY_URL}?serial={serial}&hash={doc_hash[:16]}"

    stamp_img = make_signature_stamp(signer_name, org, date_str, doc_hash, alg, serial,
                                     verify_url=verify_url, logo_path=str(LOGO_PATH))
    last_page = writer.pages[-1]
    page_w = float(last_page.mediabox.width)
    stamp_w_pt = max(130, min(230, page_w * 0.42))
    stamp_pdf_bytes = _stamp_image_to_pdf_page(stamp_img, stamp_w_pt)
    stamp_reader = PdfReader(io.BytesIO(stamp_pdf_bytes))
    stamp_page   = stamp_reader.pages[0]
    margin = 18
    last_page.merge_transformed_page(
        stamp_page, Transformation().translate(tx=margin, ty=margin), expand=False
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

        # URL de verificación incrustada en el QR del sello
        verify_url = f"{BASE_VERIFY_URL}?serial={serial}&hash={doc_hash[:16]}"

        # Sello visual: compacto, fondo transparente, logo + QR
        stamp_img = make_signature_stamp(signer_name, org, date_str,
                                         doc_hash, alg, serial, emisor,
                                         verify_url=verify_url,
                                         logo_path=str(LOGO_PATH))

        # Determinar si el documento es PDF
        is_pdf = (doc_bytes[:4] == b"%PDF" or doc_name.lower().endswith(".pdf"))

        if is_pdf:
            try:
                signed_pdf = embed_stamp_in_pdf(doc_bytes, stamp_img, sig_json, si)
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
