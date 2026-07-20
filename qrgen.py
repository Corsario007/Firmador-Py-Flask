"""
Generador de códigos QR multiplataforma.

Backends soportados (detectados automáticamente en orden):
  1. qrcode[pil]   pip install qrcode[pil]   → Windows / Linux / macOS
  2. segno         pip install segno          → Windows / Linux / macOS
  3. libqrencode   apt install libqrencode4   → Linux / macOS (sin pip)

En Windows usa el backend 1 o 2:
    pip install qrcode[pil]
    pip install segno
"""

from __future__ import annotations
from PIL import Image
import io
import platform


# ─── Backend 1: qrcode (pip install qrcode[pil]) ─────────────
def _try_qrcode(text: str, box_size: int, border: int,
                fg: tuple, bg: tuple) -> Image.Image | None:
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=box_size,
            border=border,
        )
        qr.add_data(text)
        qr.make(fit=True)
        pil = qr.make_image(fill_color=fg[:3], back_color=(255, 255, 255)).convert("RGBA")
        if bg[3] == 0:
            px = pil.load()
            for y in range(pil.height):
                for x in range(pil.width):
                    r, g, b, a = px[x, y]
                    if r > 200 and g > 200 and b > 200:
                        px[x, y] = (r, g, b, 0)
        return pil
    except ImportError:
        return None
    except Exception:
        return None


# ─── Backend 2: segno (pip install segno) ────────────────────
def _try_segno(text: str, box_size: int, border: int,
               fg: tuple, bg: tuple) -> Image.Image | None:
    try:
        import segno
        qr = segno.make_qr(text, error="m")
        buf = io.BytesIO()
        dark  = "#{:02x}{:02x}{:02x}".format(*fg[:3])
        light = (0, 0, 0, 0) if bg[3] == 0 else "#{:02x}{:02x}{:02x}".format(*bg[:3])
        qr.save(buf, kind="png", scale=box_size, border=border,
                dark=dark, light=light)
        buf.seek(0)
        return Image.open(buf).convert("RGBA")
    except ImportError:
        return None
    except Exception:
        return None


# ─── Backend 3: libqrencode ctypes (Linux / macOS) ───────────
def _try_libqrencode(text: str, box_size: int, border: int,
                     fg: tuple, bg: tuple) -> Image.Image | None:
    if platform.system() == "Windows":
        return None
    import ctypes, ctypes.util
    candidates = [
        "/usr/lib/x86_64-linux-gnu/libqrencode.so.4",
        "/usr/lib/aarch64-linux-gnu/libqrencode.so.4",
        "/usr/lib/libqrencode.so.4",
        "/usr/local/lib/libqrencode.so.4",
        ctypes.util.find_library("qrencode") or "",
    ]
    lib = None
    for name in candidates:
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if lib is None:
        return None
    try:
        from ctypes import c_char_p, c_int, Structure, POINTER, c_ubyte

        class _QR(Structure):
            _fields_ = [("version", c_int), ("width", c_int),
                        ("data", POINTER(c_ubyte))]

        lib.QRcode_encodeString.restype  = POINTER(_QR)
        lib.QRcode_encodeString.argtypes = [c_char_p, c_int, c_int, c_int, c_int]
        lib.QRcode_free.argtypes         = [POINTER(_QR)]

        ptr = lib.QRcode_encodeString(text.encode("utf-8"), 0, 1, 3, 1)
        if not ptr:
            return None
        qr  = ptr.contents
        w   = qr.width
        raw = ctypes.cast(qr.data, POINTER(c_ubyte * (w * w))).contents
        mat = [[(raw[r * w + c] & 1) for c in range(w)] for r in range(w)]
        lib.QRcode_free(ptr)

        sz  = (w + border * 2) * box_size
        img = Image.new("RGBA", (sz, sz), bg)
        px  = img.load()
        for r in range(w):
            for c in range(w):
                if mat[r][c]:
                    x0 = (c + border) * box_size
                    y0 = (r + border) * box_size
                    for dx in range(box_size):
                        for dy in range(box_size):
                            px[x0 + dx, y0 + dy] = fg
        return img
    except Exception:
        return None


# ─── Detección de backend ─────────────────────────────────────
_BACKEND: str | None = None

def _detect() -> str:
    global _BACKEND
    if _BACKEND:
        return _BACKEND
    try:
        import qrcode  # noqa
        _BACKEND = "qrcode"; return _BACKEND
    except ImportError:
        pass
    try:
        import segno  # noqa
        _BACKEND = "segno"; return _BACKEND
    except ImportError:
        pass
    if platform.system() != "Windows":
        import ctypes, ctypes.util
        for name in [
            "/usr/lib/x86_64-linux-gnu/libqrencode.so.4",
            "/usr/lib/aarch64-linux-gnu/libqrencode.so.4",
            "/usr/lib/libqrencode.so.4",
            ctypes.util.find_library("qrencode") or "",
        ]:
            if not name:
                continue
            try:
                ctypes.CDLL(name)
                _BACKEND = f"libqrencode:{name}"; return _BACKEND
            except OSError:
                pass

    _BACKEND = "none"
    return _BACKEND


# ─── API pública ──────────────────────────────────────────────
def qr_to_image(text: str,
                box_size: int = 6,
                border: int = 2,
                fg: tuple = (0, 0, 0, 255),
                bg: tuple = (255, 255, 255, 0),
                ec_level: str = "M") -> Image.Image:
    """
    Genera una imagen PIL RGBA con el código QR.
    bg con alpha=0 → fondo transparente (predeterminado).

    Si no hay backend disponible, lanza ImportError con instrucciones.
    """
    b = _detect()

    img = None
    if b == "qrcode":
        img = _try_qrcode(text, box_size, border, fg, bg)
    elif b == "segno":
        img = _try_segno(text, box_size, border, fg, bg)
    elif b.startswith("libqrencode:"):
        img = _try_libqrencode(text, box_size, border, fg, bg)

    if img is not None:
        return img

    # Ningún backend disponible
    sys_name = platform.system()
    if sys_name == "Windows":
        instrucciones = (
            "No se encontró ningún generador de QR.\n"
            "Instala uno con:\n"
            "    pip install qrcode[pil]\n"
            "  ó\n"
            "    pip install segno"
        )
    else:
        instrucciones = (
            "No se encontró ningún generador de QR.\n"
            "Instala uno con:\n"
            "    pip install qrcode[pil]\n"
            "  ó\n"
            "    sudo apt-get install libqrencode4"
        )
    raise ImportError(instrucciones)


def backend_name() -> str:
    """Retorna el nombre del backend QR activo."""
    return _detect()


# ─── Auto-test al ejecutar directamente ──────────────────────
if __name__ == "__main__":
    import sys
    print(f"Sistema operativo : {platform.system()}")
    print(f"Backend activo    : {backend_name()}")

    if backend_name() == "none":
        print("\nERROR: Ningún backend disponible.")
        print("  Windows : pip install qrcode[pil]")
        print("  Linux   : pip install qrcode[pil]  ó  apt install libqrencode4")
        sys.exit(1)

    text = "https://verificar.firmaec.gob.ec/v/TEST-12345"
    img  = qr_to_image(text, box_size=6, border=2)

    out = "qr_test.png"
    canvas = Image.new("RGB", img.size, (255, 255, 255))
    canvas.paste(img, mask=img.split()[3])
    canvas.save(out)

    print(f"QR generado       : {img.size[0]}×{img.size[1]} px → {out}")
    print("Escanea el archivo con tu celular para verificar.")
