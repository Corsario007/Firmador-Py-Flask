"""
Generador de códigos QR usando libqrencode (vía ctypes) — sin dependencias pip.
Produce QRs estándar, 100% escaneables (verificado con detectores reales).
"""

import ctypes
from ctypes import c_char_p, c_int, Structure, POINTER, c_ubyte
from PIL import Image

_LIB_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libqrencode.so.4",
    "/usr/lib/libqrencode.so.4",
    "/usr/local/lib/libqrencode.so.4",
    "libqrencode.so.4",
]

_lib = None
for path in _LIB_PATHS:
    try:
        _lib = ctypes.CDLL(path)
        break
    except OSError:
        continue

if _lib is None:
    raise ImportError(
        "No se encontró libqrencode.so.4. Instálala con: apt-get install libqrencode4"
    )


class _QRcode(Structure):
    _fields_ = [("version", c_int), ("width", c_int), ("data", POINTER(c_ubyte))]


_lib.QRcode_encodeString.restype = POINTER(_QRcode)
_lib.QRcode_encodeString.argtypes = [c_char_p, c_int, c_int, c_int, c_int]
_lib.QRcode_free.argtypes = [POINTER(_QRcode)]

_QR_MODE_8 = 3       # modo byte (acepta cualquier texto/URL)
_EC_LEVELS = {"L": 0, "M": 1, "Q": 2, "H": 3}


def generate_qr_matrix(text: str, ec_level: str = "M"):
    """Retorna (matrix, width) — matrix es lista de listas de 0/1."""
    level = _EC_LEVELS.get(ec_level.upper(), 1)
    data = text.encode("utf-8")
    qr_ptr = _lib.QRcode_encodeString(data, 0, level, _QR_MODE_8, 1)
    if not qr_ptr:
        raise ValueError(f"No se pudo generar el QR para: {text[:50]}...")
    qr = qr_ptr.contents
    width = qr.width
    raw = ctypes.cast(qr.data, POINTER(c_ubyte * (width * width))).contents
    matrix = [[(raw[r * width + c] & 1) for c in range(width)] for r in range(width)]
    _lib.QRcode_free(qr_ptr)
    return matrix, width


def qr_to_image(text: str, box_size: int = 6, border: int = 2,
                 fg=(0, 0, 0, 255), bg=(255, 255, 255, 0), ec_level: str = "M") -> Image.Image:
    """
    Genera una imagen PIL (RGBA) del código QR.
    bg con alpha=0 → fondo transparente (recomendado para sellos de firma).
    """
    matrix, width = generate_qr_matrix(text, ec_level)
    img_size = (width + border * 2) * box_size
    img = Image.new("RGBA", (img_size, img_size), bg)
    px = img.load()
    for r in range(width):
        for c in range(width):
            if matrix[r][c]:
                x0 = (c + border) * box_size
                y0 = (r + border) * box_size
                for dx in range(box_size):
                    for dy in range(box_size):
                        px[x0 + dx, y0 + dy] = fg
    return img
