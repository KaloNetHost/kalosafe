"""
KALOSAFE — Evidence watermarking.

For every uploaded image, app.py stores the untouched ORIGINAL file
and calls make_watermarked_copy() to produce a separate ANALYST COPY.
The original bytes on disk are never opened in write mode again.
The watermark is drawn onto a copy of the pixel buffer only.
"""
from PIL import Image, ImageDraw, ImageFont
import os

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def _font(size):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def make_watermarked_copy(original_path, output_path, case_number, analyst_codename):
    """
    File-path version (kept for local/offline use). Adds a top-right
    watermark stamp to a copy of the image on disk. See
    make_watermarked_bytes() for the in-memory version used when
    evidence is stored in Supabase Storage rather than local disk.
    """
    with open(original_path, "rb") as f:
        data = f.read()
    stamped = make_watermarked_bytes(data, case_number, analyst_codename)
    with open(output_path, "wb") as f:
        f.write(stamped)


def make_watermarked_bytes(original_bytes, case_number, analyst_codename):
    """
    Adds a top-right watermark stamp:
        CONFIDENTIAL — CASE [CASE NUMBER]
        [ANALYST CODENAME]
        PROPERTY OF KALOSAFE
    Does not crop or obscure any existing image content — the stamp is
    alpha-blended onto a translucent bar so underlying detail (usernames,
    timestamps, avatars) stays legible. Takes and returns raw bytes so it
    never has to touch local disk (evidence now lives in Supabase Storage).
    """
    import io

    img = Image.open(io.BytesIO(original_bytes)).convert("RGBA")
    w, h = img.size

    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    case_label = case_number if case_number.upper().startswith("CASE") else f"CASE {case_number}"
    lines = [
        f"CONFIDENTIAL \u2014 {case_label}",
        analyst_codename,
        "PROPERTY OF KALOSAFE",
    ]
    size = max(12, w // 45)
    font = _font(size)

    line_heights = []
    max_line_w = 0
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        lw, lh = bbox[2] - bbox[0], bbox[3] - bbox[1]
        line_heights.append(lh)
        max_line_w = max(max_line_w, lw)

    pad = int(size * 0.6)
    bar_w = max_line_w + pad * 2
    bar_h = sum(line_heights) + pad * 2 + (len(lines) - 1) * int(size * 0.3)

    bar_x0 = max(0, w - bar_w - 10)
    bar_y0 = 10
    draw.rectangle(
        [bar_x0, bar_y0, bar_x0 + bar_w, bar_y0 + bar_h],
        fill=(30, 10, 45, 165),  # translucent dark royal purple
    )

    y = bar_y0 + pad
    for line, lh in zip(lines, line_heights):
        draw.text((bar_x0 + pad, y), line, font=font, fill=(230, 220, 245, 255))
        y += lh + int(size * 0.3)

    stamped = Image.alpha_composite(img, overlay).convert("RGB")
    buf = io.BytesIO()
    stamped.save(buf, "JPEG", quality=92)
    return buf.getvalue()
