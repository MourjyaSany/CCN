"""Build the image assets for the Review-1 deck.

1. ``srm_logo.png``   - the official SRMIST logo, cut out of the reference deck's
                         slide-master background (``ref_master_bg.png``) with its
                         light-grey backdrop converted to transparency, then
                         upscaled 3x for a crisper placement.
2. ``background.png`` - a 1920x1080 white / light-grey background with soft
                         translucent diagonal bands and fine diagonal line bundles,
                         in the style of the SRMIST template. It deliberately has
                         no logo and no footer: both are editable shapes on the
                         slide master.

Run:  python make_assets.py   (needs Pillow + numpy)
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"


# --------------------------------------------------------------------------- #
# logo
# --------------------------------------------------------------------------- #
def extract_logo() -> Path:
    src = Image.open(ASSETS / "ref_master_bg.png").convert("RGB")
    arr = np.asarray(src).astype(float)
    # Search window: top-right corner, above the content area.
    x0, x1, y0, y1 = 930, 1300, 0, 140
    win = arr[y0:y1, x0:x1]
    sat = win.max(axis=2) - win.min(axis=2)
    dark = win.mean(axis=2)
    ink = (sat > 40) | (dark < 150)
    ys, xs = np.nonzero(ink)
    pad = 4
    bx0, bx1 = xs.min() - pad + x0, xs.max() + pad + 1 + x0
    by0, by1 = ys.min() - pad + y0, ys.max() + pad + 1 + y0
    crop = arr[by0:by1, bx0:bx1]
    h, w, _ = crop.shape

    # Backdrop estimate: interpolate each row between its left and right border.
    left = crop[:, :2].mean(axis=1)
    right = crop[:, -2:].mean(axis=1)
    t = np.linspace(0.0, 1.0, w)[None, :, None]
    bg = left[:, None, :] * (1 - t) + right[:, None, :] * t

    # GIMP-style colour-to-alpha against that backdrop.
    diff = crop - bg
    denom = np.where(diff < 0, bg, 255.0 - bg)
    denom = np.maximum(denom, 1.0)
    alpha = np.clip(np.abs(diff) / denom, 0.0, 1.0).max(axis=2)
    alpha = np.clip((alpha - 0.04) / 0.96, 0.0, 1.0)          # kill faint noise
    safe = np.maximum(alpha, 1e-3)[..., None]
    rgb = np.clip((crop - (1 - safe) * bg) / safe, 0, 255)
    rgba = np.dstack([rgb, alpha * 255]).astype(np.uint8)

    img = Image.fromarray(rgba, "RGBA")
    img = img.resize((w * 3, h * 3), Image.LANCZOS)
    out = ASSETS / "srm_logo.png"
    img.save(out)
    print(f"logo: crop {w}x{h} -> {img.size} saved to {out.name}")
    return out


# --------------------------------------------------------------------------- #
# background
# --------------------------------------------------------------------------- #
def make_background(width: int = 1920, height: int = 1080, ss: int = 2) -> Path:
    W, H = width * ss, height * ss
    base = Image.new("RGBA", (W, H), (255, 255, 255, 255))

    # A very soft vertical wash: white top-left -> faint grey on the right edge.
    xs = np.linspace(0.0, 1.0, W)
    wash = (255 - 14 * xs ** 2.2).astype(np.uint8)
    wash_img = Image.fromarray(np.tile(wash, (H, 1)), "L").convert("RGBA")
    base = Image.blend(base, wash_img, 1.0)

    def band(points, grey, alpha):
        layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ImageDraw.Draw(layer).polygon(
            [(int(x * W), int(y * H)) for x, y in points], fill=(grey, grey, grey, alpha))
        return layer

    # Translucent diagonal bands sweeping from the top edge to the right edge.
    shapes = [
        ([(0.22, 0.0), (0.52, 0.0), (1.0, 0.62), (1.0, 0.98)], 214, 46),
        ([(0.40, 0.0), (0.66, 0.0), (1.0, 0.40), (1.0, 0.70)], 205, 40),
        ([(0.70, 0.0), (1.0, 0.0), (1.0, 0.32)], 200, 54),
        ([(0.08, 0.0), (0.20, 0.0), (0.58, 1.0), (0.40, 1.0)], 232, 34),
        ([(0.80, 0.55), (1.0, 0.42), (1.0, 1.0), (0.86, 1.0)], 210, 36),
    ]
    for pts, grey, a in shapes:
        base = Image.alpha_composite(base, band(pts, grey, a))

    # Fine diagonal line bundles (the hallmark of the SRMIST template).
    lines = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(lines)
    slope = 0.72  # dy/dx in normalised units
    for i in range(16):
        off = 0.30 + i * 0.0105
        d.line([(int(off * W), 0), (W, int((1 - off) / slope * H * 0.56))],
               fill=(255, 255, 255, 150), width=2 * ss // 2 + 1)
    for i in range(10):
        off = 0.62 + i * 0.012
        d.line([(int(off * W), int(0.46 * H)), (W, int((0.46 + (1 - off) * 0.95) * H))],
               fill=(190, 190, 190, 70), width=ss)
    base = Image.alpha_composite(base, lines.filter(ImageFilter.GaussianBlur(0.6 * ss)))

    out = ASSETS / "background.png"
    base.convert("RGB").resize((width, height), Image.LANCZOS).save(out, optimize=True)
    print(f"background: {width}x{height} saved to {out.name}")
    return out


if __name__ == "__main__":
    ASSETS.mkdir(exist_ok=True)
    extract_logo()
    make_background()
