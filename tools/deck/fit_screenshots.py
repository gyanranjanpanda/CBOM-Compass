"""Crop dashboard screenshots to the template's picture-slot aspect ratios."""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

SRC, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

# (slot ratio, where to take the band from) — the template's picture slots are
# 6.28 x 1.95in on slide 3 and 6.28 x 3.02in on slide 5.
SLOTS = {
    "graph.png": (6.28 / 1.95, 0.42),
    "inventory.png": (6.28 / 1.95, 0.18),
    "recs.png": (6.28 / 3.02, 0.10),
    "overview.png": (6.28 / 3.02, 0.00),
}


def trim_uniform_bottom(im, tol=10):
    """Drop the empty band the dashboard leaves below its content."""
    rgb = im.convert("RGB")
    w, h = rgb.size
    last = rgb.crop((0, h - 1, w, h)).resize((1, 1)).getpixel((0, 0))
    for y in range(h - 1, int(h * 0.5), -1):
        row = rgb.crop((0, y, w, y + 1)).resize((1, 1)).getpixel((0, 0))
        if sum(abs(a - b) for a, b in zip(row, last)) > tol:
            return im.crop((0, 0, w, min(h, y + 12)))
    return im


for name, (ratio, focus) in SLOTS.items():
    path = SRC / name
    if not path.exists():
        continue
    im = trim_uniform_bottom(Image.open(path))
    if im.width > 2200:
        im = im.resize((2200, round(im.height * 2200 / im.width)), Image.LANCZOS)
    want = min(round(im.width / ratio), im.height)
    top = round((im.height - want) * focus)
    im.crop((0, top, im.width, top + want)).save(OUT / name, optimize=True)
    print(f"{name}: -> {Image.open(OUT / name).size}")
