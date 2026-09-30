#!/usr/bin/env python3
"""Draw the add-on icons (a shield with a keyhole) into ``extension/icons``.

Run with any Python that has Pillow: ``python3 tools/make_icons.py``. The shield is drawn at 4x
and downsampled with premultiplied alpha so the edges stay clean at 16 px.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parents[1]
ICONS = REPO_ROOT / "extension" / "icons"
SIZES = (16, 32, 48, 96, 128)

BACKGROUND = (17, 24, 39, 255)      # slate-900
SHIELD = (226, 232, 240, 255)       # slate-200
KEYHOLE = (29, 78, 216, 255)        # blue-700


def draw(size: int) -> Image.Image:
    """Render one icon at ``size`` pixels."""
    scale = 4
    canvas = size * scale
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw_ctx = ImageDraw.Draw(image)

    radius = canvas * 0.22
    draw_ctx.rounded_rectangle([0, 0, canvas - 1, canvas - 1], radius=radius, fill=BACKGROUND)

    # Shield outline: a rounded top and a pointed bottom.
    margin = canvas * 0.18
    top = margin
    left = margin
    right = canvas - margin
    bottom = canvas - margin
    middle = canvas * 0.52
    shield = [
        (left, top + (middle - top) * 0.18),
        (canvas / 2, top),
        (right, top + (middle - top) * 0.18),
        (right, middle),
        (canvas / 2, bottom),
        (left, middle),
    ]
    draw_ctx.polygon(shield, fill=SHIELD)

    # Keyhole.
    hole_radius = canvas * 0.075
    centre = (canvas / 2, canvas * 0.44)
    draw_ctx.ellipse(
        [
            centre[0] - hole_radius,
            centre[1] - hole_radius,
            centre[0] + hole_radius,
            centre[1] + hole_radius,
        ],
        fill=KEYHOLE,
    )
    stem_half = canvas * 0.028
    draw_ctx.polygon(
        [
            (centre[0] - stem_half, centre[1]),
            (centre[0] + stem_half, centre[1]),
            (centre[0] + stem_half * 1.9, canvas * 0.66),
            (centre[0] - stem_half * 1.9, canvas * 0.66),
        ],
        fill=KEYHOLE,
    )

    return image.resize((size, size), Image.LANCZOS)


def main() -> int:
    """Write every icon size and report what was produced."""
    ICONS.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        target = ICONS / f"icon-{size}.png"
        draw(size).save(target, "PNG", optimize=True)
        print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
