"""Draw the application icon at every size Windows asks for.

    python tools/draw-icon.py          (needs Pillow: python -m pip install pillow)

Each size is drawn at its own scale rather than being shrunk from one large image. A mark
shrunk to sixteen pixels loses its edges to resampling and arrives as a smudge; drawn at
sixteen, the stroke is a whole number of pixels and the edges land on pixel boundaries.

That is also why the plate's inset and the stroke's weight change with the size. At 256 the
letter can be light and the margin wide; at 16 the same proportions leave a stroke a pixel and
a half across, which no amount of care will make crisp. The small sizes are drawn heavier.

The colours are the application's own: the accent it draws its buttons with, on the surface it
draws its windows with, so the icon looks like the thing it opens.
"""

from __future__ import annotations

import os
import struct
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = os.path.join(HERE, "..", "apps", "gkrm-desktop", "src-tauri", "icons")

PLATE = (17, 24, 22, 255)        # --surface
GREEN = (37, 192, 109, 255)      # --accent

# Supersample, then average down by exactly this factor. An integer factor with the geometry
# snapped to whole device pixels means box-averaging is the exact coverage of each pixel, with
# none of the overshoot a sharpening filter would add around the edges.
SS = 16

ICO_SIZES = [16, 20, 24, 32, 40, 48, 60, 64, 96, 128, 256]
PNG_SIZES = [32, 128, 256, 512]


def weights(size: int) -> tuple[int, int, int]:
    """Margin, ring stroke and crossbar thickness, in whole device pixels.

    The crossbar is thinner than the ring on purpose. Drawn at the ring's weight it fills the
    counter at the small sizes -- at sixteen pixels the ring leaves six pixels of counter, and a
    six-pixel bar closes it completely, which is how a G becomes a blob. Thinner leaves a gap
    above and below the bar at every size, and that gap is the whole difference between reading
    the letter and reading a smudge.
    """
    # The margin widens once there is room for it. Below 48 pixels every pixel spent on the
    # margin is one the letter does not have, so the mark is pushed out to the plate; above it,
    # the crowding is the only thing left to notice, so the mark is let back in.
    inset = 0.125 if size <= 48 else 0.16
    return round(size * inset), round(size * 0.18), round(size * 0.135)


def draw(size: int) -> Image.Image:
    margin, ring, crossbar = weights(size)
    # Whole device pixels, so every edge falls on a pixel boundary once this is averaged down.
    m, w, bar = margin * SS, ring * SS, crossbar * SS
    radius = 0.22
    s = size * SS

    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(im).rounded_rectangle([0, 0, s - 1, s - 1], radius=s * radius, fill=PLATE)

    mark = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(mark)
    outer = (s - 2 * m) * 0.30
    d.rounded_rectangle([m, m, s - m, s - m], radius=outer, fill=GREEN)
    d.rounded_rectangle([m + w, m + w, s - m - w, s - m - w],
                        radius=max(outer - w, 1), fill=(0, 0, 0, 0))
    mid = s / 2
    # The opening, out of the upper right, and the crossbar that comes in from the right edge.
    # Both are cut at the bar's edges, so the gap left above the bar is exactly the gap the
    # counter has below it.
    d.rectangle([mid, m - 1, s - m + 1, mid - bar * 0.5], fill=(0, 0, 0, 0))
    d.rectangle([mid, mid - bar * 0.5, s - m, mid + bar * 0.5], fill=GREEN)

    im.alpha_composite(mark)
    return im.resize((size, size), Image.BOX)


def png_bytes(image: Image.Image) -> bytes:
    from io import BytesIO
    buf = BytesIO()
    image.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def write_ico(path: str, images: dict[int, Image.Image]) -> None:
    """ICO with a PNG payload per size, which is how the sizes stay independently drawn."""
    sizes = sorted(images)
    payloads = [png_bytes(images[s]) for s in sizes]
    offset = 6 + 16 * len(sizes)
    out = [struct.pack("<HHH", 0, 1, len(sizes))]
    for size, data in zip(sizes, payloads):
        out.append(struct.pack(
            "<BBBBHHII",
            0 if size >= 256 else size, 0 if size >= 256 else size,
            0, 0, 1, 32, len(data), offset))
        offset += len(data)
    out.extend(payloads)
    with open(path, "wb") as handle:
        handle.write(b"".join(out))


def main() -> None:
    drawn = {size: draw(size) for size in sorted(set(ICO_SIZES) | set(PNG_SIZES))}
    for size in PNG_SIZES:
        name = os.path.join(ICONS, f"{size}x{size}.png")
        drawn[size].save(name, format="PNG", optimize=True)
        print("yazildi", os.path.relpath(name, os.path.join(HERE, "..")))
    ico = os.path.join(ICONS, "icon.ico")
    write_ico(ico, {size: drawn[size] for size in ICO_SIZES})
    print("yazildi", os.path.relpath(ico, os.path.join(HERE, "..")),
          "(%s)" % ", ".join(str(s) for s in ICO_SIZES))


if __name__ == "__main__":
    main()
