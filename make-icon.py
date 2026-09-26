#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Builds the launcher icons: Briar's own mark in MeeGo's icon shape.

The silhouette is not approximated. Every Harmattan launcher icon is cut to
the same rounded square, and the shape here is the alpha channel of a stock
icon (../meego-icon-tool/mask-icon-l.png, an unchanged
/usr/share/themes/blanco/meegotouch/icons/icon-l-*.png). The same mask is used
for the Sailfish sizes, because the user wants both platforms to carry the
MeeGo silhouette.

The mark comes from Briar's own artwork (briar-android/artwork/logo_no_text.svg,
rasterised at 640 px with rsvg-convert and kept here as
icons/logo_no_text_640.png), on the white ground Briar's Android launcher icon
uses. Everything is drawn at 4x and only scaled down at the end, otherwise the
squircle's curve frays and the mark's thorns alias.
"""
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
MASK = os.path.join(HERE, "..", "meego-icon-tool", "mask-icon-l.png")
MARK = os.path.join(HERE, "icons", "logo_no_text_640.png")
OUT = os.path.join(HERE, "icons")

S = 344                          # working size: 4x the largest output (86)
BIG = 1024                       # 4x the largest Sailfish output (256)
TOP = (255, 255, 255)            # Briar's launcher ground is white ...
BOTTOM = (226, 230, 216)         # ... shaded towards its green, so the icon
                                 # does not look like a bare white tile
SIZES = [80, 64, 86, 108, 128, 172, 256]


def squircle(size):
    """MeeGo's icon silhouette, straight out of a stock icon's alpha."""
    stock = Image.open(MASK).convert("RGBA")
    return stock.split()[3].resize((size, size), Image.LANCZOS)


def ground(size):
    """A vertical gradient; flat white looks dead between the stock icons."""
    image = Image.new("RGB", (size, size))
    pixels = image.load()
    for y in range(size):
        t = y / float(size - 1)
        colour = tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3))
        for x in range(size):
            pixels[x, y] = colour
    return image


def gloss(image):
    """The highlight across the top third that the blanco icons carry."""
    size = image.size[0]
    layer = Image.new("L", (size, size), 0)
    pixels = layer.load()
    height = int(size * 0.46)
    for y in range(height):
        value = int(38 * (1.0 - y / float(height)) ** 1.6)
        for x in range(size):
            pixels[x, y] = value
    return Image.composite(Image.new("RGB", (size, size), (255, 255, 255)),
                           image, layer)


def mark(size, fraction=0.66):
    """Briar's mark, cropped to its own ink and scaled into the squircle."""
    source = Image.open(MARK).convert("RGBA")
    box = source.split()[3].getbbox()
    if box:
        source = source.crop(box)
    target = int(size * fraction)
    scale = target / float(max(source.size))
    new = (max(1, int(round(source.size[0] * scale))),
           max(1, int(round(source.size[1] * scale))))
    return source.resize(new, Image.LANCZOS)


def build(size):
    icon = gloss(ground(size)).convert("RGBA")
    glyph = mark(size)
    icon.paste(glyph, ((size - glyph.size[0]) // 2, (size - glyph.size[1]) // 2),
               glyph)
    icon.putalpha(squircle(size))
    return icon


def main():
    if not os.path.exists(MASK):
        sys.exit("the stock icon mask is missing: %s" % MASK)
    if not os.path.exists(MARK):
        sys.exit("Briar's mark is missing: %s\n"
                 "rsvg-convert -w 640 -h 640 logo_no_text.svg -o %s" % (MARK, MARK))
    big = build(BIG)
    for size in SIZES:
        # Draw once, large, and scale down -- the curve survives that, a
        # redraw at 64 px does not.
        icon = big.resize((size, size), Image.LANCZOS)
        path = os.path.join(OUT, "icon-%d.png" % size)
        icon.save(path)
        print("wrote %s" % path)


if __name__ == "__main__":
    main()
