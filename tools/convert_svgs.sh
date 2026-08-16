#!/usr/bin/env bash
set -euo pipefail

# Convert SVGs in assets/ to PNG using either rsvg-convert or ImageMagick's convert.
# Usage: bash tools/convert_svgs.sh

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."
ASSETS="$ROOT/assets"

if [ ! -d "$ASSETS" ]; then
  echo "assets/ directory not found. Run from repository root." >&2
  exit 1
fi

OUT_DIR="$ASSETS"

if command -v rsvg-convert >/dev/null 2>&1; then
  CONV="rsvg-convert"
  CONV_TYPE="rsvg-convert"
elif command -v convert >/dev/null 2>&1; then
  CONV="convert"
  CONV_TYPE="imagemagick"
else
  echo "Install 'librsvg2-bin' (rsvg-convert) or 'imagemagick' to generate PNGs." >&2
  exit 2
fi

echo "Using converter: $CONV_TYPE"

for svg in "$ASSETS"/*.svg; do
  [ -e "$svg" ] || continue
  base=$(basename "$svg" .svg)
  out="$OUT_DIR/${base}.png"
  echo "Generating $out"
  if [ "$CONV_TYPE" = "rsvg-convert" ]; then
    rsvg-convert -w 800 -h 240 "$svg" -o "$out"
  else
    convert -background none -resize 800x240 "$svg" "$out"
  fi
done

echo "PNG export completed. Files written to $OUT_DIR"
