# Rebuilding the SIH idea-submission deck

The deck is generated *inside the official SIH template*, not from a blank
presentation. `build_deck.py` opens the template file, keeps every piece of
template furniture on each slide, and replaces only the content shapes:

| Kept (template furniture) | Replaced (our content) |
|---|---|
| slide master and layouts | section headings and their rules |
| title placeholder, incl. its own paragraph structure | cards, tiles, pipeline stages |
| footer band, footer and slide-number placeholders | screenshots and captions |
| Team Nexus badge, SIH logo, title-slide artwork | diagrams |

Everything drawn is snapped to the template's own grid, measured from the
template rather than invented:

```
margin            0.30in, content width 12.73in
section heading   label at y, hairline rule at y + 0.28
6-column          x = 0.30 + n * 2.13, width 2.06   stat tiles, pipeline
4-column          x = 0.30 + n * 3.21, width 3.13   benefit cards
3-column          x = 0.30 + n * 4.28, width 4.13   reference cards
2-column          left 0.30 w 6.30 · right 6.75 w 6.28
footer band       y = 6.95, so content must end by 6.90
```

Type and colour come from the template too: Arial throughout, with the palette
the original slides already used.

## Regenerating

```bash
# 1. seed a store with a scan that exercises all eight source types
.venv/bin/python tools/deck/seed_demo_scan.py build/demo.db

# 2. screenshot the dashboard (needs playwright + chromium)
.venv/bin/python tools/deck/capture_screenshots.py build/demo.db build/raw

# 3. crop each shot to the template's picture slots
.venv/bin/python tools/deck/fit_screenshots.py build/raw build/shots

# 4. rebuild, from the template
.venv/bin/python tools/deck/build_deck.py \
    SIH2025-IDEA-CBOM-Compass-TeamNexus.pptx build/shots \
    SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx
```

Step 4 is idempotent: running it on its own output produces the same shape
count, so a rebuild never accumulates debris.

## Checking it without PowerPoint

```bash
.venv/bin/python tools/deck/preview_deck.py \
    SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx build/preview
```

An approximate renderer — it draws shape geometry and wraps text with real font
metrics. It will not match PowerPoint pixel for pixel, but it catches the things
that actually go wrong in a generated deck: text overflowing its shape, pictures
running under the footer band, and anything off-slide. It found a screenshot
running off slide 4, a chip running under a picture on slide 3, and a reference
silently truncated on slide 6. **Still open the real file in PowerPoint before
submitting.**

Render the template itself the same way to compare against the intended layout:

```bash
.venv/bin/python tools/deck/preview_deck.py \
    SIH2025-IDEA-CBOM-Compass-TeamNexus.pptx build/original
```

## Numbers that have to stay in sync

If the scanner changes, these appear on the slides and must be re-checked:

| Figure | Where it comes from |
|---|---|
| 262 tests | `pytest` |
| 100% precision / 97.5% recall | `cbom-compass eval` |
| 7 languages, 8 source types | `corpus/labels.yaml`, `engine.SCANNERS` |
| 191 assets, 209 raw findings, 125 graph nodes | step 1 above, printed on stdout |

They are literals in `build_deck.py` — grep for the value and update it there.
