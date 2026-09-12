# Rebuilding the SIH idea-submission deck

The deck is generated, not hand-edited, so the numbers on it cannot drift away
from what the tool actually produces. Every figure on slides 3–6 comes from a
real scan and a real test run.

```bash
# 1. seed a store with a scan that exercises all eight source types
.venv/bin/python tools/deck/seed_demo_scan.py build/demo.db

# 2. screenshot the dashboard (needs playwright + chromium)
.venv/bin/python tools/deck/capture_screenshots.py build/demo.db build/shots

# 3. build the deck
.venv/bin/python tools/deck/build_deck.py build/shots tools/deck/sih-logo.png \
    SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx
```

`preview_deck.py` renders the result to PNGs and reports any text that overflows
its shape — useful on a machine with no PowerPoint:

```bash
.venv/bin/python tools/deck/preview_deck.py SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx build/preview
```

It is an approximate renderer, not a fidelity one: it draws shape geometry and
wraps text with real font metrics, which is enough to catch overflow, overlap
and anything running off the slide. Check the real file in PowerPoint before
submitting.

## Numbers that have to stay in sync

If the scanner changes, these appear on the slides and must be re-checked:

| Figure | Where it comes from |
|---|---|
| 262 tests | `pytest` |
| 100% precision / 97.5% recall | `cbom-compass eval` |
| 7 languages, 8 source types | `corpus/labels.yaml`, `engine.SCANNERS` |
| 191 assets, 209 raw findings | step 1 above, printed on stdout |

`build_deck.py` holds them as literals — grep the slide functions for the value
and update it there.
