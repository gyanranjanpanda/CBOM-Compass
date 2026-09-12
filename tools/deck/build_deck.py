"""Rebuild the SIH idea-submission deck *inside* the official SIH template.

The deck is not generated from a blank presentation. It opens the SIH template
file, keeps every piece of template furniture on each slide — the title
placeholder, the footer band, the slide-number and footer placeholders, the
Team Nexus badge, the SIH logo and the title-slide artwork — and replaces only
the content shapes.

Everything it draws is snapped to the template's own grid, measured from the
template itself rather than invented:

    margin            0.30in, content width 12.73in
    section heading   label at y, hairline rule at y + 0.28
    6-column          x = 0.30 + n * 2.13, width 2.06   (stat tiles, pipeline)
    4-column          x = 0.30 + n * 3.21, width 3.13   (benefit cards)
    3-column          x = 0.30 + n * 4.28, width 4.13   (reference cards)
    2-column          left 0.30 w 6.30 · right 6.75 w 6.28
    footer band       y = 6.95, so content must end by 6.90

Type and colour also come from the template: Arial throughout, with the palette
the original slides already used.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

TEMPLATE = Path(sys.argv[1] if len(sys.argv) > 1
                else "SIH2025-IDEA-CBOM-Compass-TeamNexus.pptx")
SHOTS = Path(sys.argv[2] if len(sys.argv) > 2 else "build/shots")
OUT = Path(sys.argv[3] if len(sys.argv) > 3
           else "SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx")

# ------------------------------------------------------------------ palette
INK = RGBColor(0x1F, 0x29, 0x33)
MUTED = RGBColor(0x5A, 0x6B, 0x7C)
NAVY = RGBColor(0x1F, 0x49, 0x7D)
TEAL = RGBColor(0x0E, 0x8C, 0x86)
BLUE = RGBColor(0x00, 0x70, 0xC0)
RED = RGBColor(0x8C, 0x2A, 0x1E)
GREEN = RGBColor(0x1A, 0x5C, 0x36)
AMBER = RGBColor(0x6B, 0x4A, 0x08)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
PANEL = RGBColor(0xF3, 0xF8, 0xFC)
BORDER = RGBColor(0xCB, 0xDD, 0xEC)
TEAL_L = RGBColor(0xE6, 0xF4, 0xF3)
BLUE_L = RGBColor(0xE7, 0xF1, 0xFA)
RED_L = RGBColor(0xFB, 0xED, 0xEA)
AMBER_L = RGBColor(0xFF, 0xF6, 0xE5)
GREEN_L = RGBColor(0xE9, 0xF4, 0xEC)
FONT = "Arial"

# -------------------------------------------------------------------- grid
M = 0.30                      # left margin
CW = 12.73                    # content width
COL6 = [round(M + n * 2.13, 3) for n in range(6)]
COL4 = [round(M + n * 3.21, 3) for n in range(4)]
COL3 = [round(M + n * 4.28, 3) for n in range(3)]
W6, W4, W3 = 2.06, 3.13, 4.13
LEFT_X, LEFT_W = 0.30, 6.30
RIGHT_X, RIGHT_W = 6.75, 6.28
FOOTER_Y = 6.95


# ----------------------------------------------------------------- helpers
def keep_furniture(slide, extra_keep=()):
    """Delete content shapes; keep everything the template owns.

    The team badge is matched on its text rather than on "Oval", because the
    padlock drawing also produces ovals — a name-prefix rule would spare them on
    a second pass and quietly accumulate debris.
    """
    for sh in list(slide.shapes):
        name = sh.name
        label = sh.text_frame.text.strip() if sh.has_text_frame else ""
        keep = (
            sh.is_placeholder
            or name in extra_keep
            or name.startswith("Picture 2")
            or label == "Team Nexus"
            # the footer band: a full-width bar sitting on the footer line
            or (Emu(sh.width).inches > 13 and Emu(sh.top).inches >= 6.9)
        )
        if not keep:
            sh._element.getparent().remove(sh._element)


def box(slide, x, y, w, h, fill=None, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
        radius=0.10, lw=0.75):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    try:
        s.adjustments[0] = radius
    except (IndexError, ValueError):
        pass
    if fill is None:
        s.fill.background()
    else:
        s.fill.solid()
        s.fill.fore_color.rgb = fill
    if line is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = line
        s.line.width = Pt(lw)
    s.shadow.inherit = False
    s.text_frame.word_wrap = True
    return s


def text_into(shape, blocks, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.MIDDLE, pad=0.10):
    tf = shape.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(pad)
    tf.margin_top = tf.margin_bottom = Inches(0.03)
    _runs(tf, blocks, align)
    return shape


def tb(slide, x, y, w, h, blocks, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    s = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = s.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    _runs(tf, blocks, align)
    return s


def _runs(tf, blocks, align):
    for i, blk in enumerate(blocks):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        if blk.get("sp") is not None:
            p.space_after = Pt(blk["sp"])
        if blk.get("ls"):
            p.line_spacing = blk["ls"]
        r = p.add_run()
        r.text = blk["t"]
        f = r.font
        f.name = FONT
        f.size = Pt(blk.get("sz", 8.2))
        f.bold = blk.get("b", False)
        f.color.rgb = blk.get("c", INK)


def bar(slide, x, y, w, h, color):
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y),
                               Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s


def section(slide, y, label, x=M, w=CW):
    """The template's section heading: label, then a hairline rule."""
    tb(slide, x, y, w, 0.29, [{"t": label, "sz": 11, "c": NAVY, "b": True}])
    bar(slide, x, y + 0.28, w, 0.02, TEAL)


def card(slide, x, y, w, h, accent, fill=PANEL):
    """The template's card: rounded panel with a coloured left edge."""
    c = box(slide, x, y, w, h, fill=fill, line=BORDER, radius=0.06)
    bar(slide, x, y, 0.05, h, accent)
    return c


def tile(slide, x, y, w, h, accent, fill=WHITE):
    """The template's stat tile: rounded panel with a coloured top edge."""
    t = box(slide, x, y, w, h, fill=fill, line=BORDER, radius=0.08)
    bar(slide, x, y, w, 0.04, accent)
    return t


def shot(slide, name, x, y, w):
    pic = slide.shapes.add_picture(str(SHOTS / name), Inches(x), Inches(y),
                                   width=Inches(w))
    frame = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y),
                                   Inches(w), Emu(pic.height))
    frame.fill.background()
    frame.line.color.rgb = BORDER
    frame.line.width = Pt(0.75)
    frame.shadow.inherit = False
    return y + Emu(pic.height).inches


def caption(slide, x, y, w, t):
    """Centred under the picture, which is how the template does it."""
    tb(slide, x, y, w, 0.24, [{"t": t, "sz": 7.5, "c": MUTED, "ls": 0.95}],
       align=PP_ALIGN.CENTER)


def padlock(slide, cx, top, scale, color, bg, broken=False):
    """A padlock from primitives: a ring masked to a shackle, plus a body."""
    d = 0.46 * scale
    bw, bh = 0.62 * scale, 0.46 * scale
    ring = slide.shapes.add_shape(MSO_SHAPE.DONUT, Inches(cx - d / 2), Inches(top),
                                  Inches(d), Inches(d))
    ring.adjustments[0] = 0.20
    ring.fill.solid()
    ring.fill.fore_color.rgb = color
    ring.line.fill.background()
    ring.shadow.inherit = False
    mask = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(cx - d / 2 - 0.02),
                                  Inches(top + d * 0.52), Inches(d + 0.04),
                                  Inches(d * 0.56))
    mask.fill.solid()
    mask.fill.fore_color.rgb = bg
    mask.line.fill.background()
    mask.shadow.inherit = False

    body_top = top + d * 0.62
    body = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                  Inches(cx - bw / 2), Inches(body_top),
                                  Inches(bw), Inches(bh))
    body.adjustments[0] = 0.18
    body.fill.solid()
    body.fill.fore_color.rgb = color
    body.line.fill.background()
    body.shadow.inherit = False

    if broken:
        cut = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(cx - d * 0.64),
                                     Inches(top + d * 0.14), Inches(d * 1.3),
                                     Inches(0.055))
        cut.fill.solid()
        cut.fill.fore_color.rgb = bg
        cut.line.fill.background()
        cut.shadow.inherit = False
        cut.rotation = -32
    else:
        kh = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(cx - 0.05 * scale),
                                    Inches(body_top + bh * 0.3),
                                    Inches(0.10 * scale), Inches(0.10 * scale))
        kh.fill.solid()
        kh.fill.fore_color.rgb = bg
        kh.line.fill.background()
        kh.shadow.inherit = False


def set_title(slide, text):
    """Retitle without disturbing the placeholder's own structure.

    The template's title paragraph is an empty run, a line break, then the
    title. Writing into run 0 puts the text *above* the break, which slides the
    title up into the Team Nexus badge — so only the run that already carries
    text is replaced.
    """
    for sh in slide.shapes:
        if not (sh.is_placeholder and sh.placeholder_format.idx == 0):
            continue
        for para in sh.text_frame.paragraphs:
            for run in para.runs:
                if run.text.strip():
                    run.text = text
                    return
        return


# =========================================================== SLIDE 1 : title
def slide1(slide):
    # Keep the template's title-slide artwork; replace only the copy blocks,
    # at the positions the template already used.
    keep_furniture(slide, extra_keep=("Rectangle 24", "Freeform: Shape 26",
                                      "Picture 4"))

    # Starts at 2.30, where the template's own metadata block started: any
    # higher and it runs into the "TITLE PAGE" subtitle placeholder above.
    tb(slide, 0.36, 2.30, 6.10, 2.86, [
        {"t": "Problem Statement ID – ", "sz": 10, "c": MUTED, "sp": 0},
        {"t": "SIH25164", "sz": 12, "c": INK, "b": True, "sp": 6},
        {"t": "Problem Statement Title – ", "sz": 10, "c": MUTED, "sp": 0},
        {"t": "Development of a tool for the identification and assessment of "
              "cryptographic assets and their post-quantum migration readiness",
         "sz": 10, "c": INK, "b": True, "sp": 6, "ls": 1.02},
        {"t": "Theme – ", "sz": 10, "c": MUTED, "sp": 0},
        {"t": "Cybersecurity", "sz": 10, "c": INK, "b": True, "sp": 6},
        {"t": "PS Category – ", "sz": 10, "c": MUTED, "sp": 0},
        {"t": "Software", "sz": 10, "c": INK, "b": True, "sp": 6},
        {"t": "Team ID – ", "sz": 10, "c": MUTED, "sp": 0},
        {"t": "<TEAM ID>", "sz": 10, "c": INK, "b": True, "sp": 6},
        {"t": "Team Name (Registered on portal) – ", "sz": 10, "c": MUTED,
         "sp": 0},
        {"t": "Team Nexus", "sz": 10, "c": INK, "b": True},
    ])

    bar(slide, 0.36, 5.32, 1.30, 0.04, TEAL)
    tb(slide, 0.36, 5.45, 6.10, 0.80, [
        {"t": "CBOM Compass — an X-ray for your organisation’s encryption.",
         "sz": 12.5, "c": NAVY, "b": True, "sp": 4, "ls": 1.0},
        {"t": "Find every lock in the building, work out which ones a quantum "
              "computer can pick and which ones the regulator bans first — then "
              "hand back a prioritised locksmith’s list.",
         "sz": 10.5, "c": MUTED, "ls": 1.04},
    ])

    for i, (value, label) in enumerate([("8", "sources scanned"),
                                        ("191", "assets, demo scan"),
                                        ("262", "tests green")]):
        x = 0.36 + i * 2.05
        t = tile(slide, x, 6.34, 1.90, 0.56, TEAL)
        text_into(t, [
            {"t": value, "sz": 15, "c": NAVY, "b": True, "sp": 0, "ls": 0.85},
            {"t": label, "sz": 7.5, "c": MUTED, "ls": 0.9},
        ], align=PP_ALIGN.CENTER, pad=0.04)


# ============================================================ SLIDE 2 : idea
def slide2(slide):
    keep_furniture(slide)
    set_title(slide, "IDEA TITLE")

    banner = box(slide, M, 1.32, CW, 0.52, fill=TEAL_L, line=TEAL, radius=0.14)
    tb(slide, 0.50, 1.44, 8.30, 0.30,
       [{"t": "CBOM COMPASS — an X-ray for your organisation’s encryption",
         "sz": 12.5, "c": NAVY, "b": True}])
    tb(slide, 8.90, 1.46, 4.05, 0.28,
       [{"t": "SIH25164  ·  Cybersecurity  ·  working prototype", "sz": 9.2,
         "c": TEAL, "b": True}], align=PP_ALIGN.RIGHT)

    section(slide, 1.96, "Proposed Solution (Describe your Idea/Solution/Prototype)")

    # --- the problem, as three panels on the 3-column grid -----------------
    tb(slide, M, 2.32, CW, 0.24,
       [{"t": "THE PROBLEM, IN ONE PICTURE  —  “harvest now, decrypt later”",
         "sz": 9.2, "c": MUTED, "b": True}])
    panels = [
        (TEAL, TEAL_L, "1  ·  TODAY",
         "Your data is locked with today’s encryption.", False),
        (AMBER, AMBER_L, "2  ·  TODAY",
         "An attacker copies the locked file. They cannot open it — yet.", None),
        (RED, RED_L, "3  ·  ~2031",
         "A quantum computer opens it. Everything recorded since today is exposed.",
         True),
    ]
    for i, (accent, light, head, body, broken) in enumerate(panels):
        x = COL3[i]
        box(slide, x, 2.60, W3, 1.14, fill=light, line=accent, radius=0.06)
        tb(slide, x + 0.16, 2.70, 2.20, 0.20,
           [{"t": head, "sz": 8.6, "c": accent, "b": True}])
        tb(slide, x + 0.16, 2.94, 2.86, 0.72,
           [{"t": body, "sz": 9.2, "c": INK, "ls": 1.04}])
        if broken is None:
            box(slide, x + 3.30, 2.86, 0.40, 0.50, fill=light, line=accent,
                radius=0.10)
            box(slide, x + 3.20, 2.96, 0.40, 0.50, fill=light, line=accent,
                radius=0.10)
        else:
            padlock(slide, x + 3.48, 2.80, 1.0, accent, light, broken=broken)
        if i < 2:
            a = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                       Inches(x + W3 + 0.02), Inches(3.08),
                                       Inches(0.11), Inches(0.18))
            a.fill.solid()
            a.fill.fore_color.rgb = MUTED
            a.line.fill.background()
            a.shadow.inherit = False

    # --- left: Mosca drawn.  right: what the tool does ---------------------
    tb(slide, LEFT_X, 3.86, LEFT_W, 0.24,
       [{"t": "HOW WE DECIDE WHAT MOVES FIRST  —  Mosca’s inequality, drawn",
         "sz": 9.2, "c": MUTED, "b": True}])
    box(slide, LEFT_X, 4.12, LEFT_W, 1.22, fill=PANEL, line=BORDER, radius=0.06)

    x0, span, years = 0.52, 5.86, 15.0
    per = span / years
    xb = box(slide, x0, 4.26, per * 10, 0.26, fill=TEAL, line=None, radius=0.16)
    text_into(xb, [{"t": "X · data must stay secret · 10 yrs", "sz": 7.8,
                    "c": WHITE, "b": True}], align=PP_ALIGN.CENTER, pad=0.04)
    yb = box(slide, x0 + per * 10, 4.26, per * 5, 0.26, fill=BLUE, line=None,
             radius=0.16)
    text_into(yb, [{"t": "Y · migrate · 5", "sz": 7.8, "c": WHITE, "b": True}],
              align=PP_ALIGN.CENTER, pad=0.03)

    zx = x0 + per * 5
    bar(slide, zx, 4.16, 0.022, 0.50, RED)
    tb(slide, zx - 0.55, 4.68, 1.10, 0.20,
       [{"t": "Q-Day 2031", "sz": 7.8, "c": RED, "b": True}], align=PP_ALIGN.CENTER)
    bar(slide, x0, 4.62, span, 0.01, BORDER)
    # End labels are aligned to the axis ends rather than centred on the tick,
    # so the first does not hang past the panel's left edge and break the grid.
    ticks = (2026, 2031, 2036, 2041)
    for n, year in enumerate(ticks):
        tick_x = x0 + per * (year - 2026)
        if n == 0:
            bx, align = tick_x, PP_ALIGN.LEFT
        elif n == len(ticks) - 1:
            bx, align = tick_x - 0.56, PP_ALIGN.RIGHT
        else:
            bx, align = tick_x - 0.28, PP_ALIGN.CENTER
        tb(slide, bx, 4.90, 0.56, 0.18,
           [{"t": str(year), "sz": 7.5, "c": MUTED}], align=align)

    verdict = box(slide, x0, 5.08, span, 0.22, fill=RED_L, line=RED, radius=0.3)
    text_into(verdict, [{"t": "X + Y = 15 yrs   >   Z = 5 yrs      →   already "
                              "overdue", "sz": 8.2, "c": RED, "b": True}],
              align=PP_ALIGN.CENTER, pad=0.05)

    tb(slide, RIGHT_X, 3.86, RIGHT_W, 0.24,
       [{"t": "WHAT THE TOOL ACTUALLY DOES", "sz": 9.2, "c": MUTED, "b": True}])
    steps = [("1  SEE", "every place\nencryption hides", TEAL),
             ("2  JUDGE", "broken, weak,\nor genuinely fine", BLUE),
             ("3  RANK", "what breaks\nyou first", AMBER),
             ("4  FIX", "the exact NIST\nreplacement", GREEN)]
    sw = (RIGHT_W - 3 * 0.08) / 4
    for i, (head, body, accent) in enumerate(steps):
        x = RIGHT_X + i * (sw + 0.08)
        box(slide, x, 4.12, sw, 0.86, fill=PANEL, line=BORDER, radius=0.08)
        bar(slide, x, 4.12, sw, 0.20, accent)
        tb(slide, x, 4.145, sw, 0.18, [{"t": head, "sz": 8.2, "c": WHITE,
                                        "b": True}], align=PP_ALIGN.CENTER)
        tb(slide, x + 0.04, 4.40, sw - 0.08, 0.54,
           [{"t": body, "sz": 7.8, "c": MUTED, "ls": 0.95}], align=PP_ALIGN.CENTER)
    tb(slide, RIGHT_X, 5.06, RIGHT_W, 0.26,
       [{"t": "One command, or one drag-and-drop. Nothing scanned ever leaves "
              "the machine.", "sz": 9.2, "c": INK, "b": True, "ls": 1.0}])

    # --- the three mandated sub-headings, one line each --------------------
    cols = [
        ("Detailed explanation of the proposed solution",
         "Eight sources — code, config, dependencies, binaries, containers, TLS, "
         "SSH, cloud & HSM — merged into one de-duplicated inventory.", TEAL),
        ("How it addresses the problem",
         "You cannot migrate what you cannot see. “We think we use RSA somewhere” "
         "becomes 191 named assets, each with an exact location.", BLUE),
        ("Innovation and uniqueness of the solution",
         "Mosca made continuous, not yes/no. We refuse to cry wolf — AES-256 stays "
         "green. Every finding is re-proved from disk.", GREEN),
    ]
    for i, (head, body, accent) in enumerate(cols):
        x = COL3[i]
        card(slide, x, 5.54, W3, 1.26, accent)
        tb(slide, x + 0.18, 5.64, W3 - 0.30, 0.22,
           [{"t": head, "sz": 9.2, "c": accent, "b": True}])
        tb(slide, x + 0.18, 5.90, W3 - 0.32, 0.82,
           [{"t": body, "sz": 8.6, "c": MUTED, "ls": 1.06}])


# ======================================================= SLIDE 3 : technical
def slide3(slide):
    keep_furniture(slide)
    set_title(slide, "TECHNICAL APPROACH")

    section(slide, 1.16,
            "Technologies to be used (e.g. programming languages, frameworks, "
            "hardware)")

    sources = [("CODE", "Python AST\n+ 6 languages", TEAL),
               ("CONFIG", "SSH · IPsec\nnginx · VPN", TEAL),
               ("DEPS", "manifests +\nlibrary KB", BLUE),
               ("BINARIES", "ELF · PE\nMach-O", BLUE),
               ("CONTAINERS", "layers +\nbaked-in keys", NAVY),
               ("TLS", "live\nhandshake", AMBER),
               ("SSH", "live offered\nalgorithms", AMBER),
               ("CLOUD & HSM", "AWS · Azure · GCP\nPKCS#11", RED)]
    tw = (CW - 7 * 0.07) / 8
    for i, (head, body, accent) in enumerate(sources):
        x = M + i * (tw + 0.07)
        t = tile(slide, x, 1.50, tw, 0.70, accent)
        text_into(t, [
            {"t": head, "sz": 8.2, "c": accent, "b": True, "sp": 2, "ls": 0.9},
            {"t": body, "sz": 7.5, "c": MUTED, "ls": 0.92},
        ], align=PP_ALIGN.CENTER, pad=0.03)

    rows = [("Core", "Python 3.11  ·  FastAPI  ·  Uvicorn  ·  SQLite documents → "
                     "Postgres + JSONB by connection string", TEAL),
            ("Output & QA", "CycloneDX 1.7 / ECMA-424 2nd Ed.  ·  ReportLab board "
                            "PDF  ·  zero-build HTML dashboard  ·  pytest ×262  ·  "
                            "Playwright UI tests", GREEN)]
    for i, (label, value, accent) in enumerate(rows):
        y = 2.26 + i * 0.42
        lp = box(slide, M, y, 1.62, 0.38, fill=accent, line=None, radius=0.14)
        text_into(lp, [{"t": label, "sz": 8.2, "c": WHITE, "b": True}],
                  align=PP_ALIGN.CENTER, pad=0.04)
        vp = box(slide, 2.00, y, 11.03, 0.38, fill=PANEL, line=BORDER, radius=0.14)
        text_into(vp, [{"t": value, "sz": 8.2, "c": INK}], pad=0.14)

    tb(slide, M, 3.08, CW, 0.22,
       [{"t": "Hardware: none. Runs offline on a laptop — no GPU, no cluster, no "
              "agent, no external service; a full 191-asset scan takes about a "
              "second.", "sz": 8.2, "c": MUTED}])

    section(slide, 3.34, "Methodology and process for implementation "
                         "(Flow Charts/Images/ working prototype)")

    stages = [("1  INGEST", "zip upload or repo URL — traversal, zip-bomb, "
                            "symlink and SSRF gated at the edge", TEAL),
              ("2  SCAN", "eight scanners run independently; one failure "
                          "degrades that source, never the run", TEAL),
              ("3  MERGE", "cross-source identity merge — 209 raw findings "
                           "become 191 real assets", BLUE),
              ("4  ASSESS", "Shor-broken / classically broken / deprecated, plus "
                            "NIST IR 8547 and CNSA 2.0", BLUE),
              ("5  RANK", "risk = vulnerability × timing × HNDL, weighted by "
                          "business criticality", AMBER),
              ("6  DELIVER", "dashboard, CycloneDX 1.7 CBOM, board PDF, drift "
                             "diff between two scans", GREEN)]
    for i, (head, body, accent) in enumerate(stages):
        x = COL6[i]
        box(slide, x, 3.68, W6, 0.88, fill=PANEL, line=BORDER, radius=0.08)
        bar(slide, x, 3.68, W6, 0.24, accent)
        tb(slide, x, 3.705, W6, 0.21,
           [{"t": head, "sz": 8.2, "c": WHITE, "b": True}], align=PP_ALIGN.CENTER)
        tb(slide, x + 0.06, 3.98, W6 - 0.12, 0.54,
           [{"t": body, "sz": 7.5, "c": MUTED, "ls": 0.95}])
        if i < 5:
            tb(slide, x + W6 + 0.005, 4.03, 0.12, 0.20,
               [{"t": "›", "sz": 11, "c": BORDER, "b": True}], align=PP_ALIGN.CENTER)

    shot(slide, "graph.png", LEFT_X, 4.64, LEFT_W)
    caption(slide, LEFT_X, 6.60, LEFT_W,
            "Asset graph — blast radius. 125 nodes, 117 low-priority assets "
            "clustered so all 191 stay represented, never truncated.")
    shot(slide, "inventory.png", RIGHT_X, 4.64, RIGHT_W)
    caption(slide, RIGHT_X, 6.60, RIGHT_W,
            "Inventory explorer — every asset traceable to its source, its "
            "confidence band and an exact file:line for evidence.")


# ===================================================== SLIDE 4 : feasibility
def slide4(slide):
    keep_furniture(slide)
    set_title(slide, "FEASIBILITY AND VIABILITY")

    section(slide, 1.16, "Analysis of the feasibility of the idea")

    stats = [("262", "tests green, incl. browser UI tests", TEAL),
             ("100% / 97.5%", "precision / recall, 91-usage corpus", GREEN),
             ("7", "languages, Python through Rust", BLUE),
             ("8", "source types, code to PKCS#11", BLUE),
             ("0", "hard dependencies, runs offline", NAVY),
             ("1.7", "CycloneDX / ECMA-424, validated", TEAL)]
    for i, (value, label, accent) in enumerate(stats):
        x = COL6[i]
        t = tile(slide, x, 1.54, W6, 0.94, accent)
        text_into(t, [
            {"t": value, "sz": 17 if len(value) < 6 else 12, "c": accent,
             "b": True, "sp": 3, "ls": 0.82},
            {"t": label, "sz": 7.8, "c": MUTED, "ls": 0.98},
        ], align=PP_ALIGN.CENTER, pad=0.05)

    tb(slide, M, 2.58, CW, 0.24,
       [{"t": "Feasible because it is already built and measured. Every number "
              "above comes from pytest, the accuracy evaluator and a live scan on "
              "this machine — none of it is an estimate.", "sz": 8.6, "c": INK}])

    section(slide, 2.90, "Potential challenges and risks", x=LEFT_X, w=LEFT_W)
    section(slide, 2.90, "Strategies for overcoming these challenges",
            x=RIGHT_X, w=RIGHT_W)

    pairs = [
        ("Static analysis cannot see runtime-chosen algorithms",
         "Algorithm names read from the environment, or resolved through "
         "getattr, are invisible to any scanner.",
         "Confidence banding + independent ground truth",
         "Every finding carries a confidence level, and our 2 known misses are "
         "published in the corpus as misses, not hidden."),
        ("Q-Day (Z) is genuinely unknowable",
         "Hardcode a date and every score inherits one team’s guess — easy for a "
         "sceptical auditor to dismiss.",
         "Score the certain clock alongside the uncertain one",
         "Z is a visible dial, never a constant, and the fixed NIST IR 8547 date "
         "is scored beside it."),
        ("Business context cannot be read out of code",
         "No parser knows that a given AES call protects 25-year defence records. "
         "Guessing silently produces confident, wrong numbers.",
         "Human inputs, declared as human inputs",
         "Lifetime and criticality come from a reviewed crypto-policy.yaml; "
         "anything defaulted is stored and badged “assumed”."),
        ("The tool’s own output is a weapon",
         "A ranked list of an organisation’s weakest cryptography is an "
         "attacker’s shopping list, pre-sorted.",
         "A security model for the scanner itself",
         "Read-only connectors (never Decrypt, never Sign) · allowlisted probing, "
         "refused not warned · role-gated settings · audit-logged exports."),
    ]
    y = 3.26
    for lh, lb, rh, rb in pairs:
        card(slide, LEFT_X, y, LEFT_W, 0.86, AMBER)
        tb(slide, LEFT_X + 0.18, y + 0.08, LEFT_W - 0.30, 0.20,
           [{"t": lh, "sz": 8.6, "c": INK, "b": True}])
        tb(slide, LEFT_X + 0.18, y + 0.31, LEFT_W - 0.32, 0.50,
           [{"t": lb, "sz": 7.8, "c": MUTED, "ls": 1.02}])
        card(slide, RIGHT_X, y, RIGHT_W, 0.86, TEAL)
        tb(slide, RIGHT_X + 0.18, y + 0.08, RIGHT_W - 0.30, 0.20,
           [{"t": rh, "sz": 8.6, "c": TEAL, "b": True}])
        tb(slide, RIGHT_X + 0.18, y + 0.31, RIGHT_W - 0.32, 0.50,
           [{"t": rb, "sz": 7.8, "c": MUTED, "ls": 1.02}])
        tb(slide, 6.50, y + 0.30, 0.24, 0.22,
           [{"t": "→", "sz": 11, "c": MUTED, "b": True}], align=PP_ALIGN.CENTER)
        y += 0.92


# ========================================================== SLIDE 5 : impact
def slide5(slide):
    keep_furniture(slide)
    set_title(slide, "IMPACT AND BENEFITS")

    section(slide, 1.16, "Potential impact on the target audience",
            x=LEFT_X, w=LEFT_W)

    people = [("CISO / risk officer",
               "A ranked, defensible board report instead of a spreadsheet guess — "
               "and owns the Z dial that drives it.", TEAL),
              ("Security / crypto engineer",
               "Algorithm, key size, library version and an exact file:line per "
               "finding, each with a confidence band.", BLUE),
              ("DevOps / platform team",
               "One command or one drag-and-drop. No agent, no cluster, no code "
               "leaving the building.", NAVY),
              ("Compliance / audit lead",
               "A standards-conformant CycloneDX 1.7 CBOM is regulatory evidence. "
               "A screenshot is not.", GREEN)]
    y = 1.54
    for head, body, accent in people:
        card(slide, LEFT_X, y, LEFT_W, 0.66, accent)
        tb(slide, LEFT_X + 0.18, y + 0.07, LEFT_W - 0.30, 0.20,
           [{"t": head, "sz": 8.6, "c": accent, "b": True}])
        tb(slide, LEFT_X + 0.18, y + 0.29, LEFT_W - 0.32, 0.34,
           [{"t": body, "sz": 7.8, "c": MUTED, "ls": 1.02}])
        y += 0.71

    card(slide, LEFT_X, 4.38, LEFT_W, 0.72, TEAL, fill=TEAL_L)
    tb(slide, LEFT_X + 0.18, 4.45, LEFT_W - 0.30, 0.20,
       [{"t": "India, at national scale", "sz": 8.6, "c": TEAL, "b": True}])
    tb(slide, LEFT_X + 0.18, 4.67, LEFT_W - 0.32, 0.40,
       [{"t": "RBI, SEBI, UIDAI, defence and telecom all hold data whose "
              "confidentiality must outlast 2035 — and none of them can migrate "
              "what they have never inventoried.", "sz": 7.8, "c": INK,
         "ls": 1.02}])

    shot(slide, "recs.png", RIGHT_X, 1.54, RIGHT_W)
    caption(slide, RIGHT_X, 4.60, RIGHT_W,
            "Recommendations — every broken asset gets a named NIST replacement, "
            "ranked by risk, latency and rotation cost.")
    card(slide, RIGHT_X, 4.86, RIGHT_W, 0.52, TEAL, fill=TEAL_L)
    tb(slide, RIGHT_X + 0.19, 4.95, RIGHT_W - 0.32, 0.36,
       [{"t": "In plain English: it does not just say “this lock is weak”. It says "
              "replace this exact lock, with this exact model, before this date.",
         "sz": 8.2, "c": INK, "ls": 1.02}])

    section(slide, 5.52, "Benefits of the solution (social, economic, "
                         "environmental, etc.)")

    benefits = [("SOCIAL", "Citizen data recorded today — Aadhaar-linked, health, "
                           "financial — stays private after Q-Day.", TEAL),
                ("ECONOMIC", "Budget goes to the assets that matter instead of a "
                             "blanket rewrite. Weeks of consultancy become one "
                             "command.", BLUE),
                ("STRATEGIC", "Open and self-hosted. No Indian organisation hands "
                              "a map of its weak points to a foreign SaaS vendor.",
                 NAVY),
                ("ENVIRONMENTAL", "Static analysis on a laptop. No GPU, no "
                                  "always-on agent, no cluster.", GREEN)]
    for i, (head, body, accent) in enumerate(benefits):
        x = COL4[i]
        box(slide, x, 5.90, W4, 0.93, fill=PANEL, line=BORDER, radius=0.08)
        bar(slide, x, 5.90, W4, 0.21, accent)
        tb(slide, x, 5.925, W4, 0.19, [{"t": head, "sz": 8.2, "c": WHITE,
                                        "b": True}], align=PP_ALIGN.CENTER)
        tb(slide, x + 0.13, 6.19, W4 - 0.26, 0.60,
           [{"t": body, "sz": 7.8, "c": MUTED, "ls": 1.02}], align=PP_ALIGN.CENTER)


# ======================================================== SLIDE 6 : research
def slide6(slide):
    keep_furniture(slide)
    set_title(slide, "RESEARCH AND REFERENCES")

    section(slide, 1.16, "Details / Links of the reference and research work")

    cards = [
        ("Standards we implement", TEAL, [
            ("NIST IR 8547 (ipd)",
             "RSA and ECC deprecated after 2030, disallowed after 2035 — the "
             "second, certain clock we score alongside Q-Day."),
            ("FIPS 203 / 204 / 205 / 206 (ipd)",
             "ML-KEM, ML-DSA, SLH-DSA, FN-DSA — the replacements we name per "
             "asset. FIPS 206 carries a maturity badge, never a default."),
            ("NIST SP 800-208  ·  NSA CNSA 2.0",
             "LMS / XMSS for firmware signing; CNSA is the source of our AES-256 "
             "and SHA-384 flags, raised as policy, never as a break."),
        ]),
        ("Formats and prior art", BLUE, [
            ("CycloneDX 1.7, ratified ECMA-424 2nd Ed. (Dec 2025)",
             "cyclonedx.org/capabilities/cbom  ·  our CBOM output format, "
             "validated on every single scan."),
            ("CycloneDX Cryptography Registry",
             "Algorithm-name normalisation, so our output is directly comparable "
             "with other vendors’ CBOMs instead of using private names."),
            ("IBM CBOM  ·  github.com/IBM/CBOM",
             "The closest prior art to this problem statement, and the baseline "
             "we measured our own output shape against."),
        ]),
        ("Method and theory", NAVY, [
            ("M. Mosca — will we be ready?",
             "The X + Y > Z inequality is the backbone of our priority score."),
            ("P. Shor (1994)",
             "Why RSA, DSA, DH, ECDSA and ECDH break outright rather than merely "
             "weaken: there is no key-size fix, the mathematics is gone."),
            ("L. Grover (1996)  ·  Brassard–Høyer–Tapp",
             "And why they matter far less than the headlines claim. This reading "
             "is why we classify AES-128 and SHA-256 as adequate."),
        ]),
    ]
    for i, (title, accent, rows) in enumerate(cards):
        x = COL3[i]
        box(slide, x, 1.54, W3, 2.62, fill=WHITE, line=BORDER, radius=0.05)
        header = box(slide, x, 1.54, W3, 0.30, fill=accent, line=None, radius=0.40)
        text_into(header, [{"t": title, "sz": 9.2, "c": WHITE, "b": True}],
                  pad=0.12)
        ry = 1.94
        for head, body in rows:
            tb(slide, x + 0.17, ry, W3 - 0.30, 0.20,
               [{"t": head, "sz": 8.2, "c": INK, "b": True, "ls": 1.0}])
            tb(slide, x + 0.17, ry + 0.21, W3 - 0.32, 0.50,
               [{"t": body, "sz": 7.5, "c": MUTED, "ls": 1.02}])
            ry += 0.74

    # --- our own research, full width -------------------------------------
    box(slide, M, 4.30, CW, 2.28, fill=PANEL, line=BORDER, radius=0.05)
    header = box(slide, M, 4.30, CW, 0.30, fill=GREEN, line=None, radius=0.40)
    text_into(header, [{"t": "Our own research — not just citations", "sz": 9.2,
                        "c": WHITE, "b": True}], pad=0.14)

    own = [("corpus/ — a labelled ground truth we built",
            "91 cryptographic usages hand-labelled from source across 7 languages, "
            "plus 7 negative controls that discuss cryptography while performing "
            "none. Building it surfaced 7 real bugs in our own scanner."),
           ("Measured, not asserted  ·  cbom-compass eval",
            "Algorithm level 100% precision / 97.5% recall; strict — key size, "
            "mode and curve — 98.9% / 96.7%. Zero findings on the negative "
            "controls, and a regression fails CI instead of shipping quietly."),
           ("Proof the findings are real  ·  cbom-compass verify",
            "Re-opens each artefact on disk and re-checks the claim by a "
            "deliberately different technique, quoting the line. The tests plant "
            "fabricated findings and assert every one is rejected.")]
    for i, (head, body) in enumerate(own):
        x = 0.46 + i * 4.23
        tb(slide, x, 4.70, 4.05, 0.20,
           [{"t": head, "sz": 8.2, "c": GREEN, "b": True}])
        tb(slide, x, 4.92, 4.05, 0.80,
           [{"t": body, "sz": 7.5, "c": MUTED, "ls": 1.04}])

    bar(slide, 0.46, 5.82, 12.41, 0.01, BORDER)
    tb(slide, 0.46, 5.90, 12.41, 0.56,
       [{"t": "Research that changed the design.  Our PRD v1.0 targeted CycloneDX "
              "1.6; reading the ECMA-424 2nd Edition ratification moved us to 1.7, "
              "where nistQuantumSecurityLevel is a native field rather than a "
              "vendor extension. A scan of real third-party code (paramiko) scored "
              "an already-migrated ML-KEM key exchange at 0.60 — that single "
              "finding rewrote the priority formula from a flat max() across peer "
              "axes to vulnerability × timing.", "sz": 7.8, "c": INK, "ls": 1.04}])

    tb(slide, M, 6.66, CW, 0.20,
       [{"t": "Full specification and design record: docs/cbom-compass-prd.md  ·  "
              "scanner accuracy notes: corpus/README.md  ·  architecture, security "
              "model and stated limits: README.md", "sz": 7.5, "c": MUTED}])


def main():
    prs = Presentation(TEMPLATE)
    for build, slide in zip((slide1, slide2, slide3, slide4, slide5, slide6),
                            prs.slides):
        build(slide)
    prs.save(OUT)
    print(f"wrote {OUT}  ({OUT.stat().st_size / 1024 / 1024:.1f} MB)")


main()
