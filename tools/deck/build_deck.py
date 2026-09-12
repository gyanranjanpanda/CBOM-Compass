"""Build the SIH idea-submission deck for CBOM Compass — visual, not text-heavy."""
from __future__ import annotations

import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

SHOTS = Path(sys.argv[1] if len(sys.argv) > 1 else "build/shots")
LOGO = Path(sys.argv[2] if len(sys.argv) > 2 else "tools/deck/sih-logo.png")
OUT = Path(sys.argv[3] if len(sys.argv) > 3 else
           "SIH2025-IDEA-CBOM-Compass-TeamNexus-v2.pptx")

# ---------------------------------------------------------------- palette
INK = RGBColor(0x1F, 0x29, 0x33)
INK2 = RGBColor(0x5A, 0x6B, 0x7B)
INK3 = RGBColor(0x8F, 0xA3, 0xB8)
NAVY = RGBColor(0x1F, 0x49, 0x7D)
TEAL = RGBColor(0x0E, 0x8C, 0x86)
TEAL_L = RGBColor(0xE3, 0xF4, 0xF2)
BLUE = RGBColor(0x00, 0x70, 0xC0)
BLUE_L = RGBColor(0xE4, 0xF0, 0xFA)
RED = RGBColor(0xC0, 0x39, 0x2B)
RED_L = RGBColor(0xFB, 0xE9, 0xE7)
AMBER = RGBColor(0xB9, 0x77, 0x0E)
AMBER_L = RGBColor(0xFD, 0xF4, 0xE3)
GREEN = RGBColor(0x1E, 0x84, 0x49)
GREEN_L = RGBColor(0xE6, 0xF5, 0xEC)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
PANEL = RGBColor(0xF3, 0xF8, 0xFC)
BORDER = RGBColor(0xCB, 0xDD, 0xEC)
FONT = "Segoe UI"

W, H = 13.333, 7.5


# ---------------------------------------------------------------- helpers
def new_deck() -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(W)
    prs.slide_height = Inches(H)
    return prs


def blank(prs):
    return prs.slides.add_slide(prs.slide_layouts[6])


def box(slide, x, y, w, h, fill=None, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
        radius=0.06, lw=0.75):
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


def tb(slide, x, y, w, h, blocks, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP,
       wrap=True):
    """blocks: list of dicts {t, sz, c, b, i, sp (space_after pt), ls (line spacing)}"""
    s = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = s.text_frame
    tf.word_wrap = wrap
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
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
        f.size = Pt(blk.get("sz", 11))
        f.bold = blk.get("b", False)
        f.italic = blk.get("i", False)
        f.color.rgb = blk.get("c", INK)
    return s


def fill_text(shape, blocks, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.MIDDLE,
              pad=0.10):
    tf = shape.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(pad)
    tf.margin_top = tf.margin_bottom = Inches(0.04)
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
        f.size = Pt(blk.get("sz", 11))
        f.bold = blk.get("b", False)
        f.italic = blk.get("i", False)
        f.color.rgb = blk.get("c", INK)
    return shape


def chip(slide, x, y, w, h, text, fill, fg, sz=9.5, bold=True):
    s = box(slide, x, y, w, h, fill=fill, line=None, radius=0.5)
    fill_text(s, [{"t": text, "sz": sz, "c": fg, "b": bold}],
              align=PP_ALIGN.CENTER, pad=0.06)
    return s


def rule(slide, x, y, w, color=BORDER, weight=1.0):
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y),
                               Inches(w), Pt(weight))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s


def vrule(slide, x, y, h, color=BORDER, weight=1.0):
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y),
                               Pt(weight), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s


def chevron(slide, x, y, w, h, head, body, accent):
    s = slide.shapes.add_shape(MSO_SHAPE.CHEVRON, Inches(x), Inches(y),
                               Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = PANEL
    s.line.color.rgb = accent
    s.line.width = Pt(1.0)
    s.shadow.inherit = False
    fill_text(s, [
        {"t": head, "sz": 10.5, "c": accent, "b": True, "sp": 1},
        {"t": body, "sz": 8.5, "c": INK2, "ls": 0.92},
    ], align=PP_ALIGN.CENTER, pad=0.13)
    return s


def padlock(slide, cx, top, scale=1.0, color=TEAL, bg=WHITE, broken=False):
    """A padlock drawn from primitives: a ring with its lower half masked, and a body."""
    ring_d = 0.62 * scale
    body_w, body_h = 0.88 * scale, 0.66 * scale
    ring = slide.shapes.add_shape(
        MSO_SHAPE.DONUT, Inches(cx - ring_d / 2), Inches(top),
        Inches(ring_d), Inches(ring_d))
    ring.adjustments[0] = 0.19
    ring.fill.solid()
    ring.fill.fore_color.rgb = color
    ring.line.fill.background()
    ring.shadow.inherit = False
    # Mask the lower half of the ring so it reads as a shackle.
    mask = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(cx - ring_d / 2 - 0.02),
        Inches(top + ring_d * 0.52), Inches(ring_d + 0.04), Inches(ring_d * 0.55))
    mask.fill.solid()
    mask.fill.fore_color.rgb = bg
    mask.line.fill.background()
    mask.shadow.inherit = False

    body_top = top + ring_d * 0.62
    body = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(cx - body_w / 2), Inches(body_top),
        Inches(body_w), Inches(body_h))
    body.adjustments[0] = 0.18
    body.fill.solid()
    body.fill.fore_color.rgb = color
    body.line.fill.background()
    body.shadow.inherit = False

    if broken:
        # A diagonal slash through the shackle: the lock is open.
        cut = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, Inches(cx - ring_d * 0.62),
            Inches(top + ring_d * 0.16), Inches(ring_d * 1.3), Inches(0.075))
        cut.fill.solid()
        cut.fill.fore_color.rgb = bg
        cut.line.fill.background()
        cut.shadow.inherit = False
        cut.rotation = -32
    else:
        keyhole = slide.shapes.add_shape(
            MSO_SHAPE.OVAL, Inches(cx - 0.075 * scale),
            Inches(body_top + body_h * 0.28), Inches(0.15 * scale), Inches(0.15 * scale))
        keyhole.fill.solid()
        keyhole.fill.fore_color.rgb = bg
        keyhole.line.fill.background()
        keyhole.shadow.inherit = False
    return body_top + body_h


def chrome(prs, slide, number, title, kicker=None):
    """SIH template furniture: title, team badge, logo, footer, slide number."""
    tb(slide, 0.45, 0.28, 8.6, 0.58,
       [{"t": title, "sz": 25, "c": NAVY, "b": True}])
    if kicker:
        tb(slide, 0.45, 0.80, 9.4, 0.3, [{"t": kicker, "sz": 10.5, "c": INK2}])
    rule(slide, 0.45, 1.10 if kicker else 0.95, 12.45, BORDER, 1.0)

    badge = box(slide, 9.28, 0.30, 1.32, 0.36, fill=TEAL_L, line=TEAL, radius=0.5)
    fill_text(badge, [{"t": "Team Nexus", "sz": 9.5, "c": TEAL, "b": True}],
              align=PP_ALIGN.CENTER, pad=0.04)
    if LOGO.exists():
        slide.shapes.add_picture(str(LOGO), Inches(10.95), Inches(0.16),
                                 height=Inches(0.62))

    rule(slide, 0, 7.02, W, BORDER, 0.75)
    tb(slide, 0.45, 7.12, 5.0, 0.3,
       [{"t": "@SIH Idea submission- Template", "sz": 8.5, "c": INK3}])
    tb(slide, 11.6, 7.12, 1.3, 0.3, [{"t": str(number), "sz": 8.5, "c": INK3}],
       align=PP_ALIGN.RIGHT)


def shot(slide, name, x, y, w, caption=None):
    p = SHOTS / name
    pic = slide.shapes.add_picture(str(p), Inches(x), Inches(y), width=Inches(w))
    frame = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y),
                                   Inches(w), Emu(pic.height))
    frame.fill.background()
    frame.line.color.rgb = BORDER
    frame.line.width = Pt(0.75)
    frame.shadow.inherit = False
    bottom = y + Emu(pic.height).inches
    if caption:
        tb(slide, x, bottom + 0.07, w, 0.3,
           [{"t": caption, "sz": 8, "c": INK3, "ls": 0.95}])
    return bottom


# ================================================================ SLIDE 1
def slide_title(prs):
    s = blank(prs)
    band = slide_bg = box(s, 0, 0, W, H, fill=WHITE, line=None, radius=0,
                          shape=MSO_SHAPE.RECTANGLE)
    accent = box(s, 0, 0, 0.22, H, fill=NAVY, line=None, radius=0,
                 shape=MSO_SHAPE.RECTANGLE)

    if LOGO.exists():
        s.shapes.add_picture(str(LOGO), Inches(10.9), Inches(0.42),
                             height=Inches(0.78))

    tb(s, 0.72, 0.55, 7.5, 0.32,
       [{"t": "SMART INDIA HACKATHON 2025", "sz": 12, "c": TEAL, "b": True}])
    tb(s, 0.70, 0.92, 8.4, 1.0, [{"t": "CBOM COMPASS", "sz": 48, "c": NAVY, "b": True}])
    tb(s, 0.72, 1.85, 6.80, 0.8, [
        {"t": "An X-ray for your organisation’s encryption.", "sz": 15, "c": INK,
         "b": True, "sp": 3},
        {"t": "Find every lock in the building, work out which ones a quantum "
              "computer can pick and which ones the regulator bans first — then "
              "hand back a prioritised locksmith’s list.", "sz": 11, "c": INK2,
         "ls": 1.06},
    ])
    rule(s, 0.72, 2.92, 3.0, TEAL, 2.5)

    meta = [
        ("Problem Statement ID", "SIH25164"),
        ("Theme", "Cybersecurity"),
        ("PS Category", "Software"),
        ("Team ID", "<TEAM ID>"),
        ("Team Name", "Team Nexus"),
    ]
    y = 3.24
    for label, value in meta:
        tb(s, 0.72, y, 1.85, 0.26, [{"t": label, "sz": 9.5, "c": INK3}])
        tb(s, 2.62, y, 4.6, 0.26, [{"t": value, "sz": 10.5, "c": INK, "b": True}])
        y += 0.425
    tb(s, 0.72, y + 0.14, 6.6, 0.6, [
        {"t": "Problem Statement Title", "sz": 9.5, "c": INK3, "sp": 2},
        {"t": "Development of a tool for the identification and assessment of "
              "cryptographic assets and their post-quantum migration readiness",
         "sz": 10, "c": INK, "b": True, "ls": 1.0},
    ])

    # --- hero: an intact lock, and the same lock in 2031 --------------------
    hero = box(s, 7.75, 1.55, 5.05, 4.5, fill=PANEL, line=BORDER, radius=0.035)
    tb(s, 8.05, 1.76, 4.45, 0.3,
       [{"t": "THE SHIFT WE ARE MEASURING", "sz": 9, "c": INK3, "b": True}],
       align=PP_ALIGN.CENTER)

    padlock(s, 9.20, 2.18, scale=1.05, color=TEAL, bg=PANEL)
    tb(s, 8.15, 3.38, 2.1, 0.6, [
        {"t": "TODAY", "sz": 10, "c": TEAL, "b": True, "sp": 2},
        {"t": "RSA and ECC hold\nthe door shut.", "sz": 9.5, "c": INK2, "ls": 0.95},
    ], align=PP_ALIGN.CENTER)

    arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(10.02), Inches(2.62),
                               Inches(0.52), Inches(0.28))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = INK3
    arrow.line.fill.background()
    arrow.shadow.inherit = False

    padlock(s, 11.35, 2.18, scale=1.05, color=RED, bg=PANEL, broken=True)
    tb(s, 10.30, 3.38, 2.1, 0.6, [
        {"t": "Q-DAY", "sz": 10, "c": RED, "b": True, "sp": 2},
        {"t": "Shor’s algorithm\nopens both.", "sz": 9.5, "c": INK2, "ls": 0.95},
    ], align=PP_ALIGN.CENTER)

    rule(s, 8.15, 4.24, 4.25, BORDER, 1.0)
    tb(s, 8.15, 4.40, 4.25, 0.9, [
        {"t": "No key size fixes this. The mathematics is gone —", "sz": 9.5,
         "c": INK2, "sp": 2, "ls": 1.0},
        {"t": "so every RSA and ECC key you own has an expiry date.",
         "sz": 9.5, "c": INK, "b": True, "ls": 1.0},
    ], align=PP_ALIGN.CENTER)

    stats = [("8", "sources scanned"), ("191", "assets in the demo"),
             ("100%", "precision, measured")]
    x = 8.05
    for value, label in stats:
        t = box(s, x, 5.28, 1.50, 0.58, fill=WHITE, line=BORDER, radius=0.1)
        fill_text(t, [
            {"t": value, "sz": 15, "c": NAVY, "b": True, "sp": 0, "ls": 0.85},
            {"t": label, "sz": 7.5, "c": INK3, "ls": 0.9},
        ], align=PP_ALIGN.CENTER, pad=0.03)
        x += 1.60

    tb(s, 0.72, 6.62, 9.0, 0.3,
       [{"t": "Working prototype  ·  262 automated tests green  ·  runs offline "
              "on one laptop", "sz": 10, "c": TEAL, "b": True}])


# ================================================================ SLIDE 2
def slide_idea(prs):
    s = blank(prs)
    chrome(prs, s, 2, "IDEA TITLE",
           "CBOM Compass — find it, judge it, rank it, fix it.")

    # ---- Row A: harvest now, decrypt later, as a three-panel story --------
    tb(s, 0.45, 1.22, 8.0, 0.28,
       [{"t": "THE PROBLEM, IN ONE PICTURE — “harvest now, decrypt later”",
         "sz": 10.5, "c": NAVY, "b": True}])

    panels = [
        (TEAL, TEAL_L, "1  ·  TODAY", "Your data is locked with\ntoday’s encryption.", False),
        (AMBER, AMBER_L, "2  ·  TODAY", "An attacker copies the locked\nfile. They cannot open it — yet.", None),
        (RED, RED_L, "3  ·  ~2031", "A quantum computer opens it.\nEverything since today is exposed.", True),
    ]
    x = 0.45
    for accent, light, head, body, broken in panels:
        p = box(s, x, 1.58, 3.74, 1.68, fill=light, line=accent, radius=0.05)
        tb(s, x + 0.22, 1.74, 2.3, 0.26, [{"t": head, "sz": 9.5, "c": accent, "b": True}])
        tb(s, x + 0.22, 2.08, 2.48, 0.9,
           [{"t": body, "sz": 10, "c": INK, "ls": 1.02}])
        if broken is None:
            # a copy icon: two offset outlined pages
            for dx, dy, fc in ((0.10, 0.10, None), (0.0, 0.0, light)):
                pg = box(s, x + 2.92 + dx, 1.86 + dy, 0.52, 0.66,
                         fill=fc if fc else light, line=accent, radius=0.08)
        else:
            padlock(s, x + 3.22, 1.80, scale=0.92, color=accent, bg=light,
                    broken=broken)
        x += 3.90

    for ax in (4.16, 8.06):
        a = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(ax), Inches(2.30),
                               Inches(0.26), Inches(0.22))
        a.fill.solid()
        a.fill.fore_color.rgb = INK3
        a.line.fill.background()
        a.shadow.inherit = False

    # ---- Row B left: Mosca, drawn --------------------------------------
    m = box(s, 0.45, 3.42, 6.55, 2.12, fill=PANEL, line=BORDER, radius=0.04)
    tb(s, 0.68, 3.56, 6.1, 0.28,
       [{"t": "HOW WE DECIDE WHAT MOVES FIRST — Mosca’s inequality, drawn",
         "sz": 10, "c": NAVY, "b": True}])

    x0, span_in, years = 0.78, 5.55, 15.0          # 2026 → 2041
    per = span_in / years
    bar_y, bar_h = 4.02, 0.30

    xb = box(s, x0, bar_y, per * 10, bar_h, fill=TEAL, line=None, radius=0.12)
    fill_text(xb, [{"t": "X  ·  data must stay secret  ·  10 yrs", "sz": 8.5,
                    "c": WHITE, "b": True}], align=PP_ALIGN.CENTER, pad=0.05)
    yb = box(s, x0 + per * 10, bar_y, per * 5, bar_h, fill=BLUE, line=None, radius=0.12)
    fill_text(yb, [{"t": "Y  ·  migration  ·  5 yrs", "sz": 8.5, "c": WHITE,
                    "b": True}], align=PP_ALIGN.CENTER, pad=0.05)

    zx = x0 + per * 5                                # Q-Day at 2031
    vrule(s, zx, 3.88, 0.72, RED, 2.25)
    tb(s, zx - 0.62, 4.62, 1.30, 0.26,
       [{"t": "Q-Day  2031", "sz": 8.5, "c": RED, "b": True}], align=PP_ALIGN.CENTER)

    rule(s, x0, 4.52, span_in, BORDER, 0.75)
    for year in (2026, 2031, 2036, 2041):
        tx = x0 + per * (year - 2026)
        tb(s, tx - 0.30, 4.88, 0.60, 0.22, [{"t": str(year), "sz": 7.5, "c": INK3}],
           align=PP_ALIGN.CENTER)

    verdict = box(s, 0.78, 5.14, 5.55, 0.30, fill=RED_L, line=RED, radius=0.3)
    fill_text(verdict, [{"t": "X + Y  =  15 yrs   >   Z  =  5 yrs        "
                              "→   this asset is already overdue", "sz": 9.5,
                         "c": RED, "b": True}], align=PP_ALIGN.CENTER, pad=0.06)

    # ---- Row B right: what the tool does -------------------------------
    tb(s, 7.22, 3.42, 5.6, 0.28,
       [{"t": "WHAT THE TOOL ACTUALLY DOES", "sz": 10, "c": NAVY, "b": True}])
    steps = [
        ("1  SEE", "every place\nencryption hides", TEAL),
        ("2  JUDGE", "broken, weak,\nor genuinely fine", BLUE),
        ("3  RANK", "what breaks\nyou first", AMBER),
        ("4  FIX", "the exact NIST\nreplacement", GREEN),
    ]
    x = 7.22
    for head, body, accent in steps:
        chevron(s, x, 3.76, 1.62, 1.10, head, body, accent)
        x += 1.42

    tb(s, 7.22, 5.02, 5.6, 0.50, [
        {"t": "One command, or one drag-and-drop.", "sz": 10, "c": INK, "b": True,
         "sp": 2},
        {"t": "No agent, no cluster, and nothing scanned ever leaves the machine.",
         "sz": 9.5, "c": INK2, "ls": 1.0},
    ])

    # ---- Row C: the three mandated headings, one line each ---------------
    cols = [
        ("Detailed explanation of the solution",
         "Eight sources — code, config, dependencies, binaries, containers, TLS, "
         "SSH, cloud & HSM — merged into one de-duplicated inventory."),
        ("How it addresses the problem",
         "You cannot migrate what you cannot see. “We think we use RSA somewhere” "
         "becomes 191 named assets, each with an exact location."),
        ("Innovation and uniqueness",
         "Mosca made continuous, not yes/no. We refuse to cry wolf — AES-256 stays "
         "green. And every finding is re-proved from disk."),
    ]
    x = 0.45
    for head, body in cols:
        c = box(s, x, 5.68, 4.03, 1.18, fill=WHITE, line=BORDER, radius=0.05)
        rule(s, x, 5.68, 4.03, TEAL, 2.5)
        tb(s, x + 0.18, 5.84, 3.7, 0.24,
           [{"t": head, "sz": 9.5, "c": TEAL, "b": True}])
        tb(s, x + 0.18, 6.14, 3.68, 0.66,
           [{"t": body, "sz": 9, "c": INK2, "ls": 1.02}])
        x += 4.21


# ================================================================ SLIDE 3
def slide_technical(prs):
    s = blank(prs)
    chrome(prs, s, 3, "TECHNICAL APPROACH",
           "Pure static analysis plus read-only probes. No agent, no GPU, no cluster.")

    # ---- the eight sources ------------------------------------------------
    tb(s, 0.45, 1.24, 8.0, 0.28,
       [{"t": "WHERE ENCRYPTION HIDES — eight sources, one inventory", "sz": 10.5,
         "c": NAVY, "b": True}])
    sources = [
        ("CODE", "Python AST\n+ 6 languages", TEAL),
        ("CONFIG", "SSH · IPsec\nnginx · VPN", TEAL),
        ("DEPS", "manifests +\nlibrary KB", BLUE),
        ("BINARIES", "ELF · PE\nMach-O", BLUE),
        ("CONTAINERS", "layers +\nbaked-in keys", NAVY),
        ("TLS", "live\nhandshake", AMBER),
        ("SSH", "live offered\nalgorithms", AMBER),
        ("CLOUD & HSM", "AWS · Azure\nGCP · PKCS#11", RED),
    ]
    x, tile_w = 0.45, 1.50
    for head, body, accent in sources:
        t = box(s, x, 1.58, tile_w, 0.92, fill=WHITE, line=BORDER, radius=0.07)
        rule(s, x, 1.58, tile_w, accent, 2.5)
        fill_text(t, [
            {"t": head, "sz": 9, "c": accent, "b": True, "sp": 2, "ls": 0.9},
            {"t": body, "sz": 7.5, "c": INK2, "ls": 0.92},
        ], align=PP_ALIGN.CENTER, pad=0.04)
        x += tile_w + 0.06

    # ---- pipeline ---------------------------------------------------------
    tb(s, 0.45, 2.66, 9.0, 0.28,
       [{"t": "METHODOLOGY — six stages, and one failure never stops the run",
         "sz": 10.5, "c": NAVY, "b": True}])
    stages = [
        ("1  INGEST", "zip or repo URL,\nsandboxed at the edge"),
        ("2  SCAN", "eight scanners,\nindependently"),
        ("3  MERGE", "209 raw findings\n→ 191 real assets"),
        ("4  ASSESS", "Shor · classical\n· NIST IR 8547"),
        ("5  RANK", "Mosca × business\ncriticality"),
        ("6  DELIVER", "dashboard · CBOM\n· board PDF"),
    ]
    x = 0.45
    for i, (head, body) in enumerate(stages):
        accent = [TEAL, TEAL, BLUE, BLUE, AMBER, GREEN][i]
        chevron(s, x, 3.00, 2.18, 0.92, head, body, accent)
        x += 2.02

    # ---- technologies -----------------------------------------------------
    tb(s, 0.45, 4.12, 6.4, 0.28,
       [{"t": "TECHNOLOGIES USED", "sz": 10.5, "c": NAVY, "b": True}])
    groups = [
        ("Core", ["Python 3.11", "FastAPI", "Uvicorn", "SQLite → Postgres"], TEAL),
        ("Detection", ["ast", "LIEF", "Syft", "TLS / SSH sockets", "boto3", "azure",
                       "gcp", "PKCS#11"], BLUE),
        ("Output & QA", ["CycloneDX 1.7", "ReportLab", "pytest x262", "Playwright"],
         GREEN),
    ]
    x_start, x_limit = 1.42, 6.85
    y = 4.46
    for label, items, accent in groups:
        tb(s, 0.45, y + 0.04, 1.0, 0.24, [{"t": label, "sz": 9, "c": INK3, "b": True}])
        x = x_start
        for item in items:
            w = 0.20 + 0.075 * len(item)
            if x + w > x_limit:            # wrap rather than run off the column
                y += 0.38
                x = x_start
            chip(s, x, y, w, 0.30, item,
                 fill={TEAL: TEAL_L, BLUE: BLUE_L, GREEN: GREEN_L}[accent], fg=accent)
            x += w + 0.09
        y += 0.42

    # ---- proof shots ------------------------------------------------------
    shot(s, "graph.png", 7.05, 4.42, 2.88,
         "Asset graph - blast radius. All 191 assets stay represented.")
    shot(s, "inventory.png", 10.00, 4.42, 2.88,
         "Inventory - every asset traceable to an exact file and line.")

    strip = box(s, 0.45, 6.46, 12.43, 0.44, fill=PANEL, line=BORDER, radius=0.05)
    fill_text(strip, [{"t": "Hardware required: none.  A full 191-asset scan "
                            "finishes in about a second on a laptop - no GPU, no "
                            "cluster, and nothing scanned ever leaves the machine.",
                       "sz": 9.5, "c": INK, "b": True}],
              align=PP_ALIGN.CENTER, pad=0.15)


# ================================================================ SLIDE 4
def slide_feasibility(prs):
    s = blank(prs)
    chrome(prs, s, 4, "FEASIBILITY AND VIABILITY",
           "Feasible because it is already built, and every number below is measured.")

    tb(s, 0.45, 1.24, 7.4, 0.28,
       [{"t": "ANALYSIS OF FEASIBILITY — measured, not estimated", "sz": 10.5,
         "c": NAVY, "b": True}])

    stats = [
        ("262", "tests green", TEAL),
        ("100%", "precision", GREEN),
        ("97.5%", "recall", GREEN),
        ("7", "languages", BLUE),
        ("8", "source types", BLUE),
        ("0", "hard dependencies", NAVY),
    ]
    x, y = 0.45, 1.58
    for i, (value, label, accent) in enumerate(stats):
        if i == 3:
            x, y = 0.45, 2.42
        t = box(s, x, y, 2.38, 0.74, fill=WHITE, line=BORDER, radius=0.07)
        rule(s, x, y, 2.38, accent, 2.5)
        fill_text(t, [
            {"t": value, "sz": 20, "c": accent, "b": True, "sp": 0, "ls": 0.82},
            {"t": label, "sz": 8.5, "c": INK2, "ls": 0.9},
        ], align=PP_ALIGN.CENTER, pad=0.04)
        x += 2.46

    tb(s, 0.45, 3.26, 7.3, 0.28,
       [{"t": "Every figure comes from pytest, the accuracy evaluator and a live "
              "scan on this machine.", "sz": 9.5, "c": INK2}])

    shot(s, "overview_kpi.png", 0.45, 3.58, 6.85,
         "A real scan of the demo estate: 191 assets across all eight sources, "
         "scored and ranked - the numbers above are this run.")

    # ---- risks ------------------------------------------------------------
    tb(s, 8.00, 1.24, 4.9, 0.28,
       [{"t": "RISKS  →  HOW WE HANDLE THEM", "sz": 10.5, "c": NAVY, "b": True}])
    risks = [
        ("Static analysis cannot see runtime-chosen algorithms",
         "Every finding carries a confidence band, and our 2 known misses are "
         "published in the corpus as misses."),
        ("Q-Day is genuinely unknowable",
         "Z is a visible dial, never a constant — and the fixed NIST 2030/2035 "
         "deadline is scored beside it."),
        ("Business context is not in the code",
         "Data lifetime and criticality come from a reviewed policy file. Anything "
         "defaulted is badged “assumed”."),
        ("Our own output is an attacker’s shopping list",
         "Read-only connectors, allowlisted probing, role-gated settings, audit-logged "
         "exports, keys stored as fingerprints."),
    ]
    y = 1.58
    for head, body in risks:
        card = box(s, 8.00, y, 4.88, 1.10, fill=WHITE, line=BORDER, radius=0.05)
        vrule(s, 8.00, y, 1.10, AMBER, 2.5)
        tb(s, 8.20, y + 0.14, 4.5, 0.28,
           [{"t": head, "sz": 9.5, "c": INK, "b": True, "ls": 1.0}])
        tb(s, 8.20, y + 0.44, 4.5, 0.58,
           [{"t": body, "sz": 8.5, "c": INK2, "ls": 1.02}])
        y += 1.16

    closing = box(s, 8.00, y + 0.10, 4.88, 0.56, fill=TEAL_L, line=TEAL, radius=0.05)
    fill_text(closing, [{"t": "The scanner is threat-modelled as a target itself, "
                              "not just as a tool.", "sz": 9.5, "c": TEAL, "b": True}],
              align=PP_ALIGN.CENTER, pad=0.15)


# ================================================================ SLIDE 5
def slide_impact(prs):
    s = blank(prs)
    chrome(prs, s, 5, "IMPACT AND BENEFITS",
           "Inventory is the step every post-quantum transition has to start from.")

    tb(s, 0.45, 1.24, 7.4, 0.28,
       [{"t": "WHO IT HELPS, AND HOW", "sz": 10.5, "c": NAVY, "b": True}])
    people = [
        ("CISO / risk officer", "A ranked, defensible board report instead of a "
                                "spreadsheet guess.", TEAL),
        ("Security engineer", "Algorithm, key size and exact file:line, with a "
                              "confidence band.", BLUE),
        ("DevOps / platform", "One command. No agent, no cluster, no code leaving "
                              "the building.", NAVY),
        ("Compliance / audit", "A CycloneDX 1.7 CBOM is regulatory evidence. "
                               "A screenshot is not.", GREEN),
    ]
    x, y = 0.45, 1.58
    for i, (who, what, accent) in enumerate(people):
        if i == 2:
            x, y = 0.45, 2.62
        card = box(s, x, y, 3.62, 0.94, fill=WHITE, line=BORDER, radius=0.05)
        dot = box(s, x + 0.18, y + 0.20, 0.22, 0.22, fill=accent, line=None,
                  radius=0.5, shape=MSO_SHAPE.OVAL)
        tb(s, x + 0.50, y + 0.16, 3.0, 0.26,
           [{"t": who, "sz": 10, "c": accent, "b": True}])
        tb(s, x + 0.50, y + 0.44, 2.96, 0.46,
           [{"t": what, "sz": 8.5, "c": INK2, "ls": 1.0}])
        x += 3.78

    # ---- national scale ---------------------------------------------------
    n = box(s, 0.45, 3.70, 7.40, 0.86, fill=TEAL_L, line=TEAL, radius=0.05)
    tb(s, 0.68, 3.84, 6.95, 0.28,
       [{"t": "India, at national scale", "sz": 10.5, "c": TEAL, "b": True}])
    tb(s, 0.68, 4.13, 6.95, 0.38,
       [{"t": "RBI, SEBI, UIDAI, defence and telecom all hold data whose "
              "confidentiality must outlast 2035 — and none of them can migrate "
              "what they have never inventoried.", "sz": 9.5, "c": INK, "ls": 1.0}])

    # ---- benefits ---------------------------------------------------------
    tb(s, 0.45, 4.74, 7.4, 0.28,
       [{"t": "BENEFITS", "sz": 10.5, "c": NAVY, "b": True}])
    benefits = [
        ("SOCIAL", "Citizen data recorded today stays private after Q-Day.", TEAL),
        ("ECONOMIC", "Budget goes to the few assets that matter, not a blanket "
                     "rewrite.", BLUE),
        ("STRATEGIC", "Self-hosted. No map of India’s weak points sent to a "
                      "foreign SaaS.", NAVY),
        ("ENVIRONMENTAL", "A laptop, for about a second. No GPU, no always-on "
                          "agent.", GREEN),
    ]
    x = 0.45
    for head, body, accent in benefits:
        card = box(s, x, 5.08, 1.79, 1.62, fill=PANEL, line=BORDER, radius=0.05)
        rule(s, x, 5.08, 1.79, accent, 2.5)
        fill_text(card, [
            {"t": head, "sz": 8.5, "c": accent, "b": True, "sp": 5, "ls": 0.9},
            {"t": body, "sz": 8.5, "c": INK2, "ls": 1.04},
        ], align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE, pad=0.10)
        x += 1.87

    shot(s, "recs.png", 8.00, 1.58, 4.88,
         "Recommendations — every broken asset gets a named NIST replacement, "
         "ranked by risk, latency and rotation cost.")
    tb(s, 8.00, 5.86, 4.88, 0.94, [
        {"t": "In plain English", "sz": 10, "c": TEAL, "b": True, "sp": 3},
        {"t": "It does not just say “this lock is weak”. It says replace this exact "
              "lock, with this exact model, before this date — and puts the ones "
              "that matter most at the top.", "sz": 9.5, "c": INK, "ls": 1.04},
    ])


# ================================================================ SLIDE 6
def slide_research(prs):
    s = blank(prs)
    chrome(prs, s, 6, "RESEARCH AND REFERENCES",
           "What we implement, what we measured ourselves, and what changed the design.")

    cards = [
        ("STANDARDS WE IMPLEMENT", TEAL, [
            ("NIST IR 8547 (ipd)", "RSA and ECC deprecated after 2030, disallowed "
                                   "after 2035 — the second, certain clock."),
            ("FIPS 203 / 204 / 205 / 206", "ML-KEM, ML-DSA, SLH-DSA, FN-DSA — the "
                                           "replacements we name per asset."),
            ("NIST SP 800-208", "LMS / XMSS for firmware and code signing."),
            ("NSA CNSA 2.0", "Source of our AES-256 / SHA-384 policy flags — raised "
                             "as policy, never as a break."),
        ]),
        ("FORMATS AND PRIOR ART", BLUE, [
            ("CycloneDX 1.7 / ECMA-424 2nd Ed.", "Ratified Dec 2025. Our CBOM output "
                                                 "format, validated on every scan."),
            ("CycloneDX Cryptography Registry", "Algorithm-name normalisation, so our "
                                                "output is comparable with other vendors’."),
            ("IBM CBOM", "github.com/IBM/CBOM — the closest prior art, and the "
                         "baseline we measured our output shape against."),
        ]),
        ("METHOD AND THEORY", NAVY, [
            ("M. Mosca", "The X + Y > Z inequality — the backbone of our priority score."),
            ("P. Shor (1994)", "Why RSA, DSA, DH, ECDSA and ECDH break outright rather "
                               "than weaken: no key size fixes it."),
            ("Grover (1996) · Brassard–Høyer–Tapp", "And why they matter far less than "
                                                    "the headlines claim — this reading "
                                                    "is why we classify AES-128 and "
                                                    "SHA-256 as adequate."),
        ]),
        ("OUR OWN RESEARCH — NOT JUST CITATIONS", GREEN, [
            ("corpus/ — ground truth we built", "91 usages hand-labelled from source "
                                                "across 7 languages, plus 7 negative "
                                                "controls. Building it found 7 real bugs "
                                                "in our own scanner."),
            ("Measured, not asserted", "100% precision / 97.5% recall; strict 98.9% / "
                                       "96.7%. A regression fails CI instead of shipping."),
            ("Research that changed the design", "A real scan of paramiko scored an "
                                                 "already-migrated ML-KEM exchange at "
                                                 "0.60 — that one finding rewrote the "
                                                 "priority formula."),
        ]),
    ]

    x, y = 0.45, 1.26
    for i, (title, accent, rows) in enumerate(cards):
        if i == 2:
            x, y = 0.45, 4.06
        card = box(s, x, y, 6.20, 2.62, fill=WHITE, line=BORDER, radius=0.04)
        rule(s, x, y, 6.20, accent, 2.5)
        tb(s, x + 0.22, y + 0.15, 5.8, 0.26,
           [{"t": title, "sz": 10, "c": accent, "b": True}])
        ry = y + 0.46
        pitch = (2.62 - 0.56) / len(rows)
        for head, body in rows:
            tb(s, x + 0.22, ry, 5.76, 0.22, [{"t": head, "sz": 9, "c": INK, "b": True}])
            tb(s, x + 0.22, ry + 0.21, 5.76, pitch - 0.24,
               [{"t": body, "sz": 8.5, "c": INK2, "ls": 1.0}])
            ry += pitch
        x += 6.43

    tb(s, 0.45, 6.78, 12.0, 0.24,
       [{"t": "Full specification and design record: docs/cbom-compass-prd.md   ·   "
              "scanner accuracy notes: corpus/README.md   ·   architecture, security "
              "model and stated limits: README.md", "sz": 8, "c": INK3}])


def main():
    prs = new_deck()
    slide_title(prs)
    slide_idea(prs)
    slide_technical(prs)
    slide_feasibility(prs)
    slide_impact(prs)
    slide_research(prs)
    prs.save(OUT)
    print(f"wrote {OUT}  ({OUT.stat().st_size / 1024 / 1024:.1f} MB, "
          f"{len(prs.slides.__iter__.__self__._sldIdLst)} slides)")


main()
