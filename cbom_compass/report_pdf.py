"""PDF risk summary — PRD v1.1 section 8.2.

The audience is a board or a compliance reviewer, not an engineer, so this is
deliberately not a dump of the inventory. It leads with the numbers a risk
officer has to defend, states the assumptions behind them, and says plainly what
the tool could not see. A report that hides its own limitations is worse than no
report when an auditor reads it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

INK = colors.HexColor("#1b2430")
DIM = colors.HexColor("#5d6f7c")
RULE = colors.HexColor("#c8d2da")
ACCENT = colors.HexColor("#1d7f74")
STATUS_COLOUR = {
    "broken": colors.HexColor("#c0392b"),
    "broken_classical": colors.HexColor("#c0392b"),
    "deprecated_insufficient": colors.HexColor("#b8791d"),
    "adequate": colors.HexColor("#2f7d4f"),
    "not_applicable": colors.HexColor("#7a8896"),
    "unknown": colors.HexColor("#6a579b"),
}
STATUS_LABEL = {
    "broken": "Broken", "broken_classical": "Broken (classical)",
    "deprecated_insufficient": "Deprecated / insufficient", "adequate": "Adequate",
    "not_applicable": "Library inventory entry", "unknown": "Unclassified",
}


def _hex(colour) -> str:
    """reportlab hexval() returns 0xrrggbb; the markup parser wants #rrggbb."""
    return "#" + colour.hexval()[2:]


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=22, leading=26, textColor=INK, alignment=TA_LEFT,
                                spaceAfter=2),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontSize=10, leading=14,
                                   textColor=DIM, spaceAfter=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=12, leading=15, textColor=INK,
                             spaceBefore=16, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=14,
                               textColor=INK, spaceAfter=6),
        "note": ParagraphStyle("n", parent=base["Normal"], fontSize=8.5, leading=12.5,
                               textColor=DIM, spaceAfter=4),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8, leading=10.5,
                               textColor=INK),
        "cellmono": ParagraphStyle("cm", parent=base["Normal"], fontName="Courier",
                                   fontSize=7.5, leading=10, textColor=DIM),
    }


def _kpi_table(kpis: dict, st: dict) -> Table:
    by_status = kpis.get("by_status", {})
    broken = by_status.get("broken", 0) + by_status.get("broken_classical", 0)
    cells = [
        ("Assets", kpis["total_assets"], INK),
        ("Broken", broken, STATUS_COLOUR["broken"]),
        ("Deprecated", by_status.get("deprecated_insufficient", 0),
         STATUS_COLOUR["deprecated_insufficient"]),
        ("Adequate", by_status.get("adequate", 0), STATUS_COLOUR["adequate"]),
        ("Harvest-now", kpis.get("hndl_flagged", 0), STATUS_COLOUR["broken"]),
        ("Banned 2035", kpis.get("nist_disallowed_2035", 0),
         STATUS_COLOUR["deprecated_insufficient"]),
    ]
    data = [[Paragraph(f'<font size="18"><b>{value}</b></font><br/>'
                       f'<font size="7.5" color="#5d6f7c">{label.upper()}</font>',
                       ParagraphStyle("k", parent=st["cell"], leading=21, textColor=colour))
             for label, value, colour in cells]]
    table = Table(data, colWidths=[28.3 * mm] * len(cells), rowHeights=[22 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
    ]))
    return table


def _heat_table(heat: dict, st: dict) -> Table:
    cols = ["low", "medium", "high"]
    header = [""] + [Paragraph(f'<font size="7.5" color="#5d6f7c">{c.upper()} URGENCY</font>',
                               st["cell"]) for c in cols]
    rows = [header]
    maximum = max([1] + [heat[r][c] for r in ("high", "medium", "low") for c in cols])
    style = [("BOX", (0, 0), (-1, -1), 0.5, RULE),
             ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("ALIGN", (1, 1), (-1, -1), "CENTER")]
    for row_index, criticality in enumerate(("high", "medium", "low"), start=1):
        cells = [Paragraph(f'<font size="7.5" color="#5d6f7c">'
                           f'{criticality.upper()} CRITICALITY</font>', st["cell"])]
        for col_index, urgency in enumerate(cols, start=1):
            count = heat[criticality][urgency]
            cells.append(Paragraph(f'<font size="13"><b>{count}</b></font>', st["cell"]))
            base = STATUS_COLOUR["broken"] if urgency == "high" else (
                STATUS_COLOUR["deprecated_insufficient"] if urgency == "medium"
                else STATUS_COLOUR["adequate"])
            tint = colors.linearlyInterpolatedColor(
                colors.white, base, 0, 1, 0.10 + 0.42 * (count / maximum) if count else 0.0)
            style.append(("BACKGROUND", (col_index, row_index), (col_index, row_index), tint))
        rows.append(cells)
    table = Table(rows, colWidths=[42 * mm] + [26 * mm] * 3, rowHeights=[8 * mm] + [13 * mm] * 3)
    table.setStyle(TableStyle(style))
    return table


def _priority_table(assets: list[dict], st: dict, limit: int) -> Table:
    header = ["Score", "Asset", "Status", "Crit", "Conf", "Location", "Recommended action"]
    rows = [[Paragraph(f'<font size="7.5"><b>{h.upper()}</b></font>', st["cell"]) for h in header]]
    style = [("BOX", (0, 0), (-1, -1), 0.5, RULE),
             ("LINEBELOW", (0, 0), (-1, 0), 0.7, INK),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8f9")]),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    for index, asset in enumerate(assets[:limit], start=1):
        reco = asset.get("recommendation") or {}
        action = (f"{reco.get('standard', '')} {reco.get('algorithm', '')}".strip()
                  if reco.get("standard") != "no change" else "no change")
        colour = STATUS_COLOUR.get(asset["quantum_status"], INK)
        rows.append([
            Paragraph(f'<font color="{_hex(colour)}"><b>{asset["score"]:.2f}</b></font>'
                      + (' <font color="#c0392b"><b>!</b></font>' if asset["hndl"] else ""),
                      st["cell"]),
            Paragraph(asset["name"], st["cell"]),
            Paragraph(f'<font size="7" color="{_hex(colour)}">'
                      f'{STATUS_LABEL.get(asset["quantum_status"], asset["quantum_status"])}</font>',
                      st["cell"]),
            Paragraph(asset["criticality"], st["cell"]),
            Paragraph(asset["confidence"], st["cell"]),
            Paragraph(asset["location"][:62], st["cellmono"]),
            Paragraph(action, st["cell"]),
        ])
        style.append(("LINEBEFORE", (0, index), (0, index), 2.2, colour))
    table = Table(rows, colWidths=[15 * mm, 25 * mm, 24 * mm, 14 * mm, 15 * mm, 45 * mm, 32 * mm],
                  repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(DIM)
    canvas.drawString(18 * mm, 9.5 * mm, "CBOM Compass — cryptographic inventory and "
                                         "post-quantum readiness")
    canvas.drawRightString(A4[0] - 18 * mm, 9.5 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build(report: dict, limit: int = 25, filters: str | None = None) -> bytes:
    """Render a scan report to PDF bytes."""
    st = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title="CBOM Compass — Cryptographic Risk Summary", author="CBOM Compass",
    )
    kpis, run, policy = report["kpis"], report["run"], report["policy"]
    assets = report["assets"]
    generated = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    # An upload or repo scan lives in a workspace directory whose name means
    # nothing to a reader; the label records what was actually scanned.
    scope = run.get("label") or ", ".join(run.get("target_scope", []))[:180] or "unspecified"

    story = [
        Paragraph("Cryptographic Risk Summary", st["title"]),
        Paragraph(f"Scan <b>{run['scan_id']}</b> &nbsp;·&nbsp; generated {generated} "
                  f"&nbsp;·&nbsp; sources: {', '.join(run.get('sources_covered', [])) or 'none'}"
                  + (f" &nbsp;·&nbsp; filtered: {filters}" if filters else ""),
                  st["subtitle"]),
        _kpi_table(kpis, st),
        Spacer(1, 4 * mm),
        Paragraph(
            f"Scope: <font face='Courier' size='8'>{scope}</font>", st["note"]),
    ]

    # --- the two clocks -------------------------------------------------
    z_sensitive = kpis.get("z_sensitive", 0)
    pinned = kpis["total_assets"] - z_sensitive
    story += [
        Paragraph("Basis for these numbers", st["h2"]),
        Paragraph(
            f"Assets are scored against two independent clocks. The <b>quantum</b> clock uses "
            f"Mosca's inequality with a quantum-arrival estimate of <b>Z = {policy['z_year']}</b>, "
            f"which is an input set by the risk owner and not a prediction this tool makes. The "
            f"<b>regulatory</b> clock uses NIST IR 8547, under which RSA and elliptic-curve "
            f"cryptography are deprecated after 2030 and disallowed after 2035; those dates are "
            f"fixed and do not depend on any Q-Day estimate.", st["body"]),
        Paragraph(
            f"Of {kpis['total_assets']} assets, <b>{z_sensitive}</b> have scores that move if Z "
            f"changes. The remaining <b>{pinned}</b> are pinned by the regulatory deadline or by "
            f"an outright cryptographic break, and their priority is therefore independent of any "
            f"view about when quantum computers arrive.", st["body"]),
    ]

    story += [Paragraph("Risk distribution", st["h2"]), _heat_table(report["heat_map"], st)]
    story += [
        Paragraph("Migration priority", st["h2"]),
        Paragraph(f"The {min(limit, len(assets))} highest-scoring assets, ordered by "
                  f"Mosca exposure and regulatory deadline weighted by business criticality. "
                  f"A <b>!</b> marks data whose confidentiality requirement outlives the "
                  f"estimated time to a quantum computer, so recorded traffic is exposed today.",
                  st["note"]),
        Spacer(1, 2 * mm),
        _priority_table(assets, st, limit),
    ]

    # --- assumptions and limits ----------------------------------------
    assumed = sum(1 for a in assets if a.get("mosca") and a["mosca"]["x_source"] == "assumed")
    low_confidence = sum(1 for a in assets if a["confidence"] == "low")
    errors = report.get("errors", [])
    story += [PageBreak(), Paragraph("Assumptions and limitations", st["h2"])]
    story.append(Paragraph(
        f"<b>Untagged business inputs.</b> {assumed} of {kpis['total_assets']} assets were scored "
        f"using a default data lifetime because the owning service carries no data-classification "
        f"tag. No scanner can determine how long data must stay confidential; that is a business "
        f"fact. Tagging those services will change their scores.", st["body"]))
    story.append(Paragraph(
        f"<b>Detection confidence.</b> {low_confidence} findings are low confidence, meaning the "
        f"evidence establishes that an algorithm is present but not that the code path is reached. "
        f"Findings are labelled individually rather than presented as uniformly certain.",
        st["body"]))
    story.append(Paragraph(
        "<b>What static analysis cannot see.</b> Algorithms selected at runtime from "
        "configuration, key sizes read from variables, and indirect API resolution are not "
        "detected. Measured recall against the project's labelled corpus is published with the "
        "source; this report does not claim completeness.", st["body"]))
    story.append(Paragraph(
        "<b>Symmetric cryptography.</b> AES-128 and SHA-256 are reported as adequate. Grover's "
        "algorithm gives only a quadratic speedup, requires infeasible sequential quantum "
        "computation, and parallelises poorly; NIST defines its own post-quantum security "
        "categories using these algorithms as reference points. Where a compliance regime requires "
        "AES-256 or SHA-384 that is reported as a policy obligation, not as a cryptographic "
        "weakness.", st["body"]))
    if errors:
        story.append(Paragraph(
            f"<b>Incomplete coverage.</b> {len(errors)} scanner error(s) occurred; the affected "
            f"sources are not represented in the counts above.", st["body"]))
        for err in errors[:6]:
            story.append(Paragraph(
                f"— [{err['source_type']}] {err['target']}: {err['message'][:170]}", st["note"]))

    story.append(Paragraph("Standard conformance", st["h2"]))
    story.append(Paragraph(
        "The full inventory is exportable as a CycloneDX 1.7 Cryptography Bill of Materials, "
        "ratified as ECMA-424 2nd Edition, suitable for submission as regulatory evidence. This "
        "PDF is a summary of that inventory, not a replacement for it.", st["body"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
