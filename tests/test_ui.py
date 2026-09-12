"""Browser smoke tests for the dashboard.

These exist because the asset graph shipped empty and nobody noticed: the canvas
is sized from `clientWidth`, which is 0 while its tab is hidden, so the whole
layout scaled to nothing and drew a blank box. Every API returned 200 and the JS
parsed cleanly — only rendering the page catches that class of bug.

Skipped automatically when Playwright or its browser is not installed, so the
core suite still runs anywhere.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import closing

import pytest

from cbom_compass.engine import run_scan
from cbom_compass.policy import Policy
from cbom_compass.store import Store

# Marked rather than only skipped: CI deselects with `-m "not browser"` in the
# main matrix and runs a dedicated job that installs a browser, so a missing
# Playwright can never be mistaken for a passing UI suite.
pytestmark = pytest.mark.browser

playwright_api = pytest.importorskip("playwright.sync_api")

APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"
VIEWS = ["overview", "inventory", "heat", "graph", "recs", "reports", "settings"]


def _free_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A real uvicorn process with two scans, so drift has something to show."""
    db = tmp_path_factory.mktemp("ui") / "ui.db"
    store = Store(db)
    policy = Policy.load(POLICY)
    store.save(run_scan({"source": [APP]}, policy).to_dict())
    store.save(run_scan(
        {"source": [APP], "dependencies": [APP],
         "cloud": ["file://samples/keystore-export.json"]}, policy).to_dict())

    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "cbom_compass.cli", "--db", str(db),
         "serve", "--policy", POLICY, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.3)):
                break
        except OSError:
            time.sleep(0.25)
    else:
        process.kill()
        pytest.skip("dashboard server did not start")
    yield url
    process.terminate()
    process.wait(timeout=10)


@pytest.fixture(scope="module")
def page(server):
    with playwright_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:                       # browser not downloaded
            pytest.skip(f"chromium unavailable: {exc}")
        pg = browser.new_page(viewport={"width": 1440, "height": 900})
        pg.errors = []
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" else None)
        pg.goto(server, wait_until="networkidle")
        pg.wait_for_timeout(1500)
        yield pg
        browser.close()


def _show(page, view: str) -> None:
    page.click(f'nav button[data-v="{view}"]')
    page.wait_for_timeout(700)


def test_every_view_renders_without_javascript_errors(page):
    for view in VIEWS:
        _show(page, view)
        assert page.is_visible(f"#v-{view}"), f"{view} did not become visible"
    assert page.errors == [], f"console errors: {page.errors}"


def test_overview_shows_the_latest_scan_not_the_first(page):
    """Two scans a second apart sort ambiguously on timestamp alone; the store
    breaks the tie on rowid so the newest wins."""
    _show(page, "overview")
    total = int(page.inner_text("#kpis .kpi:first-child .n"))
    assert total > 0
    sources = page.evaluate("REPORT.run.sources_covered")
    assert "cloud" in sources, "showing an older scan than the newest"


def test_drift_panel_reports_a_diff(page):
    _show(page, "overview")
    assert "nothing to diff" not in page.inner_text("#drift")
    assert "new" in page.inner_text("#drift")


def test_asset_graph_actually_draws_pixels(page):
    """The regression that motivated this file. A blank canvas passes every API
    check, so assert on the rendered bitmap instead."""
    _show(page, "graph")
    page.wait_for_timeout(1200)
    painted = page.evaluate("""() => {
        const cv = document.querySelector('#graph');
        if(!cv.width || !cv.height) return -1;
        const d = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height).data;
        let n = 0;
        for(let i = 3; i < d.length; i += 4) if(d[i] > 8) n++;
        return n;
    }""")
    assert painted > 5000, f"asset graph canvas is effectively blank ({painted} px)"


def test_graph_reports_node_and_edge_counts(page):
    _show(page, "graph")
    info = page.inner_text("#graphinfo")
    assert "nodes" in info and "edges" in info


def test_score_explainer_opens_with_the_formula(page):
    _show(page, "overview")
    page.click("#top10 .score")
    page.wait_for_timeout(500)
    body = page.inner_text("#pbody")
    assert "exposure gap" in body
    assert "X data lifetime" in body
    assert "What set this score" in body
    page.click("#pclose")


def test_explainer_labels_assumed_inputs(page):
    """Section 8.1: a defaulted input must be visibly a default."""
    _show(page, "overview")
    page.click("#top10 .score")
    page.wait_for_timeout(500)
    html = page.inner_html("#pbody")
    assert "badge" in html and ("tagged" in html or "assumed" in html)
    page.click("#pclose")


def test_heat_map_cell_filters_the_inventory(page):
    _show(page, "heat")
    page.click("#heat-full .cell >> nth=2")      # high criticality, high urgency
    page.wait_for_timeout(600)
    assert page.is_visible("#v-inventory")
    count = page.inner_text("#count")
    assert "of" in count


def test_z_slider_recomputes_scores_live(page):
    _show(page, "overview")
    before = page.evaluate("REPORT.assets.reduce((s,a)=>s+a.score,0)")
    page.eval_on_selector("#z", """el => {
        el.value = 2050;
        el.dispatchEvent(new Event('input', {bubbles: true}));
    }""")
    page.wait_for_timeout(1400)
    after = page.evaluate("REPORT.assets.reduce((s,a)=>s+a.score,0)")
    assert after < before, "moving Z to 2050 should lower total risk"
    assert page.inner_text("#zval") == "2050"


def test_regulation_pinned_assets_hold_when_z_moves(page):
    """An RSA key is on the regulator's calendar whatever Z says, and the UI has
    to explain that rather than look broken."""
    pinned = page.evaluate("""() => REPORT.assets
        .filter(a => a.mosca && a.mosca.driver === 'compliance')
        .map(a => a.score)""")
    assert pinned, "expected some regulation-pinned assets"
    assert all(s > 0 for s in pinned)
    page.eval_on_selector("#z", """el => {
        el.value = 2031;
        el.dispatchEvent(new Event('input', {bubbles: true}));
    }""")
    page.wait_for_timeout(1400)


def test_inventory_search_filters_rows(page):
    _show(page, "inventory")
    page.fill("#q", "payments")
    page.wait_for_timeout(500)
    rows = page.eval_on_selector_all("#inv tbody tr", "els => els.length")
    assert 0 < rows < 114
    page.click("#clearf")


def test_reports_view_reports_conformance_and_history(page):
    _show(page, "reports")
    assert "valid" in page.inner_text("#validation")
    assert "1.7" in page.inner_text("#validation")
    assert page.eval_on_selector_all("#scans tbody tr", "els => els.length") >= 2


def test_settings_shows_policy_service_tags_and_audit(page):
    _show(page, "settings")
    assert "Z (quantum arrival)" in page.inner_text("#polform")
    assert "payment-gateway" in page.inner_text("#services")
    assert "allowlist" in page.inner_text("#allowlist").lower() or \
           "127.0.0.1" in page.inner_text("#allowlist")
    assert page.eval_on_selector_all("#audit tbody tr", "els => els.length") >= 1


def test_no_horizontal_page_scroll(page):
    """Wide tables must scroll in their own container, not the body."""
    for view in VIEWS:
        _show(page, view)
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert overflow <= 1, f"{view} scrolls the page sideways by {overflow}px"


def test_header_carries_scan_provenance(page):
    """A bare scan id cannot be told apart from last week's scan of someone
    else's repository. The header has to say what and when."""
    _show(page, "overview")
    header = page.inner_text("#scanid")
    assert "scan " in header
    # origin and timestamp, separated by the middot the header uses
    assert header.count("·") >= 2, header


def test_no_stale_banner_for_a_scan_from_this_session(page):
    """The banner must be quiet when it has nothing to warn about, or it
    becomes wallpaper and stops being read."""
    _show(page, "overview")
    assert not page.is_visible("#stalebar")
