"""Orchestration, KPI reconciliation, drift, and recommendations."""

from cbom_compass.engine import diff, run_scan
from cbom_compass.policy import Policy

APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"


def scan(**targets):
    return run_scan(targets or {"source": [APP], "dependencies": [APP]}, Policy.load(POLICY))


def test_kpis_reconcile_with_the_inventory():
    """The failure this guards is a demo-stage one: the Overview total not
    matching the number of rows in the Inventory Explorer."""
    report = scan()
    kpis = report.kpis()
    assert kpis["total_assets"] == len(report.priority_list())
    assert kpis["total_assets"] == len(report.inventory.assets)
    assert sum(kpis["by_status"].values()) == kpis["total_assets"]
    assert sum(kpis["by_confidence"].values()) == kpis["total_assets"]
    assert sum(kpis["by_urgency"].values()) == kpis["total_assets"]
    assert kpis["raw_findings"] - kpis["collapsed_by_dedup"] == kpis["total_assets"]


def test_heat_map_totals_match_asset_count():
    report = scan()
    total = sum(v for row in report.heat_map().values() for v in row.values())
    assert total == report.kpis()["total_assets"]


def test_a_failing_scanner_does_not_block_the_others():
    report = run_scan(
        {"source": [APP], "tls": ["blocked.example.com:443"]}, Policy.load(POLICY))
    assert report.inventory.assets
    assert any("refused" in e.message for e in report.errors)
    assert "source" in report.run.sources_covered


def test_priority_order_is_descending_and_deterministic():
    scores = [r["score"] for r in scan().priority_list()]
    assert scores == sorted(scores, reverse=True)
    assert [r["id"] for r in scan().priority_list()] == [r["id"] for r in scan().priority_list()]


def test_recommendations_name_specific_standards():
    rows = {r["name"]: r["recommendation"] for r in scan().priority_list()}
    assert rows["RSA-2048"]["standard"] == "FIPS 203"
    assert rows["RSA-2048"]["hybrid"] is True
    assert rows["ECDSA-secp256r1"]["standard"] == "FIPS 204"
    assert rows["MD5"]["algorithm"] == "SHA-256"


def test_adequate_symmetric_gets_no_change_by_default():
    """The corrected classification must not generate migration noise."""
    rows = {r["name"]: r["recommendation"] for r in scan().priority_list()}
    assert rows["SHA-256"]["standard"] == "no change"
    assert rows["AES-GCM"]["standard"] == "no change"


def test_cnsa_regime_changes_parameter_sets():
    policy = Policy.load(POLICY)
    policy.cnsa2_required = True
    report = run_scan({"source": [APP]}, policy)
    rows = {r["name"]: r["recommendation"] for r in report.priority_list()}
    assert rows["RSA-2048"]["algorithm"] == "ML-KEM-1024"
    assert rows["SHA-256"]["algorithm"] == "SHA-384"


def test_drift_detects_added_and_changed():
    first = scan().to_dict()
    second = run_scan(
        {"source": [APP], "dependencies": [APP], "container": ["samples/vulnerable-image"]},
        Policy.load(POLICY)).to_dict()
    d = diff(first, second)
    assert d["summary"]["added"] > 0
    assert d["summary"]["removed"] == 0


def test_drift_detects_score_changes_when_z_moves():
    policy = Policy.load(POLICY)
    before = run_scan({"source": [APP]}, policy).to_dict()
    policy.z_year = 2050
    after = run_scan({"source": [APP]}, policy).to_dict()
    d = diff(before, after)
    assert d["summary"]["changed"] > 0
    assert any("score" in c["changes"] for c in d["changed"])


# ---------------------------------------------------------------------------
# The offline demo path
# ---------------------------------------------------------------------------
def test_demo_seeds_two_scans_across_many_sources_without_a_network(tmp_path):
    """Scanning something live in front of an audience depends on venue wifi.

    This path has to be offline and repeatable, and it has to leave two scans
    behind so the drift view shows a real diff instead of an empty state.
    """
    from cbom_compass.cli import main
    from cbom_compass.store import Store

    db = tmp_path / "demo.db"
    assert main(["--db", str(db), "demo", "--no-serve", "--reset"]) == 0

    scans = Store(db).list_scans()
    assert len(scans) == 2

    newest = Store(db).latest()
    covered = set(newest["run"]["sources_covered"])
    # Code alone would be a thin demo; the point is breadth across source types.
    assert {"source", "config", "dependencies", "container", "cloud"} <= covered
    assert newest["kpis"]["total_assets"] > 100
    assert newest["errors"] == []


def test_demo_is_repeatable(tmp_path):
    """Same inputs, same inventory — the numbers on the slides have to hold."""
    from cbom_compass.cli import main
    from cbom_compass.store import Store

    counts = []
    for name in ("one.db", "two.db"):
        db = tmp_path / name
        main(["--db", str(db), "demo", "--no-serve", "--reset"])
        counts.append(Store(db).latest()["kpis"]["total_assets"])
    assert counts[0] == counts[1]
