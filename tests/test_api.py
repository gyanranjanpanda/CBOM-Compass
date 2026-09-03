"""API surface, including the role gate on privileged settings."""

import pytest
from fastapi.testclient import TestClient

from cbom_compass.api import create_app
from cbom_compass.engine import run_scan
from cbom_compass.policy import Policy
from cbom_compass.store import Store

APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    report = run_scan({"source": [APP], "dependencies": [APP]}, Policy.load(POLICY))
    Store(db).save(report.to_dict())
    return TestClient(create_app(db, POLICY))


def test_report_endpoint(client):
    body = client.get("/api/report").json()
    assert body["kpis"]["total_assets"] > 0
    assert body["policy"]["z_year"] == 2031


def test_z_override_rescoring_does_not_rerun_scanners(client):
    base = client.get("/api/report").json()
    moved = client.get("/api/report?z=2050").json()
    assert base["kpis"]["total_assets"] == moved["kpis"]["total_assets"]
    assert moved["policy"]["z_year"] == 2050
    assert sum(a["score"] for a in moved["assets"]) < sum(a["score"] for a in base["assets"])


def test_z_sensitivity_is_reported(client):
    """The UI needs this to explain why a pinned score does not move."""
    kpis = client.get("/api/report").json()["kpis"]
    assert "z_sensitive" in kpis
    assert set(kpis["by_driver"]) <= {"mosca-urgency", "compliance", "baseline", "none"}


def test_pinned_assets_hold_when_z_moves(client):
    """An RSA key is on the regulator's calendar whatever anyone thinks of Q-Day."""
    near = client.get("/api/report?z=2029").json()
    far = client.get("/api/report?z=2050").json()
    pinned = {a["id"]: a["score"] for a in near["assets"]
              if a["mosca"] and a["mosca"]["driver"] == "compliance"}
    assert pinned
    for asset in far["assets"]:
        if asset["id"] in pinned:
            assert asset["score"] == pinned[asset["id"]]


def test_heatmap_and_graph(client):
    heat = client.get("/api/heatmap").json()
    assert sum(v for row in heat.values() for v in row.values()) > 0
    graph = client.get("/api/graph").json()
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source_id"] in ids and e["target_id"] in ids for e in graph["edges"])


def test_settings_are_risk_officer_only(client):
    assert client.put("/api/policy", json={"z_year": 2040},
                      headers={"x-role": "auditor"}).status_code == 403
    assert client.put("/api/policy", json={"z_year": 2040},
                      headers={"x-role": "engineer"}).status_code == 403
    assert client.put("/api/policy", json={"z_year": 2040},
                      headers={"x-role": "risk_officer"}).status_code == 200


def test_auditor_can_export_but_engineer_cannot(client):
    assert client.get("/api/export/csv", headers={"x-role": "auditor"}).status_code == 200
    assert client.get("/api/export/csv", headers={"x-role": "engineer"}).status_code == 403


def test_export_respects_filters(client):
    everything = client.get("/api/export/cbom", headers={"x-role": "auditor"}).json()
    filtered = client.get("/api/export/cbom?status=broken&criticality=high",
                          headers={"x-role": "auditor"}).json()
    assert 0 < len(filtered["components"]) < len(everything["components"])
    assert filtered["specVersion"] == "1.7"


def test_settings_changes_are_audit_logged(client):
    client.put("/api/policy", json={"z_year": 2044},
               headers={"x-role": "risk_officer", "x-user": "alice"})
    log = client.get("/api/audit", headers={"x-role": "risk_officer"}).json()
    entry = next(e for e in log if e["action"] == "settings.changed")
    assert entry["principal"] == "alice"
    assert "2044" in entry["detail"]


def test_exports_are_audit_logged(client):
    client.get("/api/export/cbom", headers={"x-role": "auditor", "x-user": "bob"})
    log = client.get("/api/audit", headers={"x-role": "risk_officer"}).json()
    assert any(e["action"] == "export" and e["principal"] == "bob" for e in log)


def test_validation_endpoint(client):
    body = client.get("/api/validate").json()
    assert body["valid"] is True
    assert body["spec_version"] == "1.7"


def test_dashboard_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "CBOM Compass" in response.text


def test_empty_store_returns_404(tmp_path):
    client = TestClient(create_app(tmp_path / "empty.db", POLICY))
    assert client.get("/api/report").status_code == 404


def test_graph_clusters_rather_than_truncating(client):
    """v1 dropped the long tail past a top-N cut, which made the graph lie about
    the inventory's shape. Every asset must still be represented."""
    graph = client.get("/api/graph?max_nodes=20").json()
    assert graph["represented"] == graph["total"]
    assert graph["clustered"] > 0
    assert len(graph["nodes"]) < graph["total"]


def test_cluster_nodes_carry_their_member_count(client):
    graph = client.get("/api/graph?max_nodes=20").json()
    clusters = [n for n in graph["nodes"] if n["cluster"]]
    assert clusters
    assert sum(c["count"] for c in clusters) == graph["clustered"]
    assert all("×" in c["label"] for c in clusters)


def test_clustered_edges_resolve_to_real_nodes(client):
    graph = client.get("/api/graph?max_nodes=20").json()
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source_id"] in ids and e["target_id"] in ids for e in graph["edges"])
    assert all(e["source_id"] != e["target_id"] for e in graph["edges"])


def test_clustering_can_be_disabled(client):
    graph = client.get("/api/graph?cluster=false").json()
    assert graph["clustered"] == 0
    assert all(not n["cluster"] for n in graph["nodes"])


def test_pdf_export_is_a_pdf_and_respects_filters(client):
    everything = client.get("/api/export/pdf", headers={"x-role": "auditor"})
    assert everything.status_code == 200
    assert everything.headers["content-type"] == "application/pdf"
    assert everything.content[:5] == b"%PDF-"
    filtered = client.get("/api/export/pdf?status=broken&criticality=high",
                          headers={"x-role": "auditor"})
    assert filtered.status_code == 200
    assert len(filtered.content) < len(everything.content)


def test_pdf_export_is_role_gated_and_logged(client):
    assert client.get("/api/export/pdf", headers={"x-role": "engineer"}).status_code == 403
    client.get("/api/export/pdf", headers={"x-role": "auditor", "x-user": "carol"})
    log = client.get("/api/audit", headers={"x-role": "risk_officer"}).json()
    assert any(e["action"] == "export" and "pdf" in e["detail"] for e in log)
