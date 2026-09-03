"""HTTP API and dashboard host — PRD v1.1 sections 7 and 8.

Role gating (section 5/10) is enforced here rather than in the UI: `Z`, the
criticality weights and the scan allowlist change every score in the system, so
they are risk_officer-only, and every settings change and export is written to
the audit log.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               Response)
from fastapi.staticfiles import StaticFiles

from . import cbom as cbom_mod
from . import recommend, risk
from .engine import ScanReport, diff, run_scan
from .inventory import Inventory
from .models import Asset, ScanRun
from .policy import Policy
from .store import DEFAULT_DB, Store

WEB_DIR = Path(__file__).parent / "web"

# Demo role model. Real deployments bind these to an identity provider; the
# point here is that the privileged operations are actually gated, not that this
# is a production auth system.
ROLES = {
    "engineer": {"read", "scan", "tag"},
    "risk_officer": {"read", "scan", "tag", "settings", "export"},
    "auditor": {"read", "export"},
}


def _require(role: str, permission: str) -> None:
    if permission not in ROLES.get(role, set()):
        raise HTTPException(
            403,
            f"role '{role}' cannot '{permission}'. Z, criticality weights and the scan "
            f"allowlist are risk_officer-only because they change every score in the system.",
        )


def create_app(db_path: str | Path = DEFAULT_DB,
               policy_path: str | None = None) -> FastAPI:
    app = FastAPI(title="CBOM Compass", version="0.1.0")
    store = Store(db_path)
    state: dict[str, Any] = {"policy": Policy.load(policy_path), "policy_path": policy_path}

    def current_report() -> dict:
        document = store.latest()
        if not document:
            raise HTTPException(404, "no scans yet — run a scan first")
        return document

    def rescore(document: dict, policy: Policy) -> dict:
        """Recompute risk and recommendations for a stored scan under a new policy.

        This is what the Z-slider calls. It never re-runs the scanners, so the
        dashboard recomputes in milliseconds and the inventory stays fixed while
        only the scoring moves.
        """
        assets = [Asset.from_row(row) for row in document["assets"]]
        from .models import Relationship
        relationships = [
            Relationship(r["source_id"], r["target_id"], r["kind"])
            for r in document.get("relationships", [])
        ]
        risks = risk.classify_all(assets, policy)
        recos = recommend.recommend_all(assets, risks, relationships, policy)
        run = ScanRun(**document["run"])
        report = ScanReport(
            run=run,
            inventory=Inventory(assets, relationships,
                                merged_count=document["kpis"]["collapsed_by_dedup"]),
            risks=risks, recommendations=recos, policy=policy,
            raw_asset_count=document["kpis"]["raw_findings"],
        )
        return report.to_dict()

    def report_for(z: int | None = None, scan: str | None = None) -> dict:
        """Plain function behind /api/report.

        Route handlers must never call one another directly: FastAPI's defaults
        are `Query`/`Header` objects, not the values they describe, so an
        internal call would pass a `Query` where an int is expected.
        """
        document = store.get(scan) if scan else current_report()
        if not document:
            raise HTTPException(404, "scan not found")
        if z and z != document["policy"]["z_year"]:
            adjusted = Policy.load(state["policy_path"])
            adjusted.z_year = int(z)
            adjusted.cnsa2_required = state["policy"].cnsa2_required
            return rescore(document, adjusted)
        return document

    # ----------------------------------------------------------- dashboard
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    # ---------------------------------------------------------------- data
    @app.get("/api/report")
    def get_report(z: int | None = Query(None, description="override quantum-arrival year"),
                   scan: str | None = None) -> dict:
        return report_for(z, scan)

    @app.get("/api/scans")
    def list_scans() -> list[dict]:
        return store.list_scans()

    @app.post("/api/scan")
    def post_scan(body: dict = Body(...),
                  x_role: str = Header("engineer"),
                  x_user: str = Header("demo")) -> dict:
        _require(x_role, "scan")
        targets: dict[str, list[str]] = {}
        for path in body.get("paths", []):
            for name in ("source", "dependencies", "binary"):
                targets.setdefault(name, []).append(path)
        if body.get("containers"):
            targets["container"] = body["containers"]
        if body.get("endpoints"):
            targets["tls"] = body["endpoints"]
        if not targets:
            raise HTTPException(400, "provide at least one of paths, containers, endpoints")
        report = run_scan(targets, state["policy"], initiated_by=x_user)
        document = report.to_dict()
        store.save(document)
        return document

    @app.get("/api/heatmap")
    def get_heatmap(z: int | None = None) -> dict:
        return report_for(z)["heat_map"]

    @app.get("/api/graph")
    def get_graph(z: int | None = None, max_nodes: int = 140,
                  cluster: bool = True) -> dict:
        """Asset graph for the blast-radius view.

        v1 truncated to the top N by score, which silently dropped the long tail
        and made the graph lie about the estimate's shape. This clusters instead:
        nodes that matter individually stay individual, and the rest collapse
        into one node per (algorithm, status, source) group carrying a count, so
        every asset is still represented. PRD sections 8.2 and 14.
        """
        document = report_for(z)
        rows = document["assets"]
        edges_in = document.get("relationships", [])

        degree: dict[str, int] = {}
        for edge in edges_in:
            degree[edge["source_id"]] = degree.get(edge["source_id"], 0) + 1
            degree[edge["target_id"]] = degree.get(edge["target_id"], 0) + 1

        def node_of(row: dict) -> dict:
            return {"id": row["id"], "label": row["name"], "status": row["quantum_status"],
                    "score": row["score"], "type": row["asset_type"],
                    "criticality": row["criticality"], "location": row["location"],
                    "degree": degree.get(row["id"], 0), "cluster": False, "count": 1}

        if not cluster or len(rows) <= max_nodes:
            nodes = [node_of(r) for r in rows]
            keep = {n["id"] for n in nodes}
            edges = [e for e in edges_in
                     if e["source_id"] in keep and e["target_id"] in keep]
            return {"nodes": nodes, "edges": edges, "clustered": 0,
                    "total": len(rows), "represented": len(rows)}

        # An asset earns its own node by mattering on its own: a real score, or a
        # position in the graph that other assets depend on.
        def significant(row: dict) -> bool:
            return row["score"] >= 0.30 or degree.get(row["id"], 0) >= 2

        individual = [r for r in rows if significant(r)][:max_nodes]
        individual_ids = {r["id"] for r in individual}
        remainder = [r for r in rows if r["id"] not in individual_ids]

        groups: dict[tuple, list[dict]] = {}
        for row in remainder:
            source = row["source_types"][0] if row["source_types"] else "unknown"
            groups.setdefault((row["algorithm"], row["quantum_status"], source), []).append(row)

        member_to_cluster: dict[str, str] = {}
        cluster_nodes = []
        for (algorithm, status, source), members in sorted(groups.items()):
            cluster_id = f"cluster:{algorithm}:{status}:{source}"
            for member in members:
                member_to_cluster[member["id"]] = cluster_id
            cluster_nodes.append({
                "id": cluster_id,
                "label": f"{algorithm} ×{len(members)}",
                "status": status,
                "score": max(m["score"] for m in members),
                "type": "cluster",
                "criticality": max((m["criticality"] for m in members),
                                   key=lambda c: {"low": 0, "medium": 1, "high": 2}[c]),
                "location": f"{len(members)} assets from {source}",
                "degree": 0,
                "cluster": True,
                "count": len(members),
                "algorithm": algorithm,
            })

        nodes = [node_of(r) for r in individual] + cluster_nodes
        valid = {n["id"] for n in nodes}

        seen: set[tuple[str, str, str]] = set()
        edges = []
        for edge in edges_in:
            src = member_to_cluster.get(edge["source_id"], edge["source_id"])
            tgt = member_to_cluster.get(edge["target_id"], edge["target_id"])
            if src == tgt or src not in valid or tgt not in valid:
                continue
            triple = (src, tgt, edge["kind"])
            if triple in seen:
                continue
            seen.add(triple)
            edges.append({"source_id": src, "target_id": tgt, "kind": edge["kind"]})

        for edge in edges:
            for endpoint in (edge["source_id"], edge["target_id"]):
                for node in nodes:
                    if node["id"] == endpoint:
                        node["degree"] += 1
                        break

        return {"nodes": nodes, "edges": edges, "clustered": len(remainder),
                "total": len(rows),
                "represented": len(individual) + sum(c["count"] for c in cluster_nodes)}

    @app.get("/api/drift")
    def get_drift(scan: str | None = None) -> dict:
        document = store.get(scan) if scan else current_report()
        previous = store.previous(document["run"]["scan_id"])
        if not previous:
            return {"summary": {"added": 0, "changed": 0, "removed": 0},
                    "added": [], "changed": [], "removed": [],
                    "note": "first scan — nothing to diff against"}
        return diff(previous, document)

    # ------------------------------------------------------------ settings
    @app.get("/api/policy")
    def get_policy() -> dict:
        policy: Policy = state["policy"]
        return {
            "z_year": policy.z_year, "urgency_scale": policy.urgency_scale,
            "cnsa2_required": policy.cnsa2_required,
            "criticality_weights": policy.criticality_weights,
            "hndl_multiplier": policy.hndl_multiplier,
            "scan_allowlist": policy.scan_allowlist,
            "authorization_attestation": policy.authorization_attestation,
            "services": [
                {"name": s.name, "paths": s.paths, "data_class": s.data_class,
                 "criticality": s.criticality.value, "surface": s.surface}
                for s in policy.services
            ],
        }

    @app.put("/api/policy")
    def put_policy(body: dict = Body(...),
                   x_role: str = Header("engineer"),
                   x_user: str = Header("demo")) -> dict:
        _require(x_role, "settings")
        policy: Policy = state["policy"]
        changes = []
        if "z_year" in body:
            changes.append(f"z_year {policy.z_year} -> {body['z_year']}")
            policy.z_year = int(body["z_year"])
        if "cnsa2_required" in body:
            changes.append(f"cnsa2_required -> {body['cnsa2_required']}")
            policy.cnsa2_required = bool(body["cnsa2_required"])
        if "urgency_scale" in body:
            policy.urgency_scale = float(body["urgency_scale"])
            changes.append(f"urgency_scale -> {policy.urgency_scale}")
        if "criticality_weights" in body:
            policy.criticality_weights.update(body["criticality_weights"])
            changes.append("criticality_weights updated")
        store.audit(x_user, "settings.changed", "; ".join(changes))
        return get_policy()

    # -------------------------------------------------------------- export
    @app.get("/api/export/cbom")
    def export_cbom(scan: str | None = None, z: int | None = None,
                    status: str | None = None, criticality: str | None = None,
                    x_role: str = Header("auditor"),
                    x_user: str = Header("demo")) -> JSONResponse:
        """Exports respect the current filters, so a risk officer can export
        exactly 'red and high criticality' (PRD section 8.2)."""
        _require(x_role, "export")
        document = report_for(z, scan)
        rows = document["assets"]
        if status:
            wanted = set(status.split(","))
            rows = [r for r in rows if r["quantum_status"] in wanted]
        if criticality:
            wanted = set(criticality.split(","))
            rows = [r for r in rows if r["criticality"] in wanted]

        from .models import Relationship
        assets = [Asset.from_row(r) for r in rows]
        keep = {a.id for a in assets}
        relationships = [
            Relationship(r["source_id"], r["target_id"], r["kind"])
            for r in document.get("relationships", [])
            if r["source_id"] in keep and r["target_id"] in keep
        ]
        policy = Policy.load(state["policy_path"])
        policy.z_year = z or document["policy"]["z_year"]
        risks = risk.classify_all(assets, policy)
        recos = recommend.recommend_all(assets, risks, relationships, policy)
        payload = cbom_mod.build(assets, relationships, risks, recos,
                                 document["run"]["target_scope"])
        store.audit(x_user, "export",
                    f"cbom: {len(assets)} components "
                    f"(filters status={status or '*'} criticality={criticality or '*'})")
        return JSONResponse(payload, headers={
            "Content-Disposition": 'attachment; filename="cbom.json"'})

    @app.get("/api/export/csv", response_class=PlainTextResponse)
    def export_csv(scan: str | None = None, z: int | None = None,
                   x_role: str = Header("auditor"),
                   x_user: str = Header("demo")) -> PlainTextResponse:
        _require(x_role, "export")
        import csv
        import io
        document = report_for(z, scan)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["score", "asset", "algorithm", "key_size", "quantum_status",
                         "criticality", "urgency", "confidence", "hndl", "location",
                         "sources", "recommendation", "hybrid"])
        for row in document["assets"]:
            rec = row.get("recommendation") or {}
            writer.writerow([
                row["score"], row["name"], row["algorithm"], row["key_size"] or "",
                row["quantum_status"], row["criticality"], row["urgency_band"],
                row["confidence"], row["hndl"], row["location"],
                ";".join(row["source_types"]),
                f"{rec.get('standard', '')} {rec.get('algorithm', '')}".strip(),
                rec.get("hybrid", ""),
            ])
        store.audit(x_user, "export", f"csv: {len(document['assets'])} rows")
        return PlainTextResponse(buffer.getvalue(), headers={
            "Content-Disposition": 'attachment; filename="cbom-compass.csv"'})

    @app.get("/api/export/pdf")
    def export_pdf(scan: str | None = None, z: int | None = None,
                   status: str | None = None, criticality: str | None = None,
                   limit: int = 25,
                   x_role: str = Header("auditor"),
                   x_user: str = Header("demo")) -> Response:
        """Board and compliance summary. Filter-scoped like the other exports."""
        _require(x_role, "export")
        from . import report_pdf

        document = report_for(z, scan)
        rows = document["assets"]
        descriptors = []
        if status:
            wanted = set(status.split(","))
            rows = [r for r in rows if r["quantum_status"] in wanted]
            descriptors.append(f"status={status}")
        if criticality:
            wanted = set(criticality.split(","))
            rows = [r for r in rows if r["criticality"] in wanted]
            descriptors.append(f"criticality={criticality}")
        scoped = {**document, "assets": rows}
        payload = report_pdf.build(scoped, limit=limit,
                                   filters=", ".join(descriptors) or None)
        store.audit(x_user, "export",
                    f"pdf: {len(rows)} assets "
                    f"(filters {', '.join(descriptors) or 'none'})")
        return Response(payload, media_type="application/pdf", headers={
            "Content-Disposition": 'attachment; filename="cbom-compass-risk-summary.pdf"'})

    @app.get("/api/validate")
    def validate_cbom(scan: str | None = None) -> dict:
        document = report_for(None, scan)
        assets = [Asset.from_row(r) for r in document["assets"]]
        from .models import Relationship
        relationships = [
            Relationship(r["source_id"], r["target_id"], r["kind"])
            for r in document.get("relationships", [])
        ]
        policy = Policy.load(state["policy_path"])
        policy.z_year = document["policy"]["z_year"]
        risks = risk.classify_all(assets, policy)
        payload = cbom_mod.build(assets, relationships, risks, {},
                                 document["run"]["target_scope"])
        errors = cbom_mod.validate(payload)
        return {"spec_version": payload["specVersion"], "components": len(payload["components"]),
                "valid": not errors, "errors": errors}

    @app.get("/api/audit")
    def audit_log(x_role: str = Header("risk_officer")) -> list[dict]:
        _require(x_role, "settings")
        return store.audit_log()

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app


app = create_app()
