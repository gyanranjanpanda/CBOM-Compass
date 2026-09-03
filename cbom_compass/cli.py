"""Command-line interface.

    cbom-compass scan ./repo --policy crypto-policy.yaml
    cbom-compass scan --container myimage:latest --tls localhost:8443
    cbom-compass export --format cbom -o cbom.json
    cbom-compass diff <old-scan-id> <new-scan-id>
    cbom-compass serve
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import cbom as cbom_mod
from .engine import diff as diff_reports
from .engine import run_scan
from .policy import Policy
from .store import DEFAULT_DB, Store

BOLD, DIM, RED, YEL, GRN, CYA, RST = (
    "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[0m")
STATUS_COLOUR = {
    "broken": RED, "broken_classical": RED, "deprecated_insufficient": YEL,
    "adequate": GRN, "not_applicable": DIM, "unknown": DIM,
}


def _print_report(report, limit: int) -> None:
    k = report.kpis()
    print(f"\n{BOLD}CBOM Compass — scan {report.run.scan_id}{RST}")
    print(f"{DIM}sources: {', '.join(k['sources_covered']) or 'none'} · "
          f"Z = {k['z_year']}{RST}\n")

    print(f"  {BOLD}{k['total_assets']}{RST} assets "
          f"{DIM}({k['raw_findings']} raw findings, {k['collapsed_by_dedup']} collapsed "
          f"by de-duplication){RST}")
    order = ["broken", "broken_classical", "deprecated_insufficient", "adequate",
             "not_applicable", "unknown"]
    for status in order:
        count = k["by_status"].get(status, 0)
        if count:
            print(f"    {STATUS_COLOUR[status]}{count:>4}{RST} {status.replace('_', ' ')}")
    print(f"\n  {k['hndl_flagged']:>4} flagged harvest-now-decrypt-later")
    print(f"  {k['nist_deprecated_2030']:>4} deprecated by NIST IR 8547 after 2030")
    print(f"  {k['nist_disallowed_2035']:>4} disallowed by NIST IR 8547 after 2035")

    print(f"\n{BOLD}Priority order{RST} {DIM}(Mosca exposure x criticality){RST}")
    print(f"  {'score':>5}  {'asset':<20} {'status':<22} {'crit':<7} {'conf':<7} location")
    for row in report.priority_list(limit):
        colour = STATUS_COLOUR.get(row["quantum_status"], "")
        flag = "!" if row["hndl"] else " "
        print(f"  {row['score']:>5.2f}{flag} {row['name'][:20]:<20} "
              f"{colour}{row['quantum_status']:<22}{RST} {row['criticality']:<7} "
              f"{row['confidence']:<7} {row['location'][:48]}")

    if report.errors:
        print(f"\n{YEL}{len(report.errors)} scanner error(s) — other sources unaffected:{RST}")
        for err in report.errors[:10]:
            print(f"  {DIM}[{err.source_type}]{RST} {err.target}: {err.message}")


def _write_csv(report, path: Path) -> None:
    fields = ["score", "name", "algorithm", "key_size", "quantum_status", "criticality",
              "urgency_band", "confidence", "hndl", "location", "source_types",
              "recommendation_standard", "recommendation_algorithm", "hybrid"]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report.priority_list():
            rec = row.get("recommendation") or {}
            writer.writerow({
                "score": row["score"], "name": row["name"], "algorithm": row["algorithm"],
                "key_size": row["key_size"] or "", "quantum_status": row["quantum_status"],
                "criticality": row["criticality"], "urgency_band": row["urgency_band"],
                "confidence": row["confidence"], "hndl": row["hndl"],
                "location": row["location"], "source_types": ";".join(row["source_types"]),
                "recommendation_standard": rec.get("standard", ""),
                "recommendation_algorithm": rec.get("algorithm", ""),
                "hybrid": rec.get("hybrid", ""),
            })


def cmd_scan(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    if args.z:
        policy.z_year = args.z
    targets: dict[str, list[str]] = {}
    if args.path:
        for name in ("source", "dependencies", "binary"):
            targets[name] = list(args.path)
    if args.container:
        targets["container"] = list(args.container)
    if args.tls:
        targets["tls"] = list(args.tls)
    if args.cloud:
        targets["cloud"] = list(args.cloud)
    if not targets:
        print("nothing to scan — pass a path, --container, or --tls", file=sys.stderr)
        return 2

    report = run_scan(targets, policy, initiated_by=args.user)
    _print_report(report, args.limit)

    store = Store(args.db)
    scan_id = store.save(report.to_dict())
    print(f"\n{DIM}saved as scan {scan_id} in {args.db}{RST}")

    previous = store.previous(scan_id)
    if previous:
        drift = diff_reports(previous, report.to_dict())
        s = drift["summary"]
        if any(s.values()):
            print(f"{CYA}drift vs previous scan: +{s['added']} new, "
                  f"~{s['changed']} changed, -{s['removed']} removed{RST}")

    if args.out:
        out = Path(args.out)
        if args.format == "cbom":
            document = report.cbom()
            out.write_text(json.dumps(document, indent=2))
            errors = cbom_mod.validate(document)
            status = f"{GRN}valid{RST}" if not errors else f"{RED}{len(errors)} error(s){RST}"
            print(f"CBOM (CycloneDX {document['specVersion']}) -> {out} [{status}]")
            for err in errors[:5]:
                print(f"  {RED}{err}{RST}")
        elif args.format == "csv":
            _write_csv(report, out)
            print(f"CSV -> {out}")
        elif args.format == "pdf":
            from . import report_pdf

            out.write_bytes(report_pdf.build(report.to_dict(), limit=args.limit or 25))
            print(f"PDF risk summary -> {out}")
        else:
            out.write_text(json.dumps(report.to_dict(), indent=2))
            print(f"JSON -> {out}")
        store.audit(args.user, "export", f"{args.format} -> {out} ({report.run.scan_id})")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    store = Store(args.db)
    document = store.get(args.scan) if args.scan else store.latest()
    if not document:
        print("no scans stored — run `cbom-compass scan` first", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.write_text(json.dumps(document, indent=2))
    store.audit(args.user, "export", f"{args.format} -> {out}")
    print(f"exported -> {out}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    store = Store(args.db)
    old, new = store.get(args.old), store.get(args.new)
    if not old or not new:
        print("scan id not found", file=sys.stderr)
        return 1
    drift = diff_reports(old, new)
    s = drift["summary"]
    print(f"{BOLD}drift{RST}  +{s['added']} new  ~{s['changed']} changed  -{s['removed']} removed")
    for row in drift["added"][:15]:
        print(f"  {GRN}+{RST} {row['score']:.2f} {row['name']:<18} {row['location']}")
    for row in drift["changed"][:15]:
        deltas = ", ".join(f"{f}: {d['from']} -> {d['to']}" for f, d in row["changes"].items())
        print(f"  {YEL}~{RST}      {row['name']:<18} {deltas}")
    for row in drift["removed"][:15]:
        print(f"  {RED}-{RST}      {row['name']:<18} {row['location']}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.file).read_text())
    errors = cbom_mod.validate(document)
    if errors:
        print(f"{RED}{len(errors)} conformance error(s):{RST}")
        for err in errors:
            print(f"  {err}")
        return 1
    print(f"{GRN}valid{RST} CycloneDX {document.get('specVersion')} CBOM — "
          f"{len(document.get('components', []))} components")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from .verify import summarise, verify

    store = Store(args.db)
    document = store.get(args.scan) if args.scan else store.latest()
    if not document:
        print("no scans stored — run `cbom-compass scan` first", file=sys.stderr)
        return 1
    roots = args.root or [t.split(":", 1)[1] for t in document["run"]["target_scope"]
                          if ":" in t]
    checks = verify(document, roots, sample=args.sample, seed=args.seed)

    print(f"\n{BOLD}Verifying {len(checks)} finding(s) against the files on disk{RST}")
    print(f"{DIM}Each line below was re-read from the artefact itself. Nothing is taken "
          f"from the scan except the location it claimed.{RST}\n")
    mark = {"confirmed": f"{GRN}PASS{RST}", "unconfirmed": f"{RED}FAIL{RST}",
            "unavailable": f"{DIM}n/a {RST}"}
    for check in checks:
        print(f"  {mark[check.verdict]}  {check.asset:<20} {DIM}{check.technique}{RST}")
        print(f"        {CYA}{check.detail}{RST}")
        if check.quoted:
            print(f"        {DIM}>{RST} {check.quoted}")
    s = summarise(checks)
    colour = GRN if s["unconfirmed"] == 0 else RED
    print(f"\n  {colour}{s['confirmed']}/{s['confirmed'] + s['unconfirmed']} "
          f"independently confirmed{RST}"
          + (f" {DIM}({s['unavailable']} not re-checkable offline){RST}"
             if s["unavailable"] else ""))
    return 1 if s["unconfirmed"] else 0


def cmd_eval(args: argparse.Namespace) -> int:
    from .evaluate import evaluate, format_report
    ev = evaluate(args.corpus)
    print(format_report(ev))
    if args.min_recall and ev.algorithm.recall < args.min_recall:
        print(f"{RED}algorithm-level recall {ev.algorithm.recall:.1%} is below the "
              f"{args.min_recall:.0%} floor{RST}", file=sys.stderr)
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .api import create_app
    app = create_app(db_path=args.db, policy_path=args.policy)
    print(f"{BOLD}CBOM Compass{RST} dashboard on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cbom-compass",
        description="Cryptographic inventory and post-quantum readiness platform")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="scan store (default cbom-compass.db)")
    parser.add_argument("--user", default="cli", help="principal recorded in the audit log")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan targets and score them")
    p.add_argument("path", nargs="*", help="repo / directory / file to scan")
    p.add_argument("--container", action="append", default=[], help="image ref, tarball, or extracted dir")
    p.add_argument("--tls", action="append", default=[], help="host:port (must be in the policy allowlist)")
    p.add_argument("--cloud", action="append", default=[],
                   help="key store: aws://<region> or file://<export.json>")
    p.add_argument("--policy", default=None, help="crypto-policy.yaml")
    p.add_argument("--z", type=int, default=None, help="override the quantum-arrival year")
    p.add_argument("-o", "--out", default=None, help="write report to file")
    p.add_argument("--format", choices=["cbom", "json", "csv", "pdf"], default="cbom")
    p.add_argument("--limit", type=int, default=20, help="rows in the priority table")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("export", help="export a stored scan")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--scan", default=None, help="scan id (default: latest)")
    p.add_argument("--format", choices=["cbom", "json", "csv"], default="json")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("diff", help="drift between two stored scans")
    p.add_argument("old")
    p.add_argument("new")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("validate", help="check a CBOM file for CycloneDX conformance")
    p.add_argument("file")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("verify",
                       help="re-read findings from disk to prove they are not fabricated")
    p.add_argument("--scan", default=None, help="scan id (default: latest)")
    p.add_argument("--root", action="append", default=[], help="where the scanned files live")
    p.add_argument("--sample", type=int, default=12, help="0 to check every finding")
    p.add_argument("--seed", type=int, default=None, help="fix the sample for a repeatable demo")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("eval", help="measure scanner accuracy against the labelled corpus")
    p.add_argument("--corpus", default="corpus")
    p.add_argument("--min-recall", type=float, default=None,
                   help="exit non-zero if algorithm-level recall falls below this")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("serve", help="run the dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--policy", default=None)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
