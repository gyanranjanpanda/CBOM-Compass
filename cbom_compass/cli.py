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
from .engine import PATH_SCANNERS
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
    paths = list(args.path)
    label = ""
    if getattr(args, "repo", None):
        from .ingest import IngestError, ingest_repo
        try:
            source = ingest_repo(args.repo)
        except IngestError as exc:
            print(f"{RED}{exc}{RST}", file=sys.stderr)
            return 2
        print(f"{DIM}cloned {source.label} — {source.file_count} files "
              f"into {source.root}{RST}")
        paths.append(str(source.root))
        label = source.label
    if paths:
        for name in PATH_SCANNERS:
            targets[name] = list(paths)
    if args.container:
        targets["container"] = list(args.container)
    if args.tls:
        targets["tls"] = list(args.tls)
    if args.ssh:
        targets["ssh"] = list(args.ssh)
    if args.cloud:
        targets["cloud"] = list(args.cloud)
    if not targets:
        print("nothing to scan — pass a path, --repo, --container, --tls, "
              "--ssh or --cloud", file=sys.stderr)
        return 2

    report = run_scan(targets, policy, initiated_by=args.user, label=label)
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


# What the gate blocks on. Shor-broken and classically-broken are the defaults
# because they are the two that are not a matter of opinion; deprecated is
# opt-in, since a team mid-migration will legitimately carry some.
BLOCKING = ("broken", "broken_classical")
DEPRECATED = "deprecated_insufficient"


def _status_counts(document: dict, statuses: list[str]) -> dict[str, int]:
    counts = dict.fromkeys(statuses, 0)
    for row in document.get("assets", []):
        status = row.get("quantum_status")
        if status in counts:
            counts[status] += 1
    return counts


def _gate_markdown(passed: bool, statuses: list[str], before: dict, after: dict,
                   introduced: list[dict], allowance: int) -> str:
    verdict = "✅ **passed**" if passed else "❌ **failed**"
    lines = [f"## CBOM Compass crypto gate — {verdict}", ""]
    total_before, total_after = sum(before.values()), sum(after.values())
    lines += [
        f"Blocking statuses: `{'`, `'.join(statuses)}`"
        + (f" · allowance {allowance}" if allowance else ""), "",
        "| | base | this change | delta |",
        "|---|---:|---:|---:|",
    ]
    for status in statuses:
        delta = after[status] - before[status]
        lines.append(f"| {status.replace('_', ' ')} | {before[status]} | "
                     f"{after[status]} | {delta:+d} |")
    lines.append(f"| **total** | **{total_before}** | **{total_after}** | "
                 f"**{total_after - total_before:+d}** |")

    if introduced:
        lines += ["", "### New findings at these locations", "",
                  "| score | asset | status | location |", "|---:|---|---|---|"]
        for row in introduced[:20]:
            lines.append(f"| {row['score']:.2f} | `{row['name']}` | "
                         f"{row['quantum_status'].replace('_', ' ')} | "
                         f"`{row['location']}` |")
        if len(introduced) > 20:
            lines.append(f"| | _+{len(introduced) - 20} more_ | | |")
    if not passed:
        lines += ["", "This change increases the amount of cryptography a quantum "
                      "computer breaks. Replace the algorithms above, or record a "
                      "deliberate exception, before merging."]
    return "\n".join(lines) + "\n"


def _repo_relative(paths: list[str]) -> list[str] | None:
    """Express the gated paths relative to the repository root.

    The baseline has to cover the *same* subtree as the change, or the two
    counts are not comparable and the gate silently passes everything. Gating
    `cbom_compass` against a baseline of the whole repository is not a
    comparison, it is a coin toss.
    """
    import subprocess

    done = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        return None
    root = Path(done.stdout.strip()).resolve()
    relative: list[str] = []
    for raw in paths:
        try:
            relative.append(str(Path(raw).resolve().relative_to(root)))
        except ValueError:
            return None          # outside the repository; cannot map it
    return relative


MAX_GATE_FILES = 20_000


def _materialise_tracked(paths: list[str], dest: Path) -> bool:
    """Copy the files git knows about into `dest`, preserving layout.

    Used for the *current* side of a `--baseline-ref` comparison so both sides
    see the same population. Without it the working tree is scanned as-is,
    including everything `.gitignore` excludes — build output, vendored
    dependencies, scan workspaces — while the baseline, coming from a git
    revision, contains none of it. Every one of those files then reads as newly
    introduced cryptography and the gate fails a commit that changed nothing.

    `-c` is tracked files and `-o --exclude-standard` is untracked-but-not-
    ignored, so genuinely new work still counts.
    """
    import shutil
    import subprocess

    done = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z", "--", *paths],
        capture_output=True, text=True)
    if done.returncode != 0:
        return False
    names = [n for n in done.stdout.split("\0") if n]
    if len(names) > MAX_GATE_FILES:
        print(f"{YEL}{len(names)} files — gating the working tree directly{RST}",
              file=sys.stderr)
        return False
    for name in names:
        source = Path(name)
        if not source.is_file():
            continue
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(source, target)
        except OSError:
            continue
    return True


def _scan_git_ref(ref: str, paths: list[str], policy, user: str) -> dict | None:
    """Scan a git revision without disturbing the working tree.

    `git archive` rather than a worktree or a checkout, because this also runs
    from a pre-commit hook where touching the index or the working directory
    would be unforgivable. The tar is extracted with the `data` filter, which
    refuses absolute paths, traversal and device nodes.
    """
    import subprocess
    import tarfile
    import tempfile

    relative = _repo_relative(paths)
    if relative is None:
        print(f"{YEL}--baseline-ref needs paths inside the git repository{RST}",
              file=sys.stderr)
        return None

    with tempfile.TemporaryDirectory(prefix="cbom-baseline-") as tmp:
        archive = Path(tmp) / "ref.tar"
        tree = Path(tmp) / "tree"
        tree.mkdir()
        done = subprocess.run(
            ["git", "archive", "--format=tar", "-o", str(archive), ref],
            capture_output=True, text=True)
        if done.returncode != 0:
            print(f"{YEL}could not read git revision {ref!r}: "
                  f"{done.stderr.strip()}{RST}", file=sys.stderr)
            return None
        with tarfile.open(archive) as bundle:
            bundle.extractall(tree, filter="data")

        # A path that does not exist at the base revision is new, so everything
        # under it is a new finding — which is exactly what should be reported.
        present = [str(tree / rel) for rel in relative
                   if rel == "." or (tree / rel).exists()]
        if not present:
            present = [str(tree)] if "." in relative else []
        if not present:
            return run_scan({}, policy, initiated_by=user,
                            label=f"baseline {ref}").to_dict()
        targets = {name: list(present) for name in PATH_SCANNERS}
        return run_scan(targets, policy, initiated_by=user,
                        label=f"baseline {ref}").to_dict()


def cmd_gate(args: argparse.Namespace) -> int:
    """Fail a change that introduces new quantum-broken cryptography.

    Deliberately compares *counts by status*, not per-location asset ids.
    Identity includes the file and line, so renaming a module or moving a
    function would otherwise register as a fresh finding and fail a build that
    changed no cryptography at all. A gate that cries wolf on refactors is a
    gate somebody switches off within a week.

    The rule is "do not make it worse", not "be clean". Blocking on pre-existing
    debt makes the check unadoptable for exactly the large old estates that need
    it most; this lets them hold the line while they migrate.
    """
    statuses = list(BLOCKING) + ([DEPRECATED] if args.include_deprecated else [])
    policy = Policy.load(args.policy)

    import tempfile

    with tempfile.TemporaryDirectory(prefix="cbom-current-") as staging:
        scan_paths = list(args.path)
        if args.baseline_ref:
            # Match the baseline's population; see `_materialise_tracked`.
            tree = Path(staging) / "tree"
            tree.mkdir()
            if _materialise_tracked(scan_paths, tree):
                relative = _repo_relative(scan_paths) or []
                scan_paths = [str(tree / rel) for rel in relative
                              if rel == "." or (tree / rel).exists()] or [str(tree)]
        targets = {name: list(scan_paths) for name in PATH_SCANNERS}
        current = run_scan(targets, policy, initiated_by=args.user,
                           label="crypto gate").to_dict()
    after = _status_counts(current, statuses)

    baseline = None
    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path is not None and baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"{RED}baseline is not valid JSON: {exc}{RST}", file=sys.stderr)
            return 2
    elif args.baseline_ref:
        baseline = _scan_git_ref(args.baseline_ref, list(args.path),
                                 policy, args.user)

    if baseline is None:
        print(f"{YEL}no baseline to compare against{RST} — reporting only.")
        for status in statuses:
            print(f"  {after[status]:>4} {status.replace('_', ' ')}")
        print(f"{DIM}Write one with: cbom-compass scan <base> -o baseline.json "
              f"--format json, or pass --baseline-ref HEAD{RST}")
        if args.summary_file:
            Path(args.summary_file).write_text(_gate_markdown(
                True, statuses, dict.fromkeys(statuses, 0), after, [], args.allow))
        return 0

    before = _status_counts(baseline, statuses)

    drift = diff_reports(baseline, current)
    introduced = sorted(
        (row for row in drift["added"] if row["quantum_status"] in statuses),
        key=lambda r: -r["score"])

    added = sum(after.values()) - sum(before.values())
    passed = added <= args.allow

    print(f"\n{BOLD}CBOM Compass crypto gate{RST}")
    print(f"{DIM}blocking on: {', '.join(statuses)}"
          + (f" · allowance {args.allow}" if args.allow else "") + f"{RST}\n")
    print(f"  {'status':<24} {'base':>6} {'now':>6} {'delta':>7}")
    for status in statuses:
        delta = after[status] - before[status]
        colour = RED if delta > 0 else (GRN if delta < 0 else DIM)
        print(f"  {status.replace('_', ' '):<24} {before[status]:>6} "
              f"{after[status]:>6} {colour}{delta:>+7}{RST}")

    if introduced:
        print(f"\n{BOLD}New findings{RST}")
        for row in introduced[:15]:
            print(f"  {RED}+{RST} {row['score']:>5.2f} {row['name'][:22]:<22} "
                  f"{row['location'][:52]}")
        if len(introduced) > 15:
            print(f"  {DIM}+{len(introduced) - 15} more{RST}")

    if args.summary_file:
        Path(args.summary_file).write_text(
            _gate_markdown(passed, statuses, before, after, introduced, args.allow))

    if passed:
        print(f"\n{GRN}gate passed{RST} — this change adds no quantum-broken "
              f"cryptography.")
        return 0
    print(f"\n{RED}gate failed{RST} — this change adds {added} asset(s) that a "
          f"quantum computer breaks.", file=sys.stderr)
    return 1


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


DEMO_APP = "samples/vulnerable-app"
DEMO_POLICY = f"{DEMO_APP}/crypto-policy.yaml"


def cmd_demo(args: argparse.Namespace) -> int:
    """Seed a deterministic scan of the bundled sample estate, then serve it.

    Built because the alternative is scanning something live in front of an
    audience. Cloning a repository on stage depends on the venue's wifi, and a
    dashboard that opens on whatever happens to be in the database invites the
    question "is this real or canned?" at the worst possible moment.

    Everything here is offline and repeatable: the sample application, its
    deployment configuration, the container tree and two key-store exports that
    stand in for cloud KMS and a PKCS#11 HSM. Two scans are stored, so the drift
    view has a real diff rather than an empty state.
    """
    policy_path = args.policy or DEMO_POLICY
    if not Path(DEMO_APP).is_dir():
        print(f"{RED}{DEMO_APP} not found — run this from the repository root{RST}",
              file=sys.stderr)
        return 2

    store = Store(args.db)
    if args.reset:
        for suffix in ("", "-wal", "-shm"):
            Path(str(args.db) + suffix).unlink(missing_ok=True)
        store = Store(args.db)

    policy = Policy.load(policy_path)

    print(f"{BOLD}Seeding the demo estate{RST} {DIM}(offline, no network){RST}")
    first = run_scan({"source": [DEMO_APP], "dependencies": [DEMO_APP]}, policy,
                     initiated_by="demo", label="payments-platform (code only)")
    store.save(first.to_dict())
    print(f"  {DIM}scan 1 of 2 — code and dependencies: "
          f"{first.kpis()['total_assets']} assets{RST}")

    targets = {
        "source": [DEMO_APP],
        "config": [DEMO_APP],
        "dependencies": [DEMO_APP],
        "binary": [DEMO_APP],
        "container": ["samples/vulnerable-image"],
        "cloud": ["file://samples/keystore-export.json",
                  "file://samples/hsm-export.json"],
    }
    second = run_scan(targets, policy, initiated_by="demo",
                      label="payments-platform (full estate)")
    store.save(second.to_dict())
    _print_report(second, args.limit)

    drift = diff_reports(first.to_dict(), second.to_dict())
    s = drift["summary"]
    print(f"\n{CYA}drift between the two scans: +{s['added']} new, "
          f"~{s['changed']} changed, -{s['removed']} removed{RST}")

    if not args.serve:
        return 0
    args.policy = policy_path
    return cmd_serve(args)


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
    p.add_argument("--repo", default=None,
                   help="public repository to clone and scan, e.g. github.com/psf/requests")
    p.add_argument("--container", action="append", default=[], help="image ref, tarball, or extracted dir")
    p.add_argument("--tls", action="append", default=[],
                   help="TLS host:port (must be in the policy allowlist)")
    p.add_argument("--ssh", action="append", default=[],
                   help="SSH host:port, default port 22 (must be in the policy allowlist)")
    p.add_argument("--cloud", action="append", default=[],
                   help="key store: aws://<region>, azure://<vault>, "
                        "gcp://<project>/<location>, pkcs11://<module.so>, "
                        "or file://<export.json>")
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

    p = sub.add_parser(
        "gate", help="fail a change that introduces new quantum-broken cryptography")
    p.add_argument("path", nargs="+", help="the tree to check, usually .")
    p.add_argument("--baseline", default=None,
                   help="JSON report of the base revision "
                        "(cbom-compass scan <base> -o baseline.json --format json)")
    p.add_argument("--baseline-ref", default=None, metavar="REF",
                   help="scan this git revision as the baseline instead, without "
                        "touching the working tree (e.g. HEAD, origin/main)")
    p.add_argument("--policy", default=None, help="crypto-policy.yaml")
    p.add_argument("--include-deprecated", action="store_true",
                   help="also block on deprecated / insufficient algorithms")
    p.add_argument("--allow", type=int, default=0, metavar="N",
                   help="tolerate up to N newly introduced assets (default 0)")
    p.add_argument("--summary-file", default=None,
                   help="write a markdown summary here, e.g. $GITHUB_STEP_SUMMARY")
    p.set_defaults(func=cmd_gate)

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

    p = sub.add_parser(
        "demo", help="seed a repeatable offline scan of the sample estate and serve it")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--policy", default=None)
    p.add_argument("--limit", type=int, default=12, help="rows in the priority table")
    p.add_argument("--reset", action="store_true",
                   help="delete the store first, so the demo is identical every time")
    p.add_argument("--no-serve", dest="serve", action="store_false",
                   help="seed the store but do not start the dashboard")
    p.set_defaults(func=cmd_demo, serve=True)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
