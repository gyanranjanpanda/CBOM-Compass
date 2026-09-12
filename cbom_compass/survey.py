"""Scan many projects and aggregate the result — PRD v1.1 section 13, at scale.

Two purposes, and the second is the one that matters.

The first is operational: "how do we run this across five hundred repositories?"
is the question every organisation asks after the first demo, and an answer that
is "write a shell loop" is not an answer. A survey isolates each project so one
unclonable repository or one pathological file does not lose the whole run, and
rolls the results up into numbers a programme manager can act on.

The second is evidential. Our accuracy corpus is 94 usages we wrote ourselves,
and a corpus written by the same people who wrote the scanner can only ever
prove internal consistency. Pointing the tool at real, unmodified, widely
depended-on code is the only way to find out what it does outside its own
assumptions — and the aggregate is a finding in its own right: how much of the
software everyone actually installs is carrying cryptography a quantum computer
breaks.

Nothing here is a per-project judgement. A project appearing in these results is
not insecure today; RSA and ECDSA are correct engineering decisions right now.
The point is the size of the migration nobody has started.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .engine import PATH_SCANNERS, run_scan
from .knowledge.algorithms import PQC
from .policy import Policy

BROKEN_STATUSES = ("broken", "broken_classical")


@dataclass
class ProjectResult:
    """One project's contribution to the survey."""

    label: str
    ok: bool = True
    error: str | None = None
    files: int = 0
    assets: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    hndl: int = 0
    pqc_algorithms: list[str] = field(default_factory=list)
    broken_algorithms: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def broken(self) -> int:
        return sum(self.by_status.get(s, 0) for s in BROKEN_STATUSES)

    def to_dict(self) -> dict:
        return {
            "label": self.label, "ok": self.ok, "error": self.error,
            "files": self.files, "assets": self.assets,
            "by_status": self.by_status, "broken": self.broken,
            "hndl": self.hndl, "pqc_algorithms": self.pqc_algorithms,
            "broken_algorithms": self.broken_algorithms,
            "sources": self.sources, "seconds": round(self.seconds, 2),
        }


@dataclass
class Survey:
    projects: list[ProjectResult] = field(default_factory=list)

    @property
    def scanned(self) -> list[ProjectResult]:
        return [p for p in self.projects if p.ok]

    @property
    def failed(self) -> list[ProjectResult]:
        return [p for p in self.projects if not p.ok]

    def rollup(self) -> dict:
        done = self.scanned
        if not done:
            return {"projects": 0, "failed": len(self.failed)}

        broken_counts = [p.broken for p in done]
        with_broken = [p for p in done if p.broken]
        with_hndl = [p for p in done if p.hndl]
        with_pqc = [p for p in done if p.pqc_algorithms]

        # How many *projects* contain each algorithm, not how many call sites.
        # A project with two hundred RSA call sites and one with a single call
        # are both one organisation with an RSA migration to plan.
        algorithm_reach: Counter[str] = Counter()
        for project in done:
            algorithm_reach.update(set(project.broken_algorithms))
        pqc_reach: Counter[str] = Counter()
        for project in done:
            pqc_reach.update(set(project.pqc_algorithms))

        return {
            "projects": len(done),
            "failed": len(self.failed),
            "total_assets": sum(p.assets for p in done),
            "total_broken": sum(broken_counts),
            "projects_with_broken": len(with_broken),
            "share_with_broken": round(len(with_broken) / len(done), 4),
            "projects_with_hndl": len(with_hndl),
            "share_with_hndl": round(len(with_hndl) / len(done), 4),
            "projects_with_pqc": len(with_pqc),
            "share_with_pqc": round(len(with_pqc) / len(done), 4),
            "median_broken": statistics.median(broken_counts),
            "mean_broken": round(statistics.fmean(broken_counts), 1),
            "max_broken": max(broken_counts),
            "algorithm_reach": algorithm_reach.most_common(),
            "pqc_reach": pqc_reach.most_common(),
            "seconds": round(sum(p.seconds for p in done), 1),
        }

    def to_dict(self) -> dict:
        return {"rollup": self.rollup(),
                "projects": [p.to_dict() for p in self.projects]}


def _summarise(label: str, report, files: int, seconds: float) -> ProjectResult:
    kpis = report.kpis()
    broken, pqc = [], []
    for row in report.priority_list():
        if row["quantum_status"] in BROKEN_STATUSES:
            broken.append(row["algorithm"])
        if row["algorithm"] in PQC:
            pqc.append(row["algorithm"])
    return ProjectResult(
        label=label, ok=True, files=files,
        assets=kpis["total_assets"], by_status=kpis["by_status"],
        hndl=kpis["hndl_flagged"],
        pqc_algorithms=sorted(set(pqc)),
        broken_algorithms=sorted(set(broken)),
        sources=kpis["sources_covered"], seconds=seconds,
    )


def scan_one(target: str, policy: Policy, workspace: Path | str | None = None,
             timeout: int = 180) -> ProjectResult:
    """Scan one project, converting every failure into a recorded result.

    A survey that aborts on the first unreachable repository is not a survey.
    Failures are counted and named in the output rather than silently reducing
    the denominator, because "we scanned 40 of 50 and here are the 10 we could
    not" is a finding too.
    """
    from .ingest import IngestError, ingest_repo

    started = time.time()
    local = Path(target)
    try:
        if local.exists():
            root, label, files = local, str(local), sum(
                1 for p in local.rglob("*") if p.is_file())
        else:
            source = ingest_repo(target, workspace, timeout=timeout)
            root, label, files = source.root, source.label, source.file_count
    except IngestError as exc:
        return ProjectResult(label=target, ok=False, error=str(exc),
                             seconds=time.time() - started)
    except Exception as exc:                      # never lose the rest of the run
        return ProjectResult(label=target, ok=False,
                             error=f"{type(exc).__name__}: {exc}",
                             seconds=time.time() - started)

    try:
        targets = {name: [str(root)] for name in PATH_SCANNERS}
        report = run_scan(targets, policy, initiated_by="survey", label=label)
    except Exception as exc:
        return ProjectResult(label=label, ok=False,
                             error=f"scan failed: {type(exc).__name__}: {exc}",
                             files=files, seconds=time.time() - started)
    return _summarise(label, report, files, time.time() - started)


def read_targets(path: str | Path) -> list[str]:
    """One project per line. `#` comments and blank lines ignored."""
    lines = Path(path).read_text().splitlines()
    return [line.strip() for line in lines
            if line.strip() and not line.strip().startswith("#")]


# ----------------------------------------------------------------- reporting
def _share(value: float) -> str:
    return f"{value * 100:.0f}%"


def format_report(survey: Survey) -> str:
    r = survey.rollup()
    if not r.get("projects"):
        return "no projects scanned"
    out = [
        "",
        f"CBOM Compass — ecosystem survey",
        f"  {r['projects']} projects scanned"
        + (f", {r['failed']} could not be scanned" if r["failed"] else "")
        + f" · {r['total_assets']} assets · {r['seconds']}s",
        "",
        f"  {_share(r['share_with_broken']):>5} of projects contain cryptography a "
        f"quantum computer breaks  ({r['projects_with_broken']}/{r['projects']})",
        f"  {_share(r['share_with_hndl']):>5} contain at least one asset flagged "
        f"harvest-now-decrypt-later",
        f"  {_share(r['share_with_pqc']):>5} contain any post-quantum algorithm at "
        f"all  ({r['projects_with_pqc']}/{r['projects']})",
        "",
        f"  broken assets per project — median {r['median_broken']:g}, "
        f"mean {r['mean_broken']}, worst {r['max_broken']}",
        "",
        "  how many projects contain each broken algorithm",
    ]
    for algorithm, count in r["algorithm_reach"][:12]:
        bar = "█" * round(20 * count / r["projects"])
        out.append(f"    {algorithm:<12} {count:>3}/{r['projects']:<3} {bar}")
    if r["pqc_reach"]:
        out += ["", "  post-quantum algorithms already present"]
        for algorithm, count in r["pqc_reach"]:
            out.append(f"    {algorithm:<12} {count:>3} project(s)")
    if survey.failed:
        out += ["", "  not scanned"]
        for project in survey.failed:
            out.append(f"    {project.label:<40} {project.error}")
    return "\n".join(out) + "\n"


def markdown(survey: Survey) -> str:
    r = survey.rollup()
    if not r.get("projects"):
        return "# Ecosystem survey\n\nNo projects scanned.\n"
    lines = [
        "# What the software everyone installs is actually using",
        "",
        f"`cbom-compass survey` over **{r['projects']} widely depended-on open-source "
        f"projects**, unmodified, at their default branch.",
        "",
        "| | |",
        "|---|---|",
        f"| Projects scanned | {r['projects']}"
        + (f" ({r['failed']} could not be cloned)" if r["failed"] else "") + " |",
        f"| Cryptographic assets found | {r['total_assets']} |",
        f"| **Contain cryptography a quantum computer breaks** | "
        f"**{_share(r['share_with_broken'])}** "
        f"({r['projects_with_broken']}/{r['projects']}) |",
        f"| Contain harvest-now-decrypt-later exposure | "
        f"{_share(r['share_with_hndl'])} |",
        f"| **Contain any post-quantum algorithm** | "
        f"**{_share(r['share_with_pqc'])}** "
        f"({r['projects_with_pqc']}/{r['projects']}) |",
        f"| Broken assets per project | median {r['median_broken']:g}, "
        f"mean {r['mean_broken']}, worst {r['max_broken']} |",
        f"| Wall-clock time | {r['seconds']}s |",
        "",
        "## Reach, by algorithm",
        "",
        "How many *projects* contain each — not how many call sites. A project with "
        "two hundred RSA call sites and one with a single call are both one "
        "migration to plan.",
        "",
        "| Algorithm | Projects | Share |",
        "|---|---:|---:|",
    ]
    for algorithm, count in r["algorithm_reach"]:
        lines.append(f"| {algorithm} | {count} | {_share(count / r['projects'])} |")

    lines += ["", "## Post-quantum adoption", ""]
    if r["pqc_reach"]:
        lines += ["| Algorithm | Projects |", "|---|---:|"]
        for algorithm, count in r["pqc_reach"]:
            lines.append(f"| {algorithm} | {count} |")
    else:
        lines.append("Not one project in this sample contained a post-quantum "
                     "algorithm.")

    lines += [
        "",
        "## What this is not",
        "",
        "This is not a judgement on any project here. RSA and ECDSA are correct "
        "engineering decisions today, and every maintainer in this list is doing "
        "nothing wrong. The finding is the *size* of a migration that has barely "
        "started: the algorithms above are in the dependency tree of most software "
        "in production, and NIST IR 8547 disallows them after 2035.",
        "",
        "It is also a sample, not a census. The projects were chosen for reach "
        "across seven languages, not at random, so treat the percentages as "
        "indicative of well-maintained popular code — which, if anything, is the "
        "optimistic end of the distribution.",
        "",
        "## Reproducing it",
        "",
        "```bash",
        "cbom-compass survey tools/survey/targets.txt --report docs/ecosystem-survey.md",
        "```",
        "",
        "## Per project",
        "",
        "| Project | Assets | Broken | HNDL | PQC |",
        "|---|---:|---:|---:|---|",
    ]
    for project in sorted(survey.scanned, key=lambda p: -p.broken):
        pqc = ", ".join(project.pqc_algorithms) or "—"
        lines.append(f"| {project.label} | {project.assets} | {project.broken} | "
                     f"{project.hndl} | {pqc} |")
    if survey.failed:
        lines += ["", "### Not scanned", "", "| Project | Reason |", "|---|---|"]
        for project in survey.failed:
            lines.append(f"| {project.label} | {project.error} |")
    return "\n".join(lines) + "\n"
