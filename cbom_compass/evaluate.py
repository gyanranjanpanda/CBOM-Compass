"""Accuracy measurement against the labelled corpus — PRD v1.1 section 13.

The PRD's original success metric was "% of an organisation's cryptographic
surface scanned", which has no knowable denominator: you cannot measure what you
never found. This replaces it with precision and recall against ground truth
that was labelled by hand from the source, not generated from scanner output.

Two metric sets are reported, because they answer different questions:

    strict     every labelled attribute (key size, mode, curve) must match
    algorithm  (file, algorithm) only — did we notice the usage at all

The gap between them is the cost of imperfect attribute extraction, and it is
worth seeing separately from the cost of missing a usage entirely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .knowledge.algorithms import normalise
from .scanners.source import SourceScanner

DEFAULT_CORPUS = Path("corpus")
ATTRIBUTES = ("key_size", "mode", "curve")


@dataclass(frozen=True)
class Key:
    """A finding or label reduced to what we compare on."""

    path: str
    algorithm: str
    key_size: int | None = None
    mode: str | None = None
    curve: str | None = None

    def algorithm_only(self) -> "Key":
        return Key(self.path, self.algorithm)

    def matches(self, label: "Key") -> bool:
        """A label attribute set to None is a wildcard."""
        if self.path != label.path or self.algorithm != label.algorithm:
            return False
        return all(
            getattr(label, attr) is None or getattr(self, attr) == getattr(label, attr)
            for attr in ATTRIBUTES
        )

    def render(self) -> str:
        bits = [self.algorithm]
        if self.key_size:
            bits.append(str(self.key_size))
        if self.mode:
            bits.append(self.mode)
        if self.curve:
            bits.append(self.curve)
        return "-".join(bits)


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    false_positives: list[Key] = field(default_factory=list)
    false_negatives: list[tuple[Key, str]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class Evaluation:
    strict: Metrics
    algorithm: Metrics
    per_language: dict[str, Metrics]
    label_count: int
    finding_count: int
    negative_controls: int
    negative_control_findings: int


def _finding_keys(path: str, root: Path) -> set[Key]:
    """Scanner output for one file, reduced to comparable keys.

    Duplicates collapse: a scanner reporting the same algorithm at three call
    sites in one file is not three chances to be wrong.
    """
    result = SourceScanner().scan(str(root / path))
    keys = set()
    for asset in result.assets:
        mode = asset.parameters.get("mode")
        curve = asset.parameters.get("curve")
        keys.add(Key(
            path=path,
            algorithm=normalise(asset.algorithm),
            key_size=asset.key_size,
            mode=mode.upper() if mode else None,
            curve=curve.lower() if curve else None,
        ))
    return keys


def _label_keys(path: str, entries: list[dict]) -> list[tuple[Key, str]]:
    """Labels identical after wildcarding collapse to one.

    Findings are deduped per file, so two identical labels could never both
    be matched and would understate recall for no real reason.
    """
    out = []
    seen: set[Key] = set()
    for entry in entries:
        mode = entry.get("mode")
        curve = entry.get("curve")
        out.append((
            Key(path=path, algorithm=normalise(entry["algorithm"]),
                key_size=entry.get("key_size"),
                mode=mode.upper() if mode else None,
                curve=curve.lower() if curve else None),
            entry.get("note", ""),
        ))
    deduped = []
    for key, note in out:
        if key not in seen:
            seen.add(key)
            deduped.append((key, note))
    return deduped


def _score(findings: set[Key], labels: list[tuple[Key, str]], strict: bool) -> Metrics:
    metrics = Metrics()
    if strict:
        remaining = list(labels)
        unmatched = set(findings)
        for label, note in labels:
            hit = next((f for f in unmatched if f.matches(label)), None)
            if hit is not None:
                metrics.tp += 1
                unmatched.discard(hit)
                remaining = [(l, n) for l, n in remaining if l != label]
            else:
                metrics.fn += 1
                metrics.false_negatives.append((label, note))
        metrics.fp = len(unmatched)
        metrics.false_positives = sorted(unmatched, key=lambda k: (k.path, k.algorithm))
    else:
        found = {f.algorithm_only() for f in findings}
        wanted = {l.algorithm_only(): n for l, n in labels}
        metrics.tp = len(found & set(wanted))
        metrics.fn = len(set(wanted) - found)
        metrics.fp = len(found - set(wanted))
        metrics.false_negatives = [(k, wanted[k]) for k in sorted(
            set(wanted) - found, key=lambda k: (k.path, k.algorithm))]
        metrics.false_positives = sorted(found - set(wanted), key=lambda k: (k.path, k.algorithm))
    return metrics


def _merge(into: Metrics, other: Metrics) -> None:
    into.tp += other.tp
    into.fp += other.fp
    into.fn += other.fn
    into.false_positives.extend(other.false_positives)
    into.false_negatives.extend(other.false_negatives)


def evaluate(corpus: str | Path = DEFAULT_CORPUS) -> Evaluation:
    root = Path(corpus)
    spec = yaml.safe_load((root / "labels.yaml").read_text())

    strict = Metrics()
    algorithm = Metrics()
    per_language: dict[str, Metrics] = {}
    label_count = finding_count = negative_controls = negative_findings = 0

    for entry in spec["files"]:
        path = entry["path"]
        language = path.split("/")[0]
        labels = _label_keys(path, entry.get("expected") or [])
        findings = _finding_keys(path, root)
        label_count += len(labels)
        finding_count += len(findings)
        if not labels:
            negative_controls += 1
            negative_findings += len(findings)

        file_strict = _score(findings, labels, strict=True)
        file_algorithm = _score(findings, labels, strict=False)
        _merge(strict, file_strict)
        _merge(algorithm, file_algorithm)
        _merge(per_language.setdefault(language, Metrics()), file_algorithm)

    return Evaluation(strict, algorithm, per_language, label_count, finding_count,
                      negative_controls, negative_findings)


def format_report(ev: Evaluation) -> str:
    lines = [
        "",
        "CBOM Compass — source scanner accuracy",
        f"  corpus: {ev.label_count} hand-labelled usages · "
        f"{ev.finding_count} findings · {ev.negative_controls} negative controls",
        "",
        f"  {'metric set':<12} {'precision':>10} {'recall':>9} {'F1':>7}   "
        f"{'TP':>4} {'FP':>4} {'FN':>4}",
    ]
    for name, m in (("algorithm", ev.algorithm), ("strict", ev.strict)):
        lines.append(
            f"  {name:<12} {m.precision:>9.1%} {m.recall:>8.1%} {m.f1:>7.2f}   "
            f"{m.tp:>4} {m.fp:>4} {m.fn:>4}")
    lines += ["", "  by language (algorithm-level)"]
    for language, m in sorted(ev.per_language.items()):
        lines.append(
            f"    {language:<10} precision {m.precision:>6.1%}  recall {m.recall:>6.1%}  "
            f"({m.tp} TP, {m.fp} FP, {m.fn} FN)")

    lines += ["", f"  negative controls: {ev.negative_control_findings} finding(s) on "
                  f"{ev.negative_controls} files that should yield none"]

    if ev.algorithm.false_positives:
        lines += ["", "  false positives (algorithm-level)"]
        for key in ev.algorithm.false_positives:
            lines.append(f"    {key.path:<34} {key.render()}")
    if ev.algorithm.false_negatives:
        lines += ["", "  missed entirely (algorithm-level)"]
        for key, note in ev.algorithm.false_negatives:
            lines.append(f"    {key.path:<34} {key.render():<22} {note}")
    seen = {(k.path, k.algorithm) for k, _ in ev.algorithm.false_negatives}
    attribute_misses = [(k, n) for k, n in ev.strict.false_negatives
                        if (k.path, k.algorithm) not in seen]
    if attribute_misses:
        lines += ["", "  attribute mismatches (found the algorithm, got a detail wrong)"]
        for key, note in attribute_misses:
            lines.append(f"    {key.path:<34} expected {key.render():<22} {note}")
    strict_only_fp = [k for k in ev.strict.false_positives
                      if k.algorithm_only() not in
                      {f.algorithm_only() for f in ev.algorithm.false_positives}]
    if strict_only_fp:
        lines += ["", "  reported with wrong or missing attributes"]
        for key in strict_only_fp:
            lines.append(f"    {key.path:<34} reported {key.render()}")
    return "\n".join(lines) + "\n"
