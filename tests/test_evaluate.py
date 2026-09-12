"""Accuracy regression floor.

The corpus exists so the §13 success metrics are measurable rather than
aspirational. These thresholds are floors, not targets — raise them when the
scanner improves, and never lower them to make a build pass.
"""

from cbom_compass.evaluate import evaluate

MIN_ALGORITHM_PRECISION = 1.00
MIN_ALGORITHM_RECALL = 0.95
MIN_STRICT_PRECISION = 0.95
MIN_STRICT_RECALL = 0.90


def test_algorithm_level_accuracy():
    ev = evaluate()
    assert ev.algorithm.precision >= MIN_ALGORITHM_PRECISION
    assert ev.algorithm.recall >= MIN_ALGORITHM_RECALL


def test_strict_accuracy_including_key_sizes_modes_and_curves():
    ev = evaluate()
    assert ev.strict.precision >= MIN_STRICT_PRECISION
    assert ev.strict.recall >= MIN_STRICT_RECALL


def test_negative_controls_produce_nothing():
    """Files that mention cryptography in prose and identifiers only. This is
    what separates a scanner from a keyword grep."""
    ev = evaluate()
    assert ev.negative_control_findings == 0
    assert ev.negative_controls >= 4


# Corpus files that hold cases we have not built the analysis for yet. Every
# miss must live in one of these; a miss anywhere else is a regression, not a
# known limit.
HARD_CASE_FILES = ("hard_dataflow",)


def test_every_remaining_miss_is_a_documented_hard_case():
    ev = evaluate()
    for key, _ in ev.algorithm.false_negatives:
        assert any(h in key.path for h in HARD_CASE_FILES), \
            f"unexpected miss: {key.path} {key.render()}"


def test_constant_folding_resolves_the_cases_it_claims_to():
    """`hard_dynamic.py` used to be misses end to end.

    Module-level constant folding closed all of them — an algorithm named by a
    module constant, a key size behind an environment default, and `getattr`
    with a literal attribute. Locking that in here means the capability cannot
    quietly regress into "documented limitation" again.
    """
    ev = evaluate()
    stale = [k.render() for k, _ in ev.algorithm.false_negatives
             if "hard_dynamic" in k.path]
    assert stale == [], f"constant folding regressed: {stale}"


def test_resolved_values_declare_where_they_came_from():
    """An environment default is a real finding, but a conditional one.

    It is what runs unless the deployment overrides it, so it is reported at
    medium confidence and the evidence says so. Asserting the note here keeps
    the honesty from being a comment nobody checks.
    """
    from cbom_compass.models import Confidence
    from cbom_compass.scanners.source import SourceScanner

    assets = SourceScanner().scan("corpus/python/hard_dynamic.py").assets
    by_algorithm = {a.algorithm: a for a in assets}

    md5 = by_algorithm["MD5"]
    assert md5.confidence is Confidence.MEDIUM
    assert "environment variable" in md5.evidence[0].detail["resolved_from"]

    rsa = by_algorithm["RSA"]
    assert rsa.key_size == 1024
    assert "environment variable" in rsa.evidence[0].detail["key_size_resolved_from"]

    # `getattr(hashlib, "sha1")` is indirection in spelling only — the attribute
    # is a literal, so it is exactly as certain as writing hashlib.sha1.
    sha1 = by_algorithm["SHA-1"]
    assert sha1.confidence is Confidence.HIGH
    assert "getattr" in sha1.evidence[0].detail["resolved_from"]


# Which corpus directory holds the ground truth for each rule family. Adding a
# language to the scanner without adding one here makes the test below fail,
# which is the point: an unmeasured language is an unsupported language.
CORPUS_FOR_SUFFIX = {
    ".py": "python", ".java": "java", ".js": "js", ".go": "go",
    ".c": "c", ".cs": "csharp", ".rs": "rust",
}


def test_corpus_covers_every_supported_language():
    """A language the scanner claims to support must have measured accuracy.

    Derived from the scanner's own rule table rather than hard-coded, so adding
    a language without labelling a corpus for it fails here instead of shipping
    an unmeasured claim.
    """
    from cbom_compass.scanners.source import PATTERN_RULES

    # Several suffixes share one rule list (.ts reuses .js, .hpp reuses .c).
    # Collapse them so each distinct family is required once.
    families = {id(rules) for rules in PATTERN_RULES.values()}
    representative = {}
    for suffix, rules in PATTERN_RULES.items():
        representative.setdefault(id(rules), suffix)
    assert len(families) == len(representative)

    required = {CORPUS_FOR_SUFFIX[suffix] for suffix in representative.values()
                if suffix in CORPUS_FOR_SUFFIX}
    required.add("python")                  # AST-based, not in PATTERN_RULES

    ev = evaluate()
    missing = required - set(ev.per_language)
    assert not missing, f"no labelled corpus for: {sorted(missing)}"


def test_every_supported_suffix_maps_to_a_corpus():
    """The mapping above must not fall behind the scanner's suffix list."""
    from cbom_compass.scanners.source import PATTERN_RULES

    representative = {}
    for suffix, rules in PATTERN_RULES.items():
        representative.setdefault(id(rules), suffix)
    unmapped = set(representative.values()) - set(CORPUS_FOR_SUFFIX)
    assert not unmapped, f"rule family with no corpus mapping: {sorted(unmapped)}"
