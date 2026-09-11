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


def test_every_remaining_miss_is_a_documented_dynamic_case():
    """Recall is below 100% only because of cases we have labelled as
    unresolvable by static analysis. If a miss appears outside hard_dynamic.py,
    it is a regression, not a known limit."""
    ev = evaluate()
    for key, _ in ev.algorithm.false_negatives:
        assert "hard_dynamic" in key.path, f"unexpected miss: {key.path} {key.render()}"


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
