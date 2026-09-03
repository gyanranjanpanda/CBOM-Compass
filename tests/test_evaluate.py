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


def test_corpus_covers_every_supported_language():
    ev = evaluate()
    assert set(ev.per_language) == {"python", "java", "js", "go"}
