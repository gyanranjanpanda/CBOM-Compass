"""Hard cases beyond module-level constant folding.

`hard_dynamic.py` holds the cases we *can* now resolve: a name bound once at
module scope to a literal or to the default of an environment lookup. This file
holds the ones we still cannot, and they are labelled as expected findings so
the evaluator counts them as misses.

Keeping them here is the point. A corpus a scanner scores 100% on has stopped
measuring anything; the useful corpus always contains the next thing that does
not work yet.

Each case needs a different analysis we have not built:

  local_digest      intra-procedural dataflow — the binding is inside a
                    function, where a later branch could rebind it.
  branch_digest     path sensitivity — two values are genuinely reachable, so
                    an honest answer reports both, not one.
  caller_digest     cross-procedural analysis — the algorithm is chosen at the
                    call site and travels in as an argument. This is exactly
                    the gap the source scanner's docstring attributes to having
                    no semgrep integration.
"""
import hashlib
import os

LEGACY_MODE = os.environ.get("LEGACY") == "1"


def local_digest(blob):
    # Bound inside the function, not at module scope.
    algorithm = "sha1"
    return hashlib.new(algorithm, blob).hexdigest()


def branch_digest(blob):
    # Both branches are reachable; neither value is "the" answer.
    algorithm = "md5" if LEGACY_MODE else "sha256"
    return hashlib.new(algorithm, blob).hexdigest()


def caller_digest(blob, algorithm):
    # The name arrives as a parameter.
    return hashlib.new(algorithm, blob).hexdigest()


def legacy_checksum(blob):
    return caller_digest(blob, "md5")
