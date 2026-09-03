"""Risk engine — PRD v1.1 section 6.3.

The shape is deliberately multiplicative rather than a flat max across three
peers:

    vulnerability   1.0 broken · 0.8 deprecated · 0.3 policy-only · 0.0 adequate
    timing          max(mosca_urgency, compliance_deadline, TIMING_FLOOR)
    risk            vulnerability × timing × (0.6 + 0.4 × hndl)
    score           risk × criticality_weight

Timing modulates a real need to migrate; it never creates one. An earlier
version summed the axes with `max()`, which meant an already-migrated ML-KEM key
exchange scored 0.60 in a real scan of paramiko purely because the data it
protects is long-lived — precisely the false urgency this tool exists to avoid.
If there is nothing to migrate, no timeline makes it urgent.

The floor matters in the other direction: weak cryptography protecting
short-lived data still needs replacing, so timing never drops to zero.

One consequence is worth stating plainly: an RSA-2048 key carries a fixed NIST
IR 8547 deadline, so its score does *not* move when the Z slider moves. That is
correct — the regulator's date does not depend on anyone's Q-Day estimate — but
it would look like a broken slider if the UI stayed silent, so every
classification records which axis drove it (`driver`).

Mosca's inequality returns a boolean, and a boolean multiplied by a weight gives
two buckets rather than a ranking. We use the signed exposure gap instead, which
preserves *how badly* an asset fails the test:

    exposure_gap = (X + Y) - Z_years            # positive => already overdue
    urgency      = clamp(exposure_gap / URGENCY_SCALE, 0, 1)
    compliance   = 1.0 if disallowed_2035 else 0.6 if deprecated_2030 else 0.0
    quantum      = 1.0 if broken else 0.8 if deprecated_insufficient else 0.0
    risk         = max(urgency, compliance, quantum) * (0.6 + 0.4 * hndl)
    score        = risk * criticality_weight

max() rather than a sum: a Shor-broken asset is fully urgent regardless of how
its Mosca inputs land, and an asset facing a 2035 legal ban is urgent even if its
data lifetime is short. Summing would let a high score on one axis be diluted by
a low score on another.
"""

from __future__ import annotations

from datetime import date

from .knowledge import algorithms as kb
from .knowledge import mosca
from .models import Asset, AssetType, Criticality, QuantumStatus, RiskClassification
from .policy import Policy

# How badly does this asset need replacing at all? Nothing else matters if the
# answer is "not at all" — an already-migrated ML-KEM key exchange must score
# zero no matter how long its data must stay confidential.
VULNERABILITY = {
    QuantumStatus.BROKEN: 1.0,
    QuantumStatus.BROKEN_CLASSICAL: 1.0,
    QuantumStatus.DEPRECATED_INSUFFICIENT: 0.8,
    QuantumStatus.ADEQUATE: 0.0,
    QuantumStatus.UNKNOWN: 0.2,
    QuantumStatus.NOT_APPLICABLE: 0.0,
}

# An algorithm that is sound but outside a compliance regime the organisation is
# subject to still carries an obligation — a much smaller one than a break.
POLICY_ONLY_VULNERABILITY = 0.3

# Weak cryptography is worth replacing even when no clock is pressing, so the
# timing term never falls below this. Without a floor, a broken algorithm
# protecting short-lived data would score zero.
TIMING_FLOOR = 0.5

# NIST IR 8547 dates, and how far ahead a deadline starts exerting pressure.
# Compliance pressure rises as the date approaches rather than sitting at 1.0
# from the moment the rule is published: a flat 1.0 pinned every broken asset
# to the same score, which left Mosca unable to distinguish between them --
# and distinguishing between them is the entire point of Mosca.
NIST_DEPRECATED_YEAR = 2030
NIST_DISALLOWED_YEAR = 2035
COMPLIANCE_HORIZON = 10.0


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def classify_asset(asset: Asset, policy: Policy,
                   current_year: int | None = None) -> RiskClassification:
    current_year = current_year or date.today().year
    cls = kb.classify(asset.algorithm, asset.key_size, asset.parameters)

    non_security = asset.parameters.get("usedforsecurity") is False
    material = asset.parameters.get("material")
    is_library_row = (
        asset.asset_type == AssetType.RELATED_CRYPTO_MATERIAL
        and asset.library is not None and material is None
    )
    if is_library_row:
        cls.quantum_status = QuantumStatus.NOT_APPLICABLE
        cls.rationale = (
            f"Inventory entry for {asset.library} "
            f"{asset.library_version or '(version unresolved)'}. Risk is carried by the "
            f"algorithms it exposes, which are listed as separate assets."
        )

    tag = policy.tag_for(asset.primary_location, asset.service)
    data_class = tag.data_class if tag else None
    criticality = tag.criticality if tag else policy.default_criticality

    x, x_source = mosca.default_x(data_class)
    y, y_source = mosca.default_y(
        asset.asset_type.value, asset.location_class, tag.surface if tag else None
    )

    # Z is entered in the UI as a year; the inequality needs a duration.
    z_years = float(max(0, policy.z_year - current_year))
    exposure_gap = (x + y) - z_years
    urgency = _clamp(exposure_gap / policy.urgency_scale)

    flags = list(cls.regulatory_flags)
    deadlines = []
    if "nist8547_deprecated_2030" in flags:
        deadlines.append(NIST_DEPRECATED_YEAR)
    if "nist8547_disallowed_2035" in flags:
        deadlines.append(NIST_DISALLOWED_YEAR)
    if not deadlines:
        compliance = 0.0
    else:
        years_left = min(deadlines) - current_year
        compliance = 1.0 if years_left <= 0 else _clamp(
            (COMPLIANCE_HORIZON - years_left) / COMPLIANCE_HORIZON)
    if "classically_insufficient" in cls.advisories:
        compliance = 1.0        # already below acceptable strength: past due today

    vulnerability = VULNERABILITY[cls.quantum_status]
    if vulnerability == 0.0 and policy.cnsa2_required and "cnsa2_noncompliant" in flags:
        vulnerability = POLICY_ONLY_VULNERABILITY

    hndl_flag = mosca.hndl(data_class, x) and cls.quantum_status in {
        QuantumStatus.BROKEN, QuantumStatus.DEPRECATED_INSUFFICIENT
    }

    if material == "private-key":
        # A private key baked into an image layer is an incident regardless of
        # which algorithm it is. Only the container scanner finds these.
        vulnerability = 1.0
        compliance = max(compliance, 1.0)
        cls.advisories = list(cls.advisories) + ["embedded_key_material"]
        cls.rationale = (
            "Private key material embedded in a container image layer. Rotate the key and "
            "remove it from the build, independent of any PQC timeline."
        )

    if non_security:
        # Declared a checksum, not a security control. Still inventoried -- the
        # algorithm is genuinely present -- but it is not a finding to act on,
        # and scoring it would bury the ones that are.
        vulnerability = 0.0
        hndl_flag = False
        cls.rationale = (
            f"{cls.algorithm} called with usedforsecurity=False — declared a checksum "
            f"or cache key, not a security control. Inventoried for completeness; not "
            f"scored as a risk."
        )
        cls.advisories = list(cls.advisories) + ["declared_non_security"]

    if is_library_row:
        # An inventory-only row must score zero on every axis. Leaving it with a
        # Mosca urgency would double-count the library alongside each algorithm
        # it exposes, and inflate every KPI on the Overview.
        vulnerability = 0.0
        hndl_flag = False

    # Timing only modulates a real need to migrate; it never creates one.
    timing_axes = {"mosca-urgency": urgency, "compliance": compliance,
                   "baseline": TIMING_FLOOR}
    timing = max(timing_axes.values())
    driver = (max(timing_axes, key=lambda k: timing_axes[k])
              if vulnerability > 0 else "none")

    risk = vulnerability * timing * (
        (1.0 - policy.hndl_multiplier) + policy.hndl_multiplier * (1.0 if hndl_flag else 0.0)
    )
    weight = policy.weight(criticality)
    score = risk * weight

    return RiskClassification(
        asset_id=asset.id,
        quantum_status=cls.quantum_status,
        rationale=cls.rationale,
        hndl_flag=hndl_flag,
        regulatory_flags=flags + cls.advisories,
        nist_quantum_security_level=cls.nist_quantum_security_level,
        x_years=x, x_source=x_source,
        y_years=y, y_source=y_source,
        z_year_used=policy.z_year, z_years=z_years,
        exposure_gap=round(exposure_gap, 2),
        urgency=round(urgency, 3),
        compliance_component=compliance,
        quantum_component=vulnerability,
        criticality=criticality,
        criticality_weight=weight,
        risk=round(risk, 3),
        score=round(score, 3),
        driver=driver,
    )


def classify_all(assets: list[Asset], policy: Policy,
                 current_year: int | None = None) -> dict[str, RiskClassification]:
    return {a.id: classify_asset(a, policy, current_year) for a in assets}


def heat_map(risks: dict[str, RiskClassification]) -> dict[str, dict[str, int]]:
    """criticality x urgency grid, as rendered in the dashboard."""
    grid = {c: {u: 0 for u in ("low", "medium", "high")} for c in ("low", "medium", "high")}
    for r in risks.values():
        grid[r.criticality.value][r.urgency_band] += 1
    return grid
