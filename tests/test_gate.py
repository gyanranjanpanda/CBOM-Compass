"""The CI gate.

A gate is only worth having if teams leave it switched on, so most of these
tests are about what must *not* fail the build.
"""

from __future__ import annotations

import json

from cbom_compass.cli import main

CLEAN = "import hashlib\ndef fp(b): return hashlib.sha256(b).hexdigest()\n"
BROKEN = "import hashlib\ndef legacy(b): return hashlib.md5(b).hexdigest()\n"
DEPRECATED = "import hashlib\ndef old(b): return hashlib.sha1(b).hexdigest()\n"


def tree(tmp_path, name, files):
    root = tmp_path / name
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def baseline_for(tmp_path, root, name="baseline.json"):
    out = tmp_path / name
    assert main(["--db", str(tmp_path / "g.db"), "scan", str(root),
                 "-o", str(out), "--format", "json"]) == 0
    return out


def gate(tmp_path, root, baseline=None, *extra):
    argv = ["--db", str(tmp_path / "g.db"), "gate", str(root)]
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
    return main(argv + list(extra))


def test_a_change_that_adds_broken_cryptography_fails(tmp_path):
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    head = tree(tmp_path, "head", {"app.py": CLEAN + "\n" + BROKEN})
    assert gate(tmp_path, head, baseline_for(tmp_path, base)) == 1


def test_a_change_that_adds_nothing_passes(tmp_path):
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    head = tree(tmp_path, "head", {"app.py": CLEAN + "\ndef extra(): pass\n"})
    assert gate(tmp_path, head, baseline_for(tmp_path, base)) == 0


def test_moving_a_file_does_not_fail_the_build(tmp_path):
    """Asset identity includes file and line, so a rename reads as a new
    finding. A gate that cries wolf on refactors gets switched off."""
    base = tree(tmp_path, "base", {"old_name.py": BROKEN})
    head = tree(tmp_path, "head", {"pkg/new_name.py": BROKEN})
    assert gate(tmp_path, head, baseline_for(tmp_path, base)) == 0


def test_pre_existing_debt_does_not_fail_the_build(tmp_path):
    """The rule is "do not make it worse", not "be clean" — otherwise the large
    old estates that most need this cannot adopt it."""
    base = tree(tmp_path, "base", {"app.py": BROKEN})
    head = tree(tmp_path, "head", {"app.py": BROKEN + "\ndef unrelated(): pass\n"})
    assert gate(tmp_path, head, baseline_for(tmp_path, base)) == 0


def test_removing_broken_cryptography_passes(tmp_path):
    base = tree(tmp_path, "base", {"app.py": BROKEN})
    head = tree(tmp_path, "head", {"app.py": CLEAN})
    assert gate(tmp_path, head, baseline_for(tmp_path, base)) == 0


def test_deprecated_is_opt_in(tmp_path):
    """A team mid-migration legitimately carries some; blocking by default
    would punish exactly the teams doing the work."""
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    head = tree(tmp_path, "head", {"app.py": CLEAN + "\n" + DEPRECATED})
    line = baseline_for(tmp_path, base)
    assert gate(tmp_path, head, line) == 0
    assert gate(tmp_path, head, line, "--include-deprecated") == 1


def test_allowance_tolerates_a_stated_number(tmp_path):
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    head = tree(tmp_path, "head", {"app.py": CLEAN + "\n" + BROKEN})
    line = baseline_for(tmp_path, base)
    assert gate(tmp_path, head, line, "--allow", "1") == 0
    assert gate(tmp_path, head, line, "--allow", "0") == 1


def test_a_missing_baseline_reports_instead_of_blocking(tmp_path):
    """First run on a repository has nothing to compare against. Failing there
    would mean the check can never be introduced."""
    head = tree(tmp_path, "head", {"app.py": BROKEN})
    assert gate(tmp_path, head, tmp_path / "absent.json") == 0
    assert gate(tmp_path, head, None) == 0


def test_a_corrupt_baseline_is_a_usage_error_not_a_pass(tmp_path):
    """Silently passing on an unreadable baseline would make the gate a no-op
    that nobody notices."""
    head = tree(tmp_path, "head", {"app.py": BROKEN})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert gate(tmp_path, head, bad) == 2


def test_summary_is_written_for_the_ci_run(tmp_path):
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    head = tree(tmp_path, "head", {"app.py": CLEAN + "\n" + BROKEN})
    summary = tmp_path / "summary.md"
    gate(tmp_path, head, baseline_for(tmp_path, base),
         "--summary-file", str(summary))
    text = summary.read_text()
    assert "failed" in text
    assert "| broken classical | 0 | 1 | +1 |" in text
    assert "`MD5`" in text          # names what to fix, not just that it failed


def test_summary_on_a_passing_run_still_reports_the_counts(tmp_path):
    base = tree(tmp_path, "base", {"app.py": CLEAN})
    summary = tmp_path / "ok.md"
    gate(tmp_path, base, baseline_for(tmp_path, base),
         "--summary-file", str(summary))
    assert "passed" in summary.read_text()


def test_the_gate_reads_configuration_not_only_code(tmp_path):
    """Most protocol cryptography is configured, not called — a gate that only
    watched source would miss a cipher list being widened."""
    base = tree(tmp_path, "base", {"deploy/sshd_config": "Ciphers aes256-gcm@openssh.com\n"})
    head = tree(tmp_path, "head",
                {"deploy/sshd_config": "Ciphers aes256-gcm@openssh.com,3des-cbc\n"})
    assert gate(tmp_path, head, baseline_for(tmp_path, base),
                "--include-deprecated") == 1


def test_baseline_json_is_a_plain_report(tmp_path):
    """The baseline is whatever `scan --format json` writes, so producing one
    in CI needs no extra command."""
    base = tree(tmp_path, "base", {"app.py": BROKEN})
    document = json.loads(baseline_for(tmp_path, base).read_text())
    assert document["assets"] and "quantum_status" in document["assets"][0]


# ---------------------------------------------------------------------------
# Comparing against a git revision
# ---------------------------------------------------------------------------
def git_repo(tmp_path, files):
    import subprocess
    root = tmp_path / "repo"
    root.mkdir()
    run = lambda *a: subprocess.run(a, cwd=root, capture_output=True, check=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    run("git", "add", "-A")
    run("git", "commit", "-qm", "base")
    return root


def gate_in(root, *extra):
    import os
    cwd = os.getcwd()
    os.chdir(root)
    try:
        return main(["--db", str(root / "g.db"), "gate", ".",
                     "--baseline-ref", "HEAD", *extra])
    finally:
        os.chdir(cwd)


def test_gitignored_files_do_not_fail_the_gate(tmp_path):
    """The baseline comes from a git revision, which contains nothing git
    ignores. Scanning the working tree as-is made every build artefact and
    vendored dependency read as newly introduced cryptography, so a commit that
    changed nothing failed — which is fatal for the pre-commit hook."""
    root = git_repo(tmp_path, {".gitignore": "vendor/\n", "app.py": CLEAN})
    (root / "vendor").mkdir()
    (root / "vendor" / "legacy.py").write_text(BROKEN)
    assert gate_in(root) == 0


def test_an_uncommitted_new_file_still_counts(tmp_path):
    """Ignored is not the same as untracked. Work in progress must be gated, or
    the hook would wave through exactly what it exists to catch."""
    root = git_repo(tmp_path, {"app.py": CLEAN})
    (root / "new_feature.py").write_text(BROKEN)
    assert gate_in(root) == 1


def test_an_edit_to_a_tracked_file_counts(tmp_path):
    root = git_repo(tmp_path, {"app.py": CLEAN})
    (root / "app.py").write_text(CLEAN + "\n" + BROKEN)
    assert gate_in(root) == 1


def test_baseline_ref_compares_the_same_subtree(tmp_path):
    """Gating a subdirectory against a baseline of the whole repository is not
    a comparison; the counts are unrelated and everything passes."""
    root = git_repo(tmp_path, {"src/app.py": CLEAN, "elsewhere/old.py": BROKEN})
    import os
    cwd = os.getcwd()
    os.chdir(root)
    try:
        (root / "src" / "app.py").write_text(CLEAN + "\n" + BROKEN)
        assert main(["--db", str(root / "g.db"), "gate", "src",
                     "--baseline-ref", "HEAD"]) == 1
    finally:
        os.chdir(cwd)


# ---------------------------------------------------------------------------
# Surveying many projects
# ---------------------------------------------------------------------------
def test_survey_isolates_a_failing_project(tmp_path):
    """A survey that aborts on the first unreachable repository is not a
    survey. Failures are named in the output rather than silently reducing the
    denominator."""
    from cbom_compass.policy import Policy
    from cbom_compass.survey import Survey, scan_one

    good = tree(tmp_path, "good", {"app.py": BROKEN})
    result = Survey()
    result.projects.append(scan_one(str(good), Policy()))
    result.projects.append(scan_one("github.com/this-org/does-not-exist-xyz",
                                    Policy(), timeout=20))

    assert len(result.scanned) == 1
    assert len(result.failed) == 1
    assert result.failed[0].error
    rollup = result.rollup()
    assert rollup["projects"] == 1 and rollup["failed"] == 1


def test_survey_rollup_counts_projects_not_call_sites(tmp_path):
    """A project with two hundred RSA call sites and one with a single call are
    both one organisation with an RSA migration to plan."""
    from cbom_compass.policy import Policy
    from cbom_compass.survey import Survey, scan_one

    many = tree(tmp_path, "many", {"a.py": BROKEN * 5})
    one = tree(tmp_path, "one", {"a.py": BROKEN})
    result = Survey()
    for root in (many, one):
        result.projects.append(scan_one(str(root), Policy()))

    reach = dict(result.rollup()["algorithm_reach"])
    assert reach["MD5"] == 2, reach
    assert result.rollup()["share_with_broken"] == 1.0


def test_survey_report_states_what_it_is_not(tmp_path):
    """The write-up must not read as a judgement on the projects in it."""
    from cbom_compass.policy import Policy
    from cbom_compass.survey import Survey, markdown, scan_one

    result = Survey()
    result.projects.append(scan_one(str(tree(tmp_path, "p", {"a.py": BROKEN})),
                                    Policy()))
    text = markdown(result)
    assert "not a judgement" in text
    assert "sample, not a census" in text
