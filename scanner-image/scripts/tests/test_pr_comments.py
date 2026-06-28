"""Tests for the PR-comment helpers: diff parsing, severity filtering, path
normalization, comment bodies, and GitHub inline-comment selection."""

from pr_comments import common
from pr_comments import github


# ── common.normalize_path ─────────────────────────────────────────────────────

def test_normalize_path_strips_workspace_and_dot_prefixes():
    assert common.normalize_path("/workspace/src/Auth.cs") == "src/Auth.cs"
    assert common.normalize_path("workspace/src/Auth.cs") == "src/Auth.cs"
    assert common.normalize_path("./src/Auth.cs") == "src/Auth.cs"
    assert common.normalize_path("src/Auth.cs") == "src/Auth.cs"
    assert common.normalize_path("src\\win\\Auth.cs") == "src/win/Auth.cs"
    assert common.normalize_path(None) == ""


# ── common.finding_line ───────────────────────────────────────────────────────

def test_finding_line_prefers_start_then_end():
    assert common.finding_line({"startLine": 42, "endLine": 50}) == 42
    assert common.finding_line({"startLine": None, "endLine": 9}) == 9
    assert common.finding_line({"startLine": 0, "endLine": 0}) is None
    assert common.finding_line({}) is None


# ── common.should_inline (Blocking + High only) ───────────────────────────────

def test_should_inline_blocking_and_high_only():
    assert common.should_inline({"severity": "CRITICAL"}) is True
    assert common.should_inline({"severity": "high"}) is True
    assert common.should_inline({"severity": "MEDIUM"}) is False
    assert common.should_inline({"severity": "LOW"}) is False
    # A blocking finding is always inlined regardless of its severity label.
    assert common.should_inline({"severity": "MEDIUM", "isBlocking": True}) is True


# ── common.parse_patch_lines ──────────────────────────────────────────────────

def test_parse_patch_lines_marks_added_and_context_right_side_lines():
    patch = (
        "@@ -1,3 +1,4 @@\n"
        " context_a\n"      # new line 1 (context, commentable)
        "-removed_line\n"   # not in new file
        "+added_b\n"        # new line 2 (added, commentable)
        "+added_c\n"        # new line 3 (added, commentable)
        " context_d\n"      # new line 4 (context, commentable)
    )
    assert common.parse_patch_lines(patch) == {1, 2, 3, 4}


def test_parse_patch_lines_handles_no_newline_marker_and_empty():
    patch = "@@ -0,0 +1,1 @@\n+only line\n\\ No newline at end of file\n"
    assert common.parse_patch_lines(patch) == {1}
    assert common.parse_patch_lines(None) == set()
    assert common.parse_patch_lines("") == set()


# ── common.inline_body (no secret leakage) ────────────────────────────────────

def test_inline_body_has_marker_rule_severity_and_no_snippet_field():
    body = common.inline_body({
        "severity": "HIGH",
        "ruleId": "sql-injection",
        "scanner": "semgrep",
        "description": "User input flows into a SQL query.",
    })
    assert common.MARKER in body
    assert "sql-injection" in body
    assert "HIGH" in body
    assert "User input flows into a SQL query." in body


# ── common.build_summary ──────────────────────────────────────────────────────

def test_build_summary_blocking_with_counts():
    summary = common.build_summary(True, total=5, inline_count=2)
    assert common.MARKER in summary
    assert "Pipeline blocked" in summary
    assert "**5**" in summary
    assert "**2**" in summary
    assert "**3**" in summary  # 5 total - 2 inline = 3 on unchanged code


def test_build_summary_clean_run():
    summary = common.build_summary(False, total=0, inline_count=0)
    assert "No blocking findings detected" in summary
    assert "🎉" in summary


# ── github._build_inline_comments (diff-aware selection) ──────────────────────

def test_github_inline_selection_filters_off_diff_and_low_severity():
    findings = [
        {"filePath": "/workspace/src/A.cs", "startLine": 10, "severity": "CRITICAL", "ruleId": "r1"},  # on diff
        {"filePath": "src/A.cs", "startLine": 99, "severity": "HIGH", "ruleId": "r2"},                  # off diff
        {"filePath": "src/A.cs", "startLine": 10, "severity": "MEDIUM", "ruleId": "r3"},                # low sev
        {"filePath": "src/B.cs", "startLine": 5, "severity": "HIGH", "ruleId": "r4"},                   # file not changed
    ]
    commentable = {"src/A.cs": {10, 11, 12}}

    comments = github._build_inline_comments(findings, commentable)

    assert len(comments) == 1
    assert comments[0]["path"] == "src/A.cs"
    assert comments[0]["line"] == 10
    assert comments[0]["side"] == "RIGHT"


def test_github_inline_selection_dedupes_same_path_line_rule():
    findings = [
        {"filePath": "src/A.cs", "startLine": 10, "severity": "HIGH", "ruleId": "r1"},
        {"filePath": "/workspace/src/A.cs", "startLine": 10, "severity": "HIGH", "ruleId": "r1"},
    ]
    commentable = {"src/A.cs": {10}}

    comments = github._build_inline_comments(findings, commentable)

    assert len(comments) == 1
