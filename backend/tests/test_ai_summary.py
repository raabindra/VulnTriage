"""AI-Assisted Analysis engine tests.

The engine is optional and gated behind ANTHROPIC_API_KEY. These tests mock the
Anthropic client so no key or network is required, and verify the no-key no-op,
response parsing, graceful failure, and PDF-section rendering.
"""

import json
import types
from unittest.mock import MagicMock, patch

from app.engines.ai_summary import AiSummaryEngine
from app.engines.report_generator import ReportGenerator


def _finding(title="SQL Injection", sev="High"):
    f = types.SimpleNamespace(
        title=title, severity=sev, cwe_id="CWE-89", cve_id=None, cvss_score=7.5,
        classification="Confirmed", confidence_score=None, ml_prediction=None)
    return f


_AI_JSON = {
    "executive_summary": "One high-severity SQL injection was confirmed.",
    "key_findings": [{"title": "SQL Injection", "risk": "Data exfiltration.",
                      "fix": "Use parameterised queries."}],
    "priority_actions": ["Patch the SQL injection", "Re-scan"],
}


def _mock_client():
    """A fake anthropic.Anthropic whose messages.create returns _AI_JSON as text."""
    block = types.SimpleNamespace(type="text", text=json.dumps(_AI_JSON))
    resp = types.SimpleNamespace(content=[block])
    client = MagicMock()
    client.messages.create.return_value = resp
    return client


def test_disabled_without_key():
    e = AiSummaryEngine(api_key="")
    assert e.enabled is False
    assert e.summarise([_finding()]) is None


def test_summarise_parses_response():
    e = AiSummaryEngine(api_key="sk-test")
    assert e.enabled is True
    with patch("anthropic.Anthropic", return_value=_mock_client()):
        out = e.summarise([_finding()])
    assert out == _AI_JSON


def test_summarise_degrades_on_error():
    e = AiSummaryEngine(api_key="sk-test")
    boom = MagicMock()
    boom.messages.create.side_effect = RuntimeError("network down")
    with patch("anthropic.Anthropic", return_value=boom):
        assert e.summarise([_finding()]) is None  # no exception, just None


def test_empty_findings_returns_none():
    assert AiSummaryEngine(api_key="sk-test").summarise([]) is None


def test_ai_section_renders_flowables():
    styles = ReportGenerator._make_styles()
    story = ReportGenerator()._ai_section(_AI_JSON, styles)
    assert isinstance(story, list) and len(story) > 3
