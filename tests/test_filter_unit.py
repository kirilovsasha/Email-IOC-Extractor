"""GUI-free unit tests for filter helpers."""

from __future__ import annotations

from reliquary.core.filter_state import FilterState
from reliquary.core.models import AnalysisResult, Ioc, IocType


def _result(*iocs: Ioc) -> AnalysisResult:
    return AnalysisResult(
        source_path="t",
        source_kind="ticket",
        iocs=list(iocs),
    )


def test_filter_hides_rewriter_and_private():
    iocs = [
        Ioc("1.1.1.1", IocType.IPV4, tags=["private"]),
        Ioc("evil.com", IocType.DOMAIN, tags=["url_rewriter"]),
        Ioc("bad.com", IocType.DOMAIN, tags=["denylisted"]),
    ]
    state = FilterState(hide_private=True, hide_rewriter=True)
    out = state.apply(_result(*iocs))
    values = {i.value for i in out}
    assert "bad.com" in values
    assert "1.1.1.1" not in values
    assert "evil.com" not in values


def test_filter_only_denylisted():
    iocs = [
        Ioc("a.com", IocType.DOMAIN, tags=[]),
        Ioc("b.com", IocType.DOMAIN, tags=["denylisted"]),
    ]
    state = FilterState(only_denylisted=True)
    out = state.apply(_result(*iocs))
    assert [i.value for i in out] == ["b.com"]


def test_filter_from_prefs():
    state = FilterState.from_prefs({"actionable_only": True, "cat_network": False})
    assert state.actionable_only is True
    assert state.cat_network is False
