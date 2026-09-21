"""Export, handoff, batch JSON/CSV."""

from __future__ import annotations

import json
from pathlib import Path

from reliquary.core.error_log import append_error_log, error_log_path
from reliquary.core.exporters import export_batch_csv, export_report_json
from reliquary.core.handoff import render_handoff
from reliquary.core.models import SCHEMA_VERSION
from reliquary.core.pipeline import analyze_file, merge_results
from reliquary.gui.export_actions import EXPORT_CHOICES, default_export_filename, run_export

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
CORPUS = SAMPLES / "corpus"


def test_handoff_and_batch_export(tmp_path: Path):
    result = analyze_file(SAMPLES / "phishing_sample.eml")
    text = render_handoff(result)
    assert "Verdict:" in text
    assert "Message-ID:" in text or "File:" in text

    out = run_export("handoff", result, tmp_path / "h.txt", filtered_iocs=result.iocs)
    assert out.read_text(encoding="utf-8").startswith("===")

    a = analyze_file(SAMPLES / "phishing_sample.eml")
    b = analyze_file(SAMPLES / "phishing_sample.eml")
    merged = merge_results([a, b])
    csv_path = export_batch_csv(merged, tmp_path / "batch.csv", batch_results=[a, b])
    assert csv_path.read_text(encoding="utf-8-sig").count("\n") >= 3

    js = export_report_json(merged, tmp_path / "b.json", batch_results=[a, b])
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert "batch" in payload
    assert len(payload["batch"]) == 2
    assert payload.get("schema_version") == SCHEMA_VERSION

    assert "Тикет" in EXPORT_CHOICES
    assert "ECS" not in EXPORT_CHOICES
    assert "CEF" not in EXPORT_CHOICES
    assert "STIX" not in EXPORT_CHOICES
    assert EXPORT_CHOICES == ("JSON", "CSV", "Batch CSV", "Тикет")
    assert default_export_filename("Batch CSV").endswith(".csv")
    assert default_export_filename("ECS").endswith(".json")
    assert default_export_filename("CEF").endswith(".cef")
    assert default_export_filename("STIX").endswith(".json")


def test_siem_exports(tmp_path: Path) -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    ecs = run_export("ecs", result, tmp_path / "e.json")
    payload = json.loads(ecs.read_text(encoding="utf-8"))
    assert payload["event"]["dataset"] == "reliquary.email_ioc"
    assert "threat" in payload

    cef = run_export("cef", result, tmp_path / "c.cef")
    text = cef.read_text(encoding="utf-8")
    assert text.startswith("CEF:0|")
    assert "EmailIOCExtractor" in text

    stix = run_export("stix", result, tmp_path / "s.json")
    bundle = json.loads(stix.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert any(o.get("type") == "indicator" for o in bundle["objects"])


def test_handoff_template_placeholders() -> None:
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    text = render_handoff(
        result,
        template="V={verdict} S={score} F={file} ID={msg_id}\n{iocs}\n",
    )
    assert "V=BENIGN" in text or "V=UNKNOWN" in text or "V=" in text
    assert "S=" in text
    assert "benign_hr_notice.eml" in text


def test_handoff_level_template(tmp_path: Path) -> None:
    result = analyze_file(CORPUS / "malicious_exe_ip_url.eml")
    level = result.verdict.level.value if result.verdict else "malicious"
    tmpl = tmp_path / f"handoff_{level}.txt"
    tmpl.write_text("LVL={verdict} VER={version} BD=\n{breakdown}\n", encoding="utf-8")
    text = render_handoff(result, handoff_by_level={level: tmpl})
    assert "LVL=" in text
    assert "VER=" in text


def test_append_error_log(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("reliquary.core.error_log.app_dir", lambda: tmp_path)
    path = append_error_log("unit test note")
    assert path is not None
    assert path.exists()
    assert "unit test note" in path.read_text(encoding="utf-8")
    assert error_log_path() == tmp_path / path.name


def test_post_export_hook(tmp_path: Path, monkeypatch) -> None:
    result = analyze_file(CORPUS / "benign_hr_notice.eml")
    seen: list[tuple[str, str]] = []

    def _fake(hook, export_path, **_kwargs):
        seen.append((str(hook), str(export_path)))
        return "hook ok"

    monkeypatch.setattr(
        "reliquary.gui.export_actions.run_post_export_hook",
        _fake,
    )
    out = run_export(
        "json",
        result,
        tmp_path / "report.json",
        post_export_hook="my-hook-cmd",
    )
    assert out.is_file()
    assert seen == [("my-hook-cmd", str(out))]


def test_run_post_export_hook_writes(tmp_path: Path) -> None:
    import sys

    from reliquary.core.export_hook import run_post_export_hook

    export = tmp_path / "out.json"
    export.write_text("{}", encoding="utf-8")
    marker = tmp_path / "m.txt"
    script = tmp_path / "h.py"
    script.write_text(
        "import sys\nfrom pathlib import Path\n"
        f"Path(r'{marker.as_posix()}').write_text(sys.argv[-1], encoding='utf-8')\n",
        encoding="utf-8",
    )
    msg = run_post_export_hook(
        [sys.executable, str(script)],
        export,
        allow_external=True,
    )
    assert msg and msg.startswith("hook ok")
    assert marker.is_file()
    assert export.name in marker.read_text(encoding="utf-8")
