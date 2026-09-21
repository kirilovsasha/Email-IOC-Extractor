"""Окно «О программе» для GUI Email IOC Extractor."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox

from reliquary import __app_name__, __log_name__, __tagline__, __version__
from reliquary.core.models import AnalysisResult
from reliquary.core.paths import app_dir
from reliquary.core.self_check import format_self_check
from reliquary.core.update_check import check_update_manifest
from reliquary.gui.i18n import t


def show_about_dialog(
    *,
    appearance_mode: str,
    ioc_density: str,
    result: AnalysisResult | None = None,
    profile_dir: str | None = None,
    verdict_path: str | None = None,
    verdict_warnings: list[str] | None = None,
) -> None:
    root = app_dir()
    overrides = ""
    if result and result.meta and result.meta.overrides_loaded:
        ov = result.meta.overrides_loaded
        overrides = "\nПереопределения: " + ", ".join(
            f"{k}={Path(v).name}" for k, v in ov.items()
        )
    elif profile_dir:
        overrides = f"\nПрофиль: {profile_dir}"
    update = check_update_manifest()
    update_line = f"\n{update}" if update else ""
    runbook = root / "docs" / "ANALYST_RU.md"
    if not runbook.is_file():
        runbook = root / "ANALYST_RU.md"
    runbook_line = (
        f"\nСправка: {runbook}"
        if runbook.is_file()
        else "\nСправка: docs/ANALYST_RU.md (положите рядом с EXE)"
    )
    self_check = format_self_check(
        profile_dir=profile_dir,
        verdict_path=verdict_path,
        verdict_warnings=verdict_warnings,
    )
    messagebox.showinfo(
        f"{t('about_title')} — {__app_name__}",
        f"{__app_name__} v{__version__}\n"
        f"{__tagline__}\n\n"
        "Офлайн-triage писем (.eml / .msg).\n"
        "Один EXE + опциональные конфиги рядом. Без БД и без сети.\n"
        "Сначала вердикт; IOC — как доказательства.\n\n"
        f"{self_check}\n\n"
        "1. Откройте письмо или папку\n"
        "2. Вердикт — score / разбор / причины\n"
        "3. Вложения · URL · IOC\n"
        "4. Экспорт JSON / CSV / ECS / CEF / STIX / MISP / OpenCTI / тикет\n"
        "5. ПКМ по IOC → allowlist / сменить вердикт\n"
        "6. «Калибр.» — отчёт FP/FN по папке inbox\n\n"
        f"Журнал: {__log_name__}\n"
        "Ctrl+O · Ctrl+H тикет · Ctrl+E экспорт · Ctrl+Shift+V компакт\n"
        "Ctrl+N/P следующее письмо пакета · Ctrl+L тема · Ctrl+D плотность\n"
        f"Тема: {appearance_mode} · IOC: {ioc_density}"
        f"{overrides}{update_line}{runbook_line}\n\n"
        f"Каталог:\n{root}",
    )
