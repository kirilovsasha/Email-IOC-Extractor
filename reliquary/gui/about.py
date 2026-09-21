"""Окно «О программе» для GUI Email IOC Extractor."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox

from reliquary import __app_name__, __log_name__, __tagline__, __version__
from reliquary.core.models import AnalysisResult
from reliquary.core.paths import app_dir
from reliquary.core.qr_scan import qr_decoder_available
from reliquary.core.update_check import check_update_manifest
from reliquary.gui.i18n import t


def show_about_dialog(
    *,
    appearance_mode: str,
    ioc_density: str,
    result: AnalysisResult | None = None,
    profile_dir: str | None = None,
) -> None:
    root = app_dir()
    overrides = ""
    if result and result.meta and result.meta.overrides_loaded:
        ov = result.meta.overrides_loaded
        overrides = "\nOverrides: " + ", ".join(
            f"{k}={Path(v).name}" for k, v in ov.items()
        )
    elif profile_dir:
        overrides = f"\nПрофиль: {profile_dir}"
    update = check_update_manifest()
    update_line = f"\n{update}" if update else ""
    runbook = root / "docs" / "ANALYST_RU.md"
    runbook_line = (
        f"\nRunbook: {runbook}" if runbook.is_file() else "\nRunbook: docs/ANALYST_RU.md"
    )
    qr_line = (
        "\nQR: декодер доступен"
        if qr_decoder_available()
        else f"\n{t('qr_lite')}"
    )
    messagebox.showinfo(
        f"{t('about_title')} — {__app_name__}",
        f"{__app_name__} v{__version__}\n"
        f"{__tagline__}\n\n"
        "Офлайн-triage писем (.eml / .msg).\n"
        "Сначала вердикт; IOC — как доказательства. Сеть заблокирована.\n\n"
        "1. Откройте письмо или папку\n"
        "2. Вердикт — score / разбор / причины\n"
        "3. Вложения · URL · IOC\n"
        "4. Экспорт JSON / CSV / ECS / CEF / STIX / MISP / OpenCTI / тикет\n"
        "5. ПКМ по IOC → allowlist / сменить вердикт\n\n"
        f"Журнал: {__log_name__}\n"
        "Ctrl+O · Ctrl+H тикет · Ctrl+E экспорт · Ctrl+L тема · Ctrl+D плотность\n"
        f"Тема: {appearance_mode} · IOC: {ioc_density}"
        f"{overrides}{update_line}{runbook_line}{qr_line}\n\n"
        f"Каталог:\n{root}",
    )
