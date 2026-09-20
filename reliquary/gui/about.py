"""About dialog helper for Email IOC Extractor GUI."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox

from reliquary import __app_name__, __log_name__, __tagline__, __version__
from reliquary.core.models import AnalysisResult
from reliquary.core.paths import app_dir
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
        overrides = f"\nProfile: {profile_dir}"
    update = check_update_manifest()
    update_line = f"\n{update}" if update else ""
    runbook = root / "docs" / "ANALYST_RU.md"
    runbook_line = f"\nRunbook: {runbook}" if runbook.is_file() else "\nRunbook: docs/ANALYST_RU.md"
    messagebox.showinfo(
        f"{t('about_title')} — {__app_name__}",
        f"{__app_name__} v{__version__}\n"
        f"{__tagline__}\n\n"
        "Offline email triage (.eml / .msg).\n"
        "Verdict first; IOC as evidence. Network blocked.\n\n"
        "1. Open mail or folder\n"
        "2. Verdict — score / breakdown / reasons\n"
        "3. Attachments · URL · IOC\n"
        "4. Export JSON / CSV / Handoff\n"
        "5. ПКМ on IOC → allowlist / override\n\n"
        f"Log: {__log_name__}\n"
        "Ctrl+O · Ctrl+H handoff · Ctrl+E export · Ctrl+L theme · Ctrl+D density\n"
        f"Theme: {appearance_mode} · IOC: {ioc_density}"
        f"{overrides}{update_line}{runbook_line}\n\n"
        f"Folder:\n{root}",
    )
