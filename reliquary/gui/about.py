"""About dialog helper for Email IOC Extractor GUI."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox

from reliquary import __app_name__, __log_name__, __tagline__, __version__
from reliquary.core.models import AnalysisResult
from reliquary.core.paths import app_dir


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
    messagebox.showinfo(
        f"О программе — {__app_name__}",
        f"{__app_name__} v{__version__}\n"
        f"{__tagline__}\n\n"
        "Офлайн анализ писем (.eml / .msg).\n"
        "Вердикт — главный результат; IOC — доказательства.\n"
        "Сеть заблокирована.\n\n"
        "1. Открыть письмо или папку\n"
        "2. Вердикт — score / разбор / действия\n"
        "3. Вложения · URL · IOC\n"
        "4. Экспорт JSON / CSV / Handoff\n\n"
        f"Лог: {__log_name__}\n"
        "Ctrl+O · Ctrl+H handoff · Ctrl+E экспорт · Ctrl+L тема · Ctrl+D плотность\n"
        f"Тема: {appearance_mode} · IOC: {ioc_density}"
        f"{overrides}\n\n"
        f"Папка:\n{root}",
    )
