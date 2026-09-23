"""Окно «О программе» для GUI Email IOC Extractor."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk

from reliquary import __app_name__, __log_name__, __tagline__, __version__
from reliquary.core.models import AnalysisResult
from reliquary.core.paths import app_dir
from reliquary.core.self_check import format_self_check
from reliquary.core.update_check import check_update_manifest
from reliquary.gui.i18n import t
from reliquary.gui.theme import BTN_PRIMARY, COLORS, ctk_font


def compose_about_text(
    *,
    appearance_mode: str,
    ioc_density: str,
    result: AnalysisResult | None = None,
    profile_dir: str | None = None,
    verdict_path: str | None = None,
    verdict_warnings: list[str] | None = None,
) -> str:
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
    return (
        f"{__app_name__} v{__version__}\n"
        f"{__tagline__}\n\n"
        "Офлайн-triage писем (.eml / .msg / .mbox / .pst).\n"
        "Один EXE + опциональные конфиги рядом. Без БД и без сети.\n"
        "Сначала вердикт; IOC — как доказательства.\n\n"
        f"{self_check}\n\n"
        "1. Откройте письмо или папку\n"
        "2. Вердикт — score / уверенность / разбор / причины\n"
        "3. Вложения · URL · IOC\n"
        "4. Экспорт: JSON · CSV · Batch CSV · Тикет\n"
        "5. ПКМ по IOC → allowlist / сменить вердикт / feedback\n\n"
        f"Журнал: {__log_name__}\n"
        "Ctrl+O · Ctrl+H тикет · Ctrl+E экспорт · Ctrl+Shift+V компакт\n"
        "Ctrl+N/P пакет · Ctrl+Shift+N следующее suspicious+ · Ctrl+L тема\n"
        f"Тема: {appearance_mode} · IOC: {ioc_density}"
        f"{overrides}{update_line}{runbook_line}\n\n"
        f"Каталог:\n{root}"
    )


def show_about_dialog(
    *,
    parent: object | None = None,
    appearance_mode: str,
    ioc_density: str,
    result: AnalysisResult | None = None,
    profile_dir: str | None = None,
    verdict_path: str | None = None,
    verdict_warnings: list[str] | None = None,
) -> None:
    """Show About in a child window of the main app.

    A native ``messagebox`` without ``parent`` opens behind the CustomTkinter
    window on Windows, so the button looks dead.
    """
    try:
        body = compose_about_text(
            appearance_mode=appearance_mode,
            ioc_density=ioc_density,
            result=result,
            profile_dir=profile_dir,
            verdict_path=verdict_path,
            verdict_warnings=verdict_warnings,
        )
    except Exception as exc:  # noqa: BLE001
        body = f"{__app_name__} v{__version__}\n\nНе удалось собрать сведения:\n{exc}"

    title = f"{t('about_title')} — {__app_name__}"
    if parent is None:
        messagebox.showinfo(title, body)
        return

    win = ctk.CTkToplevel(parent)
    win.title(title)
    win.configure(fg_color=COLORS["bg"])
    win.minsize(420, 360)
    try:
        win.transient(parent)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        pass

    width, height = 640, 560
    try:
        parent.update_idletasks()  # type: ignore[attr-defined]
        px = int(parent.winfo_rootx())  # type: ignore[attr-defined]
        py = int(parent.winfo_rooty())  # type: ignore[attr-defined]
        pw = int(parent.winfo_width())  # type: ignore[attr-defined]
        ph = int(parent.winfo_height())  # type: ignore[attr-defined]
        x = px + max(0, (pw - width) // 2)
        y = py + max(0, (ph - height) // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
    except Exception:  # noqa: BLE001
        win.geometry(f"{width}x{height}")

    head = ctk.CTkLabel(
        win,
        text=f"{__app_name__}  ·  v{__version__}",
        font=ctk_font("title", weight="bold"),
        text_color=COLORS["accent"],
        anchor="w",
    )
    head.pack(fill="x", padx=16, pady=(14, 4))

    box = ctk.CTkTextbox(
        win,
        fg_color=COLORS["surface"],
        text_color=COLORS["text"],
        font=ctk_font("body"),
        wrap="word",
        border_width=1,
        border_color=COLORS["border"],
        corner_radius=8,
    )
    box.pack(fill="both", expand=True, padx=16, pady=(4, 8))
    box.insert("1.0", body)
    inner = getattr(box, "textbox", None) or getattr(box, "_textbox", None)
    if inner is not None:

        def _on_key(event: object) -> str | None:
            state = int(getattr(event, "state", 0) or 0)
            key = str(getattr(event, "keysym", "") or "").lower()
            if state & 0x4 and key in ("c", "a"):
                return None
            return "break"

        inner.bind("<Key>", _on_key)

    def _close() -> None:
        try:
            win.grab_release()
        except Exception:  # noqa: BLE001
            pass
        try:
            win.destroy()
        except Exception:  # noqa: BLE001
            pass

    ctk.CTkButton(win, text="Закрыть", width=120, command=_close, **BTN_PRIMARY).pack(
        pady=(0, 14)
    )
    win.protocol("WM_DELETE_WINDOW", _close)
    try:
        win.grab_set()
    except Exception:  # noqa: BLE001
        pass
    try:
        win.attributes("-topmost", True)
        win.after(200, lambda: win.attributes("-topmost", False))
    except Exception:  # noqa: BLE001
        pass
    win.lift()
    win.focus_force()
