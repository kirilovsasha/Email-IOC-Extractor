"""Offline prefs dialog — paths, workers, post-export hook (no network, no DB)."""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Callable

import customtkinter as ctk

from reliquary.core.prefs import load_prefs, save_prefs
from reliquary.gui.theme import BTN_PRIMARY, BTN_SECONDARY, COLORS, ctk_font


def show_settings_dialog(
    parent: ctk.CTk,
    *,
    prefs: dict[str, Any],
    on_saved: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Modal-ish settings window for fleet EXE configs beside the binary."""
    data = dict(prefs)
    win = ctk.CTkToplevel(parent)
    win.title("Настройки")
    win.geometry("640x560")
    win.minsize(520, 480)
    win.configure(fg_color=COLORS["bg"])
    try:
        win.transient(parent)
        win.grab_set()
    except Exception:  # noqa: BLE001
        pass

    scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["surface"], corner_radius=8)
    scroll.pack(fill="both", expand=True, padx=12, pady=(12, 6))

    entries: dict[str, ctk.CTkEntry] = {}
    bool_vars: dict[str, ctk.BooleanVar] = {}

    def _section(title: str) -> ctk.CTkFrame:
        block = ctk.CTkFrame(scroll, fg_color="transparent")
        block.pack(fill="x", pady=(8, 2))
        ctk.CTkLabel(
            block,
            text=title,
            font=ctk_font("section", weight="bold"),
            text_color=COLORS["accent"],
            anchor="w",
        ).pack(anchor="w")
        return block

    def _path_row(parent_f: ctk.CTkFrame, key: str, label: str, *, dir_mode: bool = False) -> None:
        row = ctk.CTkFrame(parent_f, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkLabel(row, text=label, width=160, anchor="w", font=ctk_font("caption")).pack(
            side="left"
        )
        var = ctk.StringVar(value=str(data.get(key) or ""))
        ent = ctk.CTkEntry(row, textvariable=var, height=28)
        ent.pack(side="left", fill="x", expand=True, padx=6)
        entries[key] = ent

        def _browse() -> None:
            if dir_mode:
                chosen = filedialog.askdirectory(parent=win, initialdir=var.get() or str(Path.cwd()))
            else:
                chosen = filedialog.askopenfilename(
                    parent=win, initialdir=str(Path(var.get() or Path.cwd()).parent)
                )
            if chosen:
                var.set(chosen)

        ctk.CTkButton(row, text="…", width=36, command=_browse, **BTN_SECONDARY).pack(side="left")

    def _int_row(parent_f: ctk.CTkFrame, key: str, label: str) -> None:
        row = ctk.CTkFrame(parent_f, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkLabel(row, text=label, width=160, anchor="w", font=ctk_font("caption")).pack(
            side="left"
        )
        var = ctk.StringVar(value=str(data.get(key) if data.get(key) is not None else ""))
        ent = ctk.CTkEntry(row, textvariable=var, width=100, height=28)
        ent.pack(side="left", padx=6)
        entries[key] = ent

    def _check(parent_f: ctk.CTkFrame, key: str, label: str) -> None:
        var = ctk.BooleanVar(value=bool(data.get(key)))
        bool_vars[key] = var
        ctk.CTkCheckBox(
            parent_f,
            text=label,
            variable=var,
            font=ctk_font("caption"),
            text_color=COLORS["text"],
        ).pack(anchor="w", pady=2)

    paths = _section("Пути (рядом с EXE / переопределения)")
    _path_row(paths, "allowlist_path", "Allowlist")
    _path_row(paths, "verdict_path", "verdict_extra.json")
    _path_row(paths, "brands_path", "brands.txt")
    _path_row(paths, "handoff_template_path", "Шаблон тикета")
    _path_row(paths, "profile_dir", "org_profile", dir_mode=True)

    fleet = _section("Пакет / workers")
    _int_row(fleet, "max_workers", "Workers (0=auto)")
    _int_row(fleet, "folder_warn_threshold", "Порог предупреждения папки")
    _check(fleet, "skip_broken", "Пропускать битые файлы в пакете")

    hook = _section("Post-export hook")
    _path_row(hook, "post_export_hook", "Команда / скрипт")
    _check(hook, "post_export_hook_json_sidecar", "JSON sidecar (schema_version:2) 2-м argv")
    _check(hook, "post_export_hook_allow_external", "Разрешить hook вне каталога EXE")
    _check(hook, "disable_post_export_hook", "Отключить hook (корпоративный lock)")

    ui = _section("Интерфейс")
    row_a = ctk.CTkFrame(ui, fg_color="transparent")
    row_a.pack(fill="x", pady=3)
    ctk.CTkLabel(row_a, text="Тема", width=160, anchor="w", font=ctk_font("caption")).pack(
        side="left"
    )
    appearance_var = ctk.StringVar(value=str(data.get("appearance_mode") or "dark"))
    ctk.CTkOptionMenu(
        row_a,
        variable=appearance_var,
        values=["dark", "light", "system"],
        width=120,
        font=ctk_font("caption"),
    ).pack(side="left", padx=6)
    row_d = ctk.CTkFrame(ui, fg_color="transparent")
    row_d.pack(fill="x", pady=3)
    ctk.CTkLabel(row_d, text="Плотность IOC", width=160, anchor="w", font=ctk_font("caption")).pack(
        side="left"
    )
    density_var = ctk.StringVar(value=str(data.get("ioc_density") or "normal"))
    ctk.CTkOptionMenu(
        row_d,
        variable=density_var,
        values=["compact", "normal", "comfortable"],
        width=140,
        font=ctk_font("caption"),
    ).pack(side="left", padx=6)
    _check(ui, "high_contrast", "Высокий контраст")
    _check(ui, "verdict_compact", "Компактный вердикт (скрыть исходник)")

    noise = _section("Фильтры IOC по умолчанию")
    _check(noise, "actionable_only", "Только «к разбору»")
    _check(noise, "hide_rewriter", "Скрыть rewriter URL")
    _check(noise, "hide_allowlisted", "Скрыть allowlisted")
    _check(noise, "hide_private", "Скрыть private/local")
    _check(noise, "full_ioc_types", "Все типы IOC (registry/mutex/…)")
    _path_row(noise, "last_inbox_dir", "Папка калибровки", dir_mode=True)

    exp = _section("Экспорт по умолчанию")
    row_e = ctk.CTkFrame(exp, fg_color="transparent")
    row_e.pack(fill="x", pady=3)
    ctk.CTkLabel(row_e, text="Формат", width=160, anchor="w", font=ctk_font("caption")).pack(
        side="left"
    )
    export_var = ctk.StringVar(value=str(data.get("export_choice") or "JSON"))
    export_menu = ctk.CTkOptionMenu(
        row_e,
        variable=export_var,
        values=[
            "JSON",
            "CSV",
            "Batch CSV",
            "Тикет",
            "Кампания",
            "Campaign pack",
            "ECS",
            "CEF",
            "STIX",
            "MISP",
            "OpenCTI",
        ],
        width=180,
        font=ctk_font("caption"),
    )
    export_menu.pack(side="left", padx=6)

    btn_row = ctk.CTkFrame(win, fg_color="transparent")
    btn_row.pack(fill="x", padx=12, pady=(4, 12))

    def _save() -> None:
        updates: dict[str, Any] = {
            "export_choice": export_var.get(),
            "appearance_mode": appearance_var.get(),
            "ioc_density": density_var.get(),
        }
        for key, ent in entries.items():
            val = ent.get().strip()
            if key in ("max_workers", "folder_warn_threshold"):
                try:
                    updates[key] = int(val or "0")
                except ValueError:
                    messagebox.showerror("Настройки", f"Неверное число: {key}", parent=win)
                    return
            else:
                updates[key] = val
        for key, var in bool_vars.items():
            updates[key] = bool(var.get())
        if not save_prefs(updates):
            messagebox.showerror("Настройки", "Не удалось сохранить ui_prefs.json", parent=win)
            return
        fresh = load_prefs()
        prefs.clear()
        prefs.update(fresh)
        if on_saved is not None:
            on_saved(fresh)
        try:
            win.destroy()
        except Exception:  # noqa: BLE001
            pass

    ctk.CTkButton(btn_row, text="Сохранить", width=120, command=_save, **BTN_PRIMARY).pack(
        side="right", padx=(6, 0)
    )
    ctk.CTkButton(
        btn_row, text="Отмена", width=100, command=win.destroy, **BTN_SECONDARY
    ).pack(side="right")
