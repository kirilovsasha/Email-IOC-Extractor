"""Email IOC Extractor desktop GUI — email triage with verdict (CustomTkinter)."""

from __future__ import annotations

import tkinter as tk
from collections import Counter

import customtkinter as ctk

from reliquary import __app_name__
from reliquary.core.defang import defang_value
from reliquary.core.filter_state import CAT_PREF_KEYS, CATEGORY_TYPES
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.offline import enforce_offline
from reliquary.core.paths import app_dir
from reliquary.core.prefs import load_prefs
from reliquary.core.self_check import build_self_check_lines
from reliquary.core.verdict import probe_verdict_extra_warnings
from reliquary.gui.about import show_about_dialog
from reliquary.gui.analysis_actions import AnalysisActionsMixin
from reliquary.gui.analyst_actions import AnalystActionsMixin
from reliquary.gui.clipboard_actions import ClipboardActionsMixin
from reliquary.gui.filters_actions import FiltersActionsMixin
from reliquary.gui.hotkeys import HotkeysMixin
from reliquary.gui.layout import LayoutMixin
from reliquary.gui.prefs_actions import PrefsMixin
from reliquary.gui.result_panels import ResultPanelsMixin
from reliquary.gui.tabs import desired_result_tabs
from reliquary.gui.theme import (
    COLORS,
    FONT,
    FONT_UI,
    IOC_TYPE_COLORS,
    SEVERITY_COLORS,
    VERDICT_COLORS,
    apply_appearance,
    apply_global_fonts,
    ctk_font,
    set_high_contrast,
)

ctk.set_default_color_theme("dark-blue")
apply_global_fonts()

_PLACEHOLDER = (
    "Откройте .eml / .msg или вставьте исходник письма (RFC822).\n\n"
    "Ctrl+O — письмо · Ctrl+H — тикет · Ctrl+E — экспорт · 1 — вердикт"
)

_COPY_FORMATS = ("type|value", "value", "csv", "defanged", "defanged|type")


class ExtractorApp(
    AnalysisActionsMixin,
    AnalystActionsMixin,
    ClipboardActionsMixin,
    FiltersActionsMixin,
    ResultPanelsMixin,
    HotkeysMixin,
    PrefsMixin,
    LayoutMixin,
    ctk.CTk,
):
    """Email triage GUI — verdict first, IOC as evidence."""
    def __init__(self) -> None:
        super().__init__()
        self._prefs = load_prefs()
        if bool(self._prefs.get("high_contrast")):
            set_high_contrast(True)
        appearance = str(self._prefs.get("appearance_mode") or "dark")
        apply_appearance(appearance)
        self._appearance_mode = appearance
        self._ioc_density = str(self._prefs.get("ioc_density") or "normal")
        self._verdict_compact = bool(self._prefs.get("verdict_compact"))
        scale = float(self._prefs.get("ui_scale") or 1.0)
        try:
            # Widget scale only — window scaling drifts saved geometry off-screen.
            ctk.set_widget_scaling(scale)
        except (AttributeError, ValueError, TypeError, tk.TclError):
            pass
        self._ui_scale = scale

        self.title(__app_name__)
        self.minsize(920, 620)
        self.configure(fg_color=COLORS["bg"])
        self._placed_on_screen = False
        self._apply_saved_geometry()

        def _place_once(_event: object = None) -> None:
            if self._placed_on_screen:
                return
            self._placed_on_screen = True
            self._apply_saved_geometry()

        self.bind("<Map>", _place_once, add="+")
        self.after(20, _place_once)

        self.result: AnalysisResult | None = None
        self._batch_results: list[AnalysisResult] = []
        self._failed_paths: list[str] = []
        self._focus_source_file = ""
        self._placeholder_active = True
        self._cancel_batch = False
        self._batch_row_tags: dict[str, str] = {}
        self._search_after_id: str | None = None
        self._layout_after: str | None = None
        self._layout_w = 0
        self._hint_wrap = 640
        self._job_track = False
        self._tabs_compact = False
        self._toolbar_mode = ""
        self._summary_stacked = False
        self._filters_stacked = False
        self._panels_result_id: int | None = None
        self._allowlist_path = str(self._prefs.get("allowlist_path") or "") or None
        self._verdict_path = str(self._prefs.get("verdict_path") or "") or None
        self._handoff_template_path = (
            str(self._prefs.get("handoff_template_path") or "") or None
        )
        self._brands_path = str(self._prefs.get("brands_path") or "") or None
        self._profile_dir = str(self._prefs.get("profile_dir") or "") or None
        self._handoff_by_level: dict[str, str] | None = None
        self._job_busy = False
        self._hint_default = "Откройте письмо или вставьте RFC822 · затем вкладка «Вердикт»"
        self._flash_after_id: str | None = None

        _cat_defaults = {
            "Сеть": True,
            "Хеши и CVE": True,
            "Хост": True,
            "Крипто": False,
        }
        self.cat_vars = {
            name: ctk.BooleanVar(
                value=bool(self._prefs.get(CAT_PREF_KEYS[name], _cat_defaults[name]))
            )
            for name in CATEGORY_TYPES
        }
        self.hide_rewriter = ctk.BooleanVar(value=bool(self._prefs.get("hide_rewriter", True)))
        self.hide_allowlisted = ctk.BooleanVar(
            value=bool(self._prefs.get("hide_allowlisted", True))
        )
        self.hide_private = ctk.BooleanVar(value=bool(self._prefs.get("hide_private", True)))
        # Default ON for email triage: show actionable evidence first
        self.actionable_only = ctk.BooleanVar(
            value=bool(self._prefs.get("actionable_only", True))
        )
        self.full_ioc_types = ctk.BooleanVar(
            value=bool(self._prefs.get("full_ioc_types", False))
        )
        self._export_choice = ctk.StringVar(
            value=str(self._prefs.get("export_choice") or "JSON")
        )
        self._copy_format = ctk.StringVar(
            value=str(self._prefs.get("copy_format") or "type|value")
        )
        self._search_var = ctk.StringVar(value="")
        self._last_dir = str(self._prefs.get("last_dir") or "") or str(app_dir())
        self._last_export_dir = str(self._prefs.get("last_export_dir") or "") or ""

        self._build()
        if self._verdict_compact:
            self._apply_verdict_compact()
        self._verdict_extra_warnings = probe_verdict_extra_warnings(self._verdict_path)
        self._try_hook_drop()
        self._bind_global_hotkeys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._search_var.trace_add("write", lambda *_: self._schedule_search_refresh())
        # Startup self-check (QR + configs beside EXE)
        try:
            lines = build_self_check_lines(
                profile_dir=self._profile_dir,
                verdict_path=self._verdict_path,
                verdict_warnings=self._verdict_extra_warnings,
            )
            short = " · ".join(lines[:2])
            if self._verdict_extra_warnings:
                short = f"⚠ verdict_extra · {short}"
            self.after(200, lambda: self._set_status(short[:180]))
        except (OSError, AttributeError, TypeError, ValueError):
            pass

    # ------------------------------------------------------------------ UI
    def _on_window_configure(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if event.widget is not self:
            return
        w = int(getattr(event, "width", 0) or 0)
        if bool(self._filters_open.get()):
            self._position_filters_overlay()
        # Ignore the noise of a drag; panes already scale with grid weights.
        if w and abs(w - self._layout_w) < 24:
            return
        self._layout_w = w
        if self._layout_after:
            try:
                self.after_cancel(self._layout_after)
            except Exception:  # noqa: BLE001
                pass
        self._layout_after = self.after(280, self._apply_window_layout)

    def _apply_window_layout(self) -> None:
        """Settle hint wrapping after a resize. Do not move the main panes."""
        self._layout_after = None
        try:
            right_w = max(self._right.winfo_width() - 48, 200)
            if abs(right_w - self._hint_wrap) >= 64:
                self._hint_wrap = right_w
                self.filter_hint.configure(wraplength=right_w)
        except Exception:  # noqa: BLE001
            pass

    # ---------------------------------------------------------- placeholder
    def _bind_placeholder(self) -> None:
        widget = getattr(self.input_box, "textbox", None) or getattr(
            self.input_box, "_textbox", None
        )
        if widget is None:
            return
        widget.bind("<FocusIn>", self._on_input_focus_in, add="+")
        widget.bind("<FocusOut>", self._on_input_focus_out, add="+")
        widget.bind("<Key>", self._on_input_key, add="+")
        widget.bind("<<Paste>>", self._on_input_paste, add="+")
        widget.bind("<Control-v>", self._on_input_paste, add="+")
        widget.bind("<Control-V>", self._on_input_paste, add="+")
        widget.bind("<Button-1>", self._on_input_click, add="+")
        widget.bind("<Control-Return>", lambda _e: self.analyze_text_area(), add="+")

    def _show_placeholder(self) -> None:
        self._placeholder_active = True
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", _PLACEHOLDER)
        self.input_box.configure(text_color=COLORS["muted"])

    def _clear_placeholder(self) -> None:
        if not self._placeholder_active:
            return
        self._placeholder_active = False
        self.input_box.delete("1.0", "end")
        self.input_box.configure(text_color=COLORS["text"])

    def _on_input_focus_in(self, _event: object = None) -> None:
        self._clear_placeholder()

    def _on_input_focus_out(self, _event: object = None) -> None:
        if self._placeholder_active:
            return
        if not self.input_box.get("1.0", "end").strip():
            self._show_placeholder()

    def _on_input_key(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._placeholder_active and event.keysym not in (
            "Shift_L",
            "Shift_R",
            "Control_L",
            "Control_R",
            "Alt_L",
            "Alt_R",
            "Tab",
            "Escape",
            "Return",
        ):
            self._clear_placeholder()

    def _on_input_paste(self, _event: object = None) -> None:
        self._clear_placeholder()

    def _on_input_click(self, _event: object = None) -> None:
        self._clear_placeholder()

    # -------------------------------------------------------- text helpers
    def _make_text(self, parent: ctk.CTkFrame) -> ctk.CTkTextbox:
        box = ctk.CTkTextbox(
            parent,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            font=ctk_font("panel"),
            wrap="word",
            activate_scrollbars=True,
        )
        box.pack(fill="both", expand=True, padx=2, pady=2)
        self._configure_result_tags(box)
        return box

    def _tk(self, box: ctk.CTkTextbox):
        return getattr(box, "textbox", None) or getattr(box, "_textbox", None)

    def _panel_font_tuple(self, size_key: str, *, bold: bool = False) -> tuple:
        scale = getattr(self, "_ui_scale", 1.0)
        size = max(12, int(round(FONT[size_key] * scale)))
        if bold:
            return (FONT_UI, size, "bold")
        return (FONT_UI, size)

    def _configure_result_tags(self, box: ctk.CTkTextbox) -> None:
        widget = self._tk(box)
        if widget is None:
            return
        base = self._panel_font_tuple("panel")
        bold = self._panel_font_tuple("panel", bold=True)
        section = self._panel_font_tuple("title", bold=True)
        hero = self._panel_font_tuple("hero", bold=True)
        widget.tag_configure(
            "section", foreground=COLORS["accent"], font=section, spacing1=12, spacing3=6
        )
        widget.tag_configure("hero", font=hero, spacing1=2, spacing3=6)
        widget.tag_configure("muted", foreground=COLORS["muted"], font=base, spacing3=2)
        widget.tag_configure("value", foreground=COLORS["value"], font=bold)
        widget.tag_configure("label", foreground=COLORS["muted"], font=base)
        widget.tag_configure("ok", foreground=COLORS["ok"], font=bold)
        widget.tag_configure("warn", foreground=COLORS["warn"], font=bold)
        widget.tag_configure("danger", foreground=COLORS["danger"], font=bold)
        widget.tag_configure("info", foreground=COLORS["info"], font=bold)
        widget.tag_configure("meta", foreground=COLORS["info"], font=base)
        widget.tag_configure("empty", foreground=COLORS["muted"], font=section)
        widget.tag_configure("ioc_click", foreground=COLORS["value"], font=bold)
        for itype, color in IOC_TYPE_COLORS.items():
            widget.tag_configure(f"type_{itype}", foreground=color, font=bold)
        for sev, color in SEVERITY_COLORS.items():
            widget.tag_configure(f"sev_{sev}", foreground=color, font=bold)
        widget.tag_raise("hero")

    def _apply_panel_fonts(self) -> None:
        panel = ctk_font("panel")
        for box in (
            getattr(self, "mail_box", None),
            getattr(self, "att_box", None),
            getattr(self, "url_box", None),
            getattr(self, "batch_box", None),
            getattr(self, "err_box", None),
        ):
            if box is None:
                continue
            try:
                box.configure(font=panel)
            except Exception:  # noqa: BLE001
                pass
            self._configure_result_tags(box)

    def _on_ioc_table_select(self, ioc: Ioc) -> None:
        # Select only — copy is explicit (Enter / Ctrl+C / кнопка)
        preview = ioc.value if len(ioc.value) <= 64 else ioc.value[:61] + "…"
        self._set_status(f"Выбрано: {ioc.ioc_type.value} · {preview}")

    def _on_ioc_table_copy(self, ioc: Ioc) -> None:
        self.clipboard_clear()
        self.clipboard_append(ioc.value)
        self._set_status(f"Скопировано: {ioc.ioc_type.value} → {ioc.value[:80]}")

    def _on_ioc_table_context(self, ioc: Ioc, x_root: int, y_root: int) -> None:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Копировать value", command=lambda: self._copy_one(ioc.value))
        menu.add_command(
            label="Копировать defanged",
            command=lambda: self._copy_one(defang_value(ioc.value)),
        )
        menu.add_separator()
        menu.add_command(
            label="В allowlist",
            command=lambda: self._allowlist_host_from_ioc(ioc),
        )
        menu.add_command(
            label="Сменить вердикт…",
            command=self._override_verdict,
        )
        menu.add_separator()
        menu.add_command(
            label="Feedback: ложное срабатывание (FP)",
            command=lambda: self._record_feedback("fp"),
        )
        menu.add_command(
            label="Feedback: пропуск (FN)",
            command=lambda: self._record_feedback("fn"),
        )
        menu.add_command(
            label="Feedback: подтвердить вердикт",
            command=lambda: self._record_feedback("confirm"),
        )
        if self.result and any(
            "encrypted_archive" in a.risk_flags for a in (self.result.attachments or [])
        ):
            menu.add_command(
                label="Заметка: шифрованный архив",
                command=self._copy_encrypted_archive_note,
            )
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()

    def _copy_one(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status(f"Скопировано: {value[:80]}")


    def _clear_box(self, box: ctk.CTkTextbox) -> None:
        widget = self._tk(box)
        if widget is None:
            box.delete("1.0", "end")
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")

    def _put(self, box: ctk.CTkTextbox, text: str, *tags: str) -> None:
        widget = self._tk(box)
        if widget is None:
            box.insert("end", text)
            return
        widget.insert("end", text, tags if tags else ())

    def _set_hint_default(self, text: str) -> None:
        self._hint_default = text
        if self._flash_after_id:
            try:
                self.after_cancel(self._flash_after_id)
            except Exception:  # noqa: BLE001
                pass
            self._flash_after_id = None
        if not self._job_busy:
            self.filter_hint.configure(text=text, text_color=COLORS["muted"])

    def _restore_hint(self) -> None:
        self._flash_after_id = None
        if self._job_busy:
            return
        self.filter_hint.configure(text=self._hint_default, text_color=COLORS["muted"])

    def _set_status(self, text: str) -> None:
        try:
            self.status.configure(text=text)
        except Exception:  # noqa: BLE001
            pass
        color = COLORS["text"] if self._job_busy else COLORS["muted"]
        try:
            self.filter_hint.configure(text=text, text_color=color)
        except Exception:  # noqa: BLE001
            pass
        if self._job_busy:
            return
        if self._flash_after_id:
            try:
                self.after_cancel(self._flash_after_id)
            except Exception:  # noqa: BLE001
                pass
        self._flash_after_id = self.after(2800, self._restore_hint)

    def _sync_job_row(self, *, busy: bool | None = None) -> None:
        if busy is not None:
            self._job_busy = busy
        # A single letter must not insert the progress strip: it appears and
        # disappears in one beat and shoves the verdict block.
        show = bool(self._failed_paths) or (self._job_busy and self._job_track)
        self._apply_job_row(show)

    def _apply_job_row(self, show: bool) -> None:
        self._progress.pack_forget()
        self._stop_btn.pack_forget()
        self._retry_btn.pack_forget()
        if self._job_busy:
            self._progress.pack(side="right", padx=(0, 8), pady=6)
            self._stop_btn.configure(state="normal")
            self._stop_btn.pack(side="right", padx=(4, 10), pady=4)
        else:
            self._stop_btn.configure(state="disabled")
            self._progress.set(0)
            if self._failed_paths:
                self._retry_btn.configure(state="normal")
                self._retry_btn.pack(side="right", padx=(4, 10), pady=4)
            else:
                self._retry_btn.configure(state="disabled")
        if show:
            try:
                if not self._job_row.winfo_ismapped():
                    self._job_row.pack(fill="x", padx=10, pady=(0, 4), after=self._summary)
            except Exception:  # noqa: BLE001
                self._job_row.pack(fill="x", padx=10, pady=(0, 4), after=self._summary)
        else:
            self._job_row.pack_forget()


    def _on_tab_selected(self, label: str) -> None:
        key = self._tab_key_by_label.get(label)
        if key:
            self._show_tab_frame(key)

    def _show_tab_frame(self, key: str) -> None:
        self._active_tab_key = key
        frame = self._tab_frames.get(key)
        if frame is None:
            return
        try:
            frame.tkraise()
        except Exception:  # noqa: BLE001
            # Fallback if tkraise unavailable on some CTk builds
            for k, fr in self._tab_frames.items():
                try:
                    if k == key:
                        fr.grid()
                    else:
                        fr.grid_remove()
                except Exception:  # noqa: BLE001
                    pass

    def _mail_tab_relevant(self, result: AnalysisResult) -> bool:
        rows = result.file_rows or []
        if result.source_kind not in ("email", "batch"):
            return False
        return bool(
            result.verdict
            or result.mail_identity
            or result.headers
            or result.raw_headers
            or any(r.kind == "email" for r in rows)
        )

    def _desired_tabs(
        self, result: AnalysisResult | None, filtered_count: int
    ) -> list[tuple[str, str]]:
        return desired_result_tabs(result, filtered_count, compact=self._tabs_compact)

    def _sync_result_tabs(self, result: AnalysisResult | None, filtered_count: int = 0) -> None:
        desired = self._desired_tabs(result, filtered_count)
        labels = [label for _, label in desired]
        key_by_label = {label: key for key, label in desired}
        label_by_key = {key: label for key, label in desired}

        prev_key = self._active_tab_key
        prev_labels = list(getattr(self, "_tab_seg_labels", ()) or ())
        self._tab_key_by_label = key_by_label
        self._tab_label_by_key = label_by_key

        # Rebuild the bar only when the set of tabs changes. The button
        # height stays fixed, so the letter and verdict panes do not move.
        if labels != prev_labels:
            self._tab_seg_labels = tuple(labels)
            self._tab_seg.configure(values=labels)

        if prev_key in label_by_key:
            select_key = prev_key
        elif "mail" in label_by_key:
            select_key = "mail"
        else:
            select_key = desired[0][0]
        select_label = label_by_key[select_key]
        try:
            if self._tab_var.get() != select_label:
                self._tab_var.set(select_label)
                self._tab_seg.set(select_label)
        except Exception:  # noqa: BLE001
            self._tab_var.set(select_label)
            self._tab_seg.set(select_label)
        self._show_tab_frame(select_key)

    def _screen_metrics(self) -> tuple[tuple[int, int], tuple[int, int, int, int]]:
        try:
            self.update_idletasks()
        except Exception:  # noqa: BLE001
            pass
        sw = max(int(self.winfo_screenwidth() or 1320), 640)
        sh = max(int(self.winfo_screenheight() or 820), 480)
        try:
            vx = int(self.winfo_vrootx())
            vy = int(self.winfo_vrooty())
            vw = int(self.winfo_vrootwidth()) or sw
            vh = int(self.winfo_vrootheight()) or sh
        except Exception:  # noqa: BLE001
            vx, vy, vw, vh = 0, 0, sw, sh
        return (sw, sh), (vx, vy, vw, vh)

    def _schedule_search_refresh(self) -> None:
        if self._search_after_id is not None:
            try:
                self.after_cancel(self._search_after_id)
            except Exception:  # noqa: BLE001
                pass
        self._search_after_id = self.after(200, self._run_search_refresh)

    def _run_search_refresh(self) -> None:
        self._search_after_id = None
        self._refresh_views()

    def _clear_file_focus(self) -> None:
        self._focus_source_file = ""
        self._refresh_views()
        self._set_status("Фокус файла снят")

    def _update_focus_hint(self) -> None:
        if self._focus_source_file:
            self.focus_hint.configure(
                text=f"Фокус файла: {self._focus_source_file}  [снять]"
            )
            if not self.focus_clear_btn.winfo_ismapped():
                self.focus_clear_btn.pack(side="right", padx=(8, 0))
        else:
            self.focus_hint.configure(text="")
            self.focus_clear_btn.pack_forget()

    def _goto_ioc_context(self, ioc: Ioc) -> None:
        """Focus source pane on context snippet / value (double-click)."""
        needle = (ioc.context or "").strip() or ioc.value
        if not needle:
            self._copy_one(ioc.value)
            return
        preview = needle[:80]
        box = self.input_box
        try:
            start = box.search(ioc.value, "1.0", tk.END)
            if not start and ioc.context:
                frag = ioc.context.strip()[:40]
                if frag:
                    start = box.search(frag, "1.0", tk.END)
            if start:
                box.see(start)
                end = f"{start}+{len(ioc.value)}c"
                try:
                    box.tag_remove("search_hit", "1.0", "end")
                except Exception:  # noqa: BLE001
                    pass
                try:
                    box.tag_add("search_hit", start, end)
                    box.tag_config("search_hit", background=COLORS["accent_dim"])
                except Exception:  # noqa: BLE001
                    pass
                self._set_status(f"Контекст: {preview}")
            else:
                self._set_status(f"Откуда: {ioc.source or '—'} · {preview}")
                self._copy_one(ioc.value)
        except Exception:  # noqa: BLE001
            self._set_status(f"Откуда: {ioc.source or '—'} · {preview}")
            self._copy_one(ioc.value)

    def _refresh_views(self, *, full: bool = False) -> None:
        if not self.result:
            self._panels_result_id = None
            self.ioc_summary_label.configure(text="")
            self.verdict_badge.configure(text="Вердикт —", text_color=COLORS["muted"])
            self._set_hint_default(
                "Откройте письмо или вставьте RFC822 · затем вкладка «Вердикт»"
            )
            self.source_meta.configure(text="")
            self._sync_result_tabs(None)
            self.ioc_table.clear()
            self.ioc_empty_label.configure(
                text=(
                    "1. Откройте .eml / .msg (или папку с письмами)\n"
                    "2. Смотрите «Вердикт» — score, причины, разбор\n"
                    "3. IOC — доказательства; фильтр «к разбору» включён по умолчанию"
                )
            )
            self._update_focus_hint()
            return

        filtered = self._filtered_iocs()
        counts = Counter(i.ioc_type.value for i in filtered)
        total = len(filtered)
        full_count = len(self.result.iocs)

        self._update_focus_hint()

        if total == full_count:
            self.ioc_summary_label.configure(text=f"доказательства {total}")
            hint = "Вердикт → вложения / URL → IOC · Enter копирует · 2×клик — к фрагменту"
        else:
            self.ioc_summary_label.configure(text=f"доказательства {total}/{full_count}")
            hint = f"Показано {total} из {full_count} · фильтр/поиск · Enter копирует выбранное"
        if total == 0 and full_count > 0:
            hint = "Пусто — снимите «к разбору» или ослабьте «Шум»"
        self._set_hint_default(hint)

        # Type breakdown only in the hint line — not beside the verdict badge
        if counts:
            breakdown = " · ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            try:
                self.filter_hint.configure(text=f"{hint}  ·  {breakdown}")
            except Exception:  # noqa: BLE001
                pass

        self._update_verdict_badge(self.result)
        self._sync_result_tabs(self.result, filtered_count=total)
        self._fill_iocs(self.result, filtered)

        rid = id(self.result)
        if full or self._panels_result_id != rid:
            self._panels_result_id = rid
            self._fill_batch(self.result)
            self._fill_urls(self.result)
            self._fill_attachments(self.result)
            self._fill_mail_tab(self.result)
            self._fill_errors(self.result)
        self._highlight_search_in_panels()

    def _highlight_search_in_panels(self) -> None:
        """Underline the query in verdict reasons and attachment names."""
        query = ""
        try:
            query = str(self._search_var.get() or "").strip()
        except (AttributeError, tk.TclError):
            return
        for name in ("mail_box", "att_box", "url_box"):
            box = getattr(self, name, None)
            if box is None:
                continue
            widget = self._tk(box)
            if widget is None:
                continue
            try:
                widget.tag_remove("search_hit", "1.0", "end")
            except tk.TclError:
                continue
            if len(query) < 2:
                continue
            start = "1.0"
            first = ""
            while True:
                try:
                    start = widget.search(query, start, tk.END, nocase=True)
                except tk.TclError:
                    break
                if not start:
                    break
                end = f"{start}+{len(query)}c"
                try:
                    widget.tag_add("search_hit", start, end)
                except tk.TclError:
                    break
                if not first:
                    first = start
                start = end
            if first:
                try:
                    widget.tag_config("search_hit", background=COLORS["accent_dim"])
                    widget.see(first)
                except tk.TclError:
                    pass

    def _update_verdict_badge(self, result: AnalysisResult) -> None:
        v = result.verdict
        if not v:
            self.verdict_badge.configure(text="Вердикт —", text_color=COLORS["muted"])
            return
        color = VERDICT_COLORS.get(v.level.value, COLORS["muted"])
        self.verdict_badge.configure(
            text=f"{v.level.value.upper()} · {v.score}",
            text_color=color,
        )

    def show_about(self) -> None:
        # Defer past the button release so the dialog is not created under the click.
        self.after(10, self._open_about)

    def _open_about(self) -> None:
        try:
            show_about_dialog(
                parent=self,
                appearance_mode=self._appearance_mode,
                ioc_density=self._ioc_density,
                result=self.result,
                profile_dir=self._profile_dir,
                verdict_path=self._verdict_path,
                verdict_warnings=getattr(self, "_verdict_extra_warnings", None),
            )
        except Exception as exc:  # noqa: BLE001
            from tkinter import messagebox

            messagebox.showerror(__app_name__, f"О программе: {exc}", parent=self)


def run() -> None:
    enforce_offline()
    apply_global_fonts()
    try:
        app = ExtractorApp()
    except tk.TclError as exc:
        raise SystemExit(
            f"GUI недоступен ({exc}). Используйте CLI: python -m reliquary.cli <файл>"
        ) from exc
    app.mainloop()
