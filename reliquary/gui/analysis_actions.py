"""Open / batch / text analysis actions — mixin for ExtractorApp."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from reliquary import __app_name__
from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.batch import default_max_workers, format_eta, run_batch
from reliquary.core.error_log import append_error_log
from reliquary.core.formats import (
    cleanup_ingest_dirs,
    collect_supported,
    expand_input_paths,
    ingest_problem_notes,
    take_ingest_notes,
    tk_filetypes,
)
from reliquary.core.models import AnalysisResult
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_text

_PREVIEW_CAP = 4000


def source_panel_text(result: AnalysisResult) -> str:
    """Left-hand source text. Says when only the first N characters are shown."""
    preview = result.raw_text_preview or ""
    lines = [
        f"Файл: {result.source_path}",
        f"Тип: {result.source_kind}",
    ]
    if result.sender:
        lines.append(f"From: {result.sender}")
    if result.subject:
        lines.append(f"Subject: {result.subject}")
    if result.verdict:
        lines.append(f"Вердикт: {result.verdict.level.value} · {result.verdict.score}")
    for note in result.status_notes:
        if note and note not in lines:
            lines.append(note)
    total = int(result.body_chars or 0)
    if preview and (len(preview) >= _PREVIEW_CAP or total > len(preview)):
        lines.append(f"Показаны первые {len(preview)} символов")
    lines.extend(["=" * 40, "", preview])
    return "\n".join(lines)


def _source_meta_line(kind: str, name: str, subject: str) -> str:
    """File name and subject on two lines. The subject is not cut."""
    subject = " ".join((subject or "").split())
    name = name or ""
    if name and subject:
        return f"{name}\n{subject}"
    if name:
        return f"{kind}  ·  {name}" if kind else name
    return subject or kind


def cancel_in_progress_status(current_name: str = "") -> str:
    name = (current_name or "").strip()
    if name:
        return f"Отмена: {name} ещё дочитывается"
    return "Отмена: текущий файл ещё дочитывается"


def cancelled_batch_status() -> str:
    return "Отменено: текущий файл дочитан, результат не применён"


class AnalysisActionsMixin:
    """Requires ExtractorApp prefs, widgets, and ``_apply_result`` helpers."""

    def _analysis_options(self) -> AnalysisOptions:
        opts = AnalysisOptions(
            allowlist_path=getattr(self, "_allowlist_path", None),
            verdict_path=getattr(self, "_verdict_path", None),
            handoff_template_path=getattr(self, "_handoff_template_path", None),
            brands_path=getattr(self, "_brands_path", None),
            profile_dir=getattr(self, "_profile_dir", None),
            max_workers=int(self._prefs.get("max_workers") or 0),
            skip_broken=bool(self._prefs.get("skip_broken", True)),
            yara_rules_path=str(self._prefs.get("yara_rules_path") or "") or None,
            enable_yara=bool(self._prefs.get("enable_yara", False)),
        )
        old = getattr(self, "_org_profile", None)
        if old is not None:
            try:
                old.cleanup()
            except (OSError, AttributeError, RuntimeError):
                pass
            self._org_profile = None
        profile = load_org_profile(opts.profile_dir)
        self._org_profile = profile
        if profile is not None:
            opts = opts.with_profile(profile)
            self._handoff_by_level = {
                k: str(v) for k, v in (profile.handoff_by_level or {}).items()
            } or None
            # Remember resolved profile path for About / prefs
            if not getattr(self, "_profile_dir", None):
                self._profile_dir = str(profile.root)
        return opts

    def cancel_batch(self) -> None:
        self._cancel_batch = True
        self._set_status(cancel_in_progress_status())

    def analyze_text_area(self) -> None:
        if self._placeholder_active:
            messagebox.showinfo(__app_name__, "Вставьте исходник письма (RFC822) слева")
            return
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo(__app_name__, "Вставьте исходник письма (RFC822) слева")
            return
        self._cancel_batch = False
        self._job_track = False
        self._sync_job_row(busy=True)
        self._set_status("Разбор письма…")
        threading.Thread(target=self._run_text, args=(text,), daemon=True).start()

    def _run_text(self, text: str) -> None:
        try:
            if self._cancel_batch:
                self.after(0, lambda: self._sync_job_row(busy=False))
                self.after(0, lambda: self._set_status(cancelled_batch_status()))
                return
            result = analyze_text(text, options=self._analysis_options())
            if self._cancel_batch:
                self.after(0, lambda: self._sync_job_row(busy=False))
                self.after(0, lambda: self._set_status(cancelled_batch_status()))
                return

            def _ok() -> None:
                self._sync_job_row(busy=False)
                self._apply_result(result, preload_text=False)

            self.after(0, _ok)
        except Exception as exc:  # noqa: BLE001
            append_error_log("text analysis failed", exc=exc)
            msg = str(exc)

            def _fail() -> None:
                self._sync_job_row(busy=False)
                messagebox.showerror("Ошибка", msg)
                self._set_status("Ошибка разбора")

            self.after(0, _fail)

    def retry_failed(self) -> None:
        if not self._failed_paths:
            return
        paths = list(self._failed_paths)
        self._analyze_paths(paths)

    def open_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title=f"{__app_name__} — открыть письма",
            initialdir=self._last_dir or None,
            filetypes=tk_filetypes(),
        )
        if not paths:
            return
        self._last_dir = str(Path(paths[0]).parent)
        self._persist_prefs()
        expanded = expand_input_paths(list(paths))
        notes = take_ingest_notes()
        if not expanded:
            cleanup_ingest_dirs()
            self._show_ingest_notes(notes or ["Не удалось разобрать выбранные файлы."], dialog=True)
            return
        self._pending_ingest_notes = ingest_problem_notes(notes)
        self._announce_ingest_notes(self._pending_ingest_notes)
        self._analyze_paths(expanded)

    def open_folder(self) -> None:
        folder = filedialog.askdirectory(
            title=f"{__app_name__} — папка с письмами",
            initialdir=self._last_dir or None,
        )
        if not folder:
            return
        self._last_dir = folder
        self._persist_prefs()
        paths = collect_supported(Path(folder), recursive=True)
        notes = take_ingest_notes()
        if not paths:
            cleanup_ingest_dirs()
            text = "\n".join(notes) if notes else "В папке нет писем (.eml / .msg / .mbox / .pst)."
            self._show_ingest_notes(ingest_problem_notes(notes) or [text], dialog=True)
            return
        try:
            threshold = int(self._prefs.get("folder_warn_threshold") or 80)
        except (TypeError, ValueError):
            threshold = 80
        if len(paths) > threshold:
            if not messagebox.askyesno(
                __app_name__,
                f"Найдено писем: {len(paths)} (порог: {threshold}).\n"
                "Продолжить пакетный разбор?",
            ):
                cleanup_ingest_dirs()
                return
        self._pending_ingest_notes = ingest_problem_notes(notes)
        self._announce_ingest_notes(self._pending_ingest_notes)
        self._analyze_paths(paths)

    def _on_drop(self, files) -> None:
        from reliquary.core.formats import SUPPORTED_SUFFIXES

        paths: list[str] = []
        for item in files:
            if isinstance(item, bytes):
                for enc in ("utf-8", "mbcs"):
                    try:
                        item = item.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    item = item.decode("utf-8", errors="replace")
            path = Path(str(item))
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
                paths.append(str(path))
            elif path.is_dir():
                paths.extend(collect_supported(path, recursive=True))
        paths = expand_input_paths(sorted(set(paths)))
        notes = take_ingest_notes()
        if not paths:
            cleanup_ingest_dirs()

            def _empty() -> None:
                text = "\n".join(notes) if notes else "Нет писем (.eml / .msg / .mbox / .pst) для разбора"
                self._show_ingest_notes(ingest_problem_notes(notes) or [text], dialog=True)

            self.after(0, _empty)
            return
        self._pending_ingest_notes = ingest_problem_notes(notes)
        self.after(0, lambda: self._announce_ingest_notes(self._pending_ingest_notes))
        self.after(0, lambda: self._analyze_paths(paths))

    def _analyze_paths(self, paths: list[str]) -> None:
        self._cancel_batch = False
        self._job_track = len(paths) > 1
        self._focus_source_file = ""
        names = ", ".join(Path(p).name for p in paths[:3])
        extra = f" (+{len(paths) - 3})" if len(paths) > 3 else ""
        self._sync_job_row(busy=True)
        self._progress.set(0)
        self._set_status(f"Разбор 0/{len(paths)}: {names}{extra}…")
        self.update_idletasks()
        threading.Thread(target=self._run_paths, args=(paths,), daemon=True).start()

    def _run_paths(self, paths: list[str]) -> None:
        workers = default_max_workers(int(self._prefs.get("max_workers") or 0) or None)
        skip_broken = bool(self._prefs.get("skip_broken", True))

        def _on_progress(done: int, total: int, name: str, eta: float | None) -> None:
            eta_s = format_eta(eta)
            label = f"Разбор {done}/{total}: {name}"
            if eta_s:
                label += f" · осталось {eta_s}"
            frac = done / total if total else 0

            def _ui() -> None:
                self._batch_current_name = name
                if self._cancel_batch:
                    self._set_status(cancel_in_progress_status())
                else:
                    self._set_status(label)
                try:
                    self._progress.set(frac)
                except Exception:  # noqa: BLE001
                    pass

            self.after(0, _ui)

        try:
            outcome = run_batch(
                paths,
                max_workers=workers,
                skip_broken=skip_broken,
                is_cancelled=lambda: self._cancel_batch,
                on_progress=_on_progress,
                options=self._analysis_options(),
            )
        except Exception as exc:  # noqa: BLE001
            append_error_log("batch analysis failed", exc=exc)
            err = str(exc)

            def _fail() -> None:
                cleanup_ingest_dirs()
                self._sync_job_row(busy=False)
                messagebox.showerror("Ошибка", err)
                self._set_status("Ошибка разбора")

            self.after(0, _fail)
            return

        def _finish() -> None:
            cleanup_ingest_dirs()
            self._set_failed(outcome.failed)
            self._sync_job_row(busy=False)
            if outcome.cancelled:
                self._set_status(cancelled_batch_status())
                return
            if outcome.result is None:
                msg = "Не удалось разобрать ни одного письма.\n" + "\n".join(
                    outcome.errors[:8]
                )
                if outcome.failed:
                    msg += "\n\nFailed:\n" + "\n".join(
                        Path(p).name for p in outcome.failed[:12]
                    )
                append_error_log(f"batch empty result: {msg}")
                messagebox.showerror("Ошибка", msg)
                self._set_status("Ошибка разбора")
                return
            self._apply_result(
                outcome.result,
                preload_text=True,
                batch_results=outcome.batch_results,
                failed=outcome.failed,
            )
            if outcome.failed:
                self._set_status(
                    f"Готово с пропусками: {len(outcome.failed)} — вкладка «Ошибки»"
                )

        self.after(0, _finish)

    def _set_failed(self, failed: list[str]) -> None:
        self._failed_paths = list(failed)
        self._sync_job_row()

    def _announce_ingest_notes(self, notes: list[str]) -> None:
        clean = [n for n in notes if (n or "").strip()]
        if not clean:
            return
        messagebox.showinfo(__app_name__, "\n".join(clean))

    def _show_ingest_notes(self, notes: list[str], *, dialog: bool = False) -> None:
        """Keep mailbox/PST remarks on the notes tab until the analyst closes them."""
        clean = [n for n in notes if (n or "").strip()]
        if not clean:
            return
        self._extra_remarks = list(getattr(self, "_extra_remarks", []) or [])
        for note in clean:
            if note not in self._extra_remarks:
                self._extra_remarks.append(note)
        self._remarks_dismissed = False
        if dialog:
            messagebox.showinfo(__app_name__, "\n".join(clean))
        self._set_status(clean[0] if len(clean) == 1 else " · ".join(clean))
        if getattr(self, "result", None) is not None:
            self._refresh_views(full=True)
            return
        try:
            self._sync_result_tabs(None)
            self._fill_errors(None)
            if "err" in getattr(self, "_tab_label_by_key", {}):
                self._hotkey_tab("err")
        except (AttributeError, tk.TclError):
            pass

    def _open_batch_path(self, rows: list) -> str:
        """Path of the row the batch table already puts first."""
        from reliquary.core.pipeline import sort_batch_rows

        col = str(getattr(self, "_batch_sort_col", "score") or "score")
        reverse = bool(getattr(self, "_batch_sort_reverse", True))
        ordered = sort_batch_rows(rows, column=col, reverse=reverse)
        return ordered[0].path if ordered else ""

    def _present_batch_message(self, path: str, *, preload_text: bool = True) -> None:
        """Open one already-scored message and keep the batch table and peers."""
        from copy import copy

        batch = list(getattr(self, "_batch_results", None) or [])
        target = next((r for r in batch if r.source_path == path), None)
        if target is None:
            name = Path(path).name
            target = next((r for r in batch if Path(r.source_path).name == name), None)
        if target is None:
            self._set_status(f"Нет письма: {path}")
            return
        merged = getattr(self, "_batch_merged", None)
        shown = copy(target)
        rows = list(getattr(merged, "file_rows", None) or [])
        if len(rows) >= 2:
            shown.file_rows = rows
        self.result = shown
        self._focus_source_file = target.source_path
        self._panels_result_id = None
        kind = shown.source_kind
        name = Path(shown.source_path).name if shown.source_path else ""
        self.source_meta.configure(text=_source_meta_line(kind, name, shown.subject or ""))
        if preload_text:
            self._placeholder_active = False
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", source_panel_text(shown))
            from reliquary.gui.theme import COLORS

            self.input_box.configure(text_color=COLORS["text"])
        self._refresh_views(full=True)
        try:
            idx = next(i for i, r in enumerate(batch) if r.source_path == target.source_path)
        except StopIteration:
            idx = 0
        self._set_status(f"Письмо {idx + 1}/{len(batch)}: {name}")

    def _apply_result(
        self,
        result: AnalysisResult,
        preload_text: bool,
        batch_results: list[AnalysisResult] | None = None,
        failed: list[str] | None = None,
    ) -> None:
        self._batch_results = list(batch_results or ([result] if result else []))
        self._batch_merged = result
        self._panels_result_id = None
        self._set_failed(failed or [])
        notices = list(getattr(self, "_pending_ingest_notes", None) or [])
        self._pending_ingest_notes = []
        if notices:
            self._extra_remarks = list(getattr(self, "_extra_remarks", []) or []) + notices
            self._remarks_dismissed = False
        if len(self._batch_results) >= 2 and result.file_rows:
            opened = self._open_batch_path(result.file_rows)
            self._present_batch_message(
                opened or self._batch_results[0].source_path,
                preload_text=preload_text,
            )
            return
        self.result = result
        kind = result.source_kind
        name = Path(result.source_path).name if result.source_path else ""
        self.source_meta.configure(text=_source_meta_line(kind, name, result.subject or ""))

        if preload_text:
            self._placeholder_active = False
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", source_panel_text(result))
            from reliquary.gui.theme import COLORS

            self.input_box.configure(text_color=COLORS["text"])

        self._refresh_views()
        if result.errors:
            self._set_status(f"Замечания: {len(result.errors)} — вкладка «Ошибки»")
