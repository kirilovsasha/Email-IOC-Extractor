"""Open / batch / text analysis actions — mixin for ExtractorApp."""

from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog, messagebox

from reliquary import __app_name__
from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.batch import default_max_workers, format_eta, run_batch
from reliquary.core.calibration import calibrate_inbox
from reliquary.core.error_log import append_error_log
from reliquary.core.formats import collect_supported, tk_filetypes
from reliquary.core.models import AnalysisResult
from reliquary.core.org_profile import load_org_profile
from reliquary.core.paths import app_dir
from reliquary.core.pipeline import analyze_text


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

    def calibrate_inbox_folder(self) -> None:
        """Калибровка папки inbox → текстовый отчёт рядом с EXE (без БД)."""
        folder = filedialog.askdirectory(
            title=f"{__app_name__} — папка inbox для калибровки",
            initialdir=self._last_dir or None,
        )
        if not folder:
            return
        self._last_dir = folder
        self._persist_prefs()
        self._sync_job_row(busy=True)
        self._set_status("Калибровка inbox…")

        def _run() -> None:
            try:
                report = calibrate_inbox(folder)
                out = app_dir() / "calibration_inbox_report.txt"
                out.write_text(report.to_text(), encoding="utf-8")

                def _ok() -> None:
                    self._sync_job_row(busy=False)
                    # Show in errors / status
                    if hasattr(self, "err_box"):
                        self._clear_box(self.err_box)
                        self._put(self.err_box, report.to_text(), "value")
                        if "err" in getattr(self, "_tab_label_by_key", {}):
                            label = self._tab_label_by_key["err"]
                            self._tab_var.set(label)
                            self._tab_seg.set(label)
                            self._show_tab_frame("err")
                    self._set_status(f"Калибровка: {out.name} ({report.scored}/{report.file_count})")
                    messagebox.showinfo(
                        __app_name__,
                        f"Калибровка завершена.\n"
                        f"Файлов: {report.file_count}, со score: {report.scored}\n"
                        f"Отчёт: {out}",
                    )

                self.after(0, _ok)
            except Exception as exc:  # noqa: BLE001
                append_error_log("inbox calibration failed", exc=exc)
                msg = str(exc)

                def _fail() -> None:
                    self._sync_job_row(busy=False)
                    messagebox.showerror("Ошибка", msg)
                    self._set_status("Ошибка калибровки")

                self.after(0, _fail)

        threading.Thread(target=_run, daemon=True).start()

    def cancel_batch(self) -> None:
        self._cancel_batch = True
        self._set_status("Отмена…")

    def analyze_text_area(self) -> None:
        if self._placeholder_active:
            messagebox.showinfo(__app_name__, "Вставьте исходник письма (RFC822) слева")
            return
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo(__app_name__, "Вставьте исходник письма (RFC822) слева")
            return
        self._cancel_batch = False
        self._sync_job_row(busy=True)
        self._set_status("Разбор письма…")
        threading.Thread(target=self._run_text, args=(text,), daemon=True).start()

    def _run_text(self, text: str) -> None:
        try:
            if self._cancel_batch:
                self.after(0, lambda: self._sync_job_row(busy=False))
                self.after(0, lambda: self._set_status("Отменено"))
                return
            result = analyze_text(text, options=self._analysis_options())
            if self._cancel_batch:
                self.after(0, lambda: self._sync_job_row(busy=False))
                self.after(0, lambda: self._set_status("Отменено"))
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
        self._analyze_paths(list(paths))

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
        if not paths:
            messagebox.showinfo(
                __app_name__,
                "В папке нет писем (.eml / .msg).",
            )
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
                return
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
        paths = sorted(set(paths))
        if not paths:
            self.after(
                0,
                lambda: messagebox.showinfo(
                    __app_name__, "Нет писем (.eml / .msg) для разбора"
                ),
            )
            return
        self.after(0, lambda: self._analyze_paths(paths))

    def _analyze_paths(self, paths: list[str]) -> None:
        self._cancel_batch = False
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
                self._sync_job_row(busy=False)
                messagebox.showerror("Ошибка", err)
                self._set_status("Ошибка разбора")

            self.after(0, _fail)
            return

        def _finish() -> None:
            self._set_failed(outcome.failed)
            self._sync_job_row(busy=False)
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

    def _apply_result(
        self,
        result: AnalysisResult,
        preload_text: bool,
        batch_results: list[AnalysisResult] | None = None,
        failed: list[str] | None = None,
    ) -> None:
        self.result = result
        self._batch_results = list(batch_results or ([result] if result else []))
        self._panels_result_id = None
        self._set_failed(failed or [])
        kind = result.source_kind
        name = Path(result.source_path).name if result.source_path else ""
        if result.subject:
            self.source_meta.configure(text=f"{name}  ·  {result.subject}")
        else:
            self.source_meta.configure(text=f"{kind}  ·  {name}" if name else kind)

        if preload_text:
            preview = result.raw_text_preview or ""
            meta_lines = [
                f"Файл: {result.source_path}",
                f"Тип: {result.source_kind}",
            ]
            if result.sender:
                meta_lines.append(f"From: {result.sender}")
            if result.subject:
                meta_lines.append(f"Subject: {result.subject}")
            if result.verdict:
                meta_lines.append(
                    f"Вердикт: {result.verdict.level.value} · {result.verdict.score}"
                )
            meta_lines.extend(["=" * 40, "", preview])
            self._placeholder_active = False
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", "\n".join(meta_lines))
            from reliquary.gui.theme import COLORS

            self.input_box.configure(text_color=COLORS["text"])

        self._refresh_views()
        if result.errors:
            self._set_status(f"Замечания: {len(result.errors)} — вкладка «Ошибки»")
