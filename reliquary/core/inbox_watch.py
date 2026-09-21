"""Poll a watch-inbox directory for new .eml/.msg (offline, no network)."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

from reliquary.core.formats import collect_supported


class InboxWatcher:
    """Simple mtime/set poller — no inotify dependency (air-gap friendly)."""

    def __init__(
        self,
        folder: str | Path,
        on_new: Callable[[list[str]], None],
        *,
        interval_s: float = 3.0,
        recursive: bool = True,
    ) -> None:
        self.folder = Path(folder)
        self.on_new = on_new
        self.interval_s = max(1.0, float(interval_s))
        self.recursive = recursive
        self._seen: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def seed(self) -> None:
        if self.folder.is_dir():
            self._seen = set(collect_supported(self.folder, recursive=self.recursive))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.seed()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="inbox-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            if not self.folder.is_dir():
                continue
            try:
                current = set(collect_supported(self.folder, recursive=self.recursive))
            except OSError:
                continue
            fresh = sorted(current - self._seen)
            self._seen |= current
            if fresh:
                try:
                    self.on_new(fresh)
                except Exception:
                    # Watcher must not die on consumer errors
                    continue


def sleep_brief() -> None:
    """Test helper."""
    time.sleep(0.05)
