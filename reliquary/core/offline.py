"""Hard offline guarantee — Reliquary must never phone home.

Imported at app start. Blocks common outbound helpers if somehow called.
"""

from __future__ import annotations

import socket


class OfflineViolation(RuntimeError):
    """Raised when code attempts network I/O."""


def _blocked(*_args, **_kwargs):
    raise OfflineViolation(
        "Reliquary работает строго офлайн: сетевые соединения запрещены."
    )


def enforce_offline() -> None:
    """Monkey-patch socket.create_connection to fail closed."""
    socket.create_connection = _blocked  # type: ignore[assignment]
