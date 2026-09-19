"""Hard offline guarantee — Email IOC Extractor must never phone home.

Imported at app start. Blocks common outbound helpers if somehow called.
Must run AFTER third-party imports so class patching is safe.
"""

from __future__ import annotations

import socket


class OfflineViolation(RuntimeError):
    """Raised when code attempts network I/O."""


def _blocked(*_args, **_kwargs):
    raise OfflineViolation(
        "Email IOC Extractor работает строго офлайн: сетевые соединения запрещены."
    )


def _blocked_getaddrinfo(*_args, **_kwargs):
    raise OfflineViolation(
        "Email IOC Extractor работает строго офлайн: DNS/getaddrinfo запрещены."
    )


def enforce_offline() -> None:
    """Fail-closed at the socket layer (connect + DNS).

    Avoid replacing ``http.client.HTTPConnection`` with a function — urllib3
    subclasses those classes at import time and breaks if they are callables.
    """
    socket.create_connection = _blocked  # type: ignore[assignment]
    socket.socket.connect = _blocked  # type: ignore[method-assign, assignment]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign, assignment]
    socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]
    try:
        socket.gethostbyname = _blocked_getaddrinfo  # type: ignore[assignment]
        socket.gethostbyname_ex = _blocked_getaddrinfo  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass

    # Soft-block high-level helpers if already imported (do not replace classes).
    try:
        import urllib.request as ureq

        ureq.urlopen = _blocked  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass
