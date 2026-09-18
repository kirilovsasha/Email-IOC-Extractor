"""Hard offline guarantee — IOC Extractor must never phone home.

Imported at app start. Blocks common outbound helpers if somehow called.
"""

from __future__ import annotations

import socket
import ssl


class OfflineViolation(RuntimeError):
    """Raised when code attempts network I/O."""


def _blocked(*_args, **_kwargs):
    raise OfflineViolation(
        "IOC Extractor работает строго офлайн: сетевые соединения запрещены."
    )


def _blocked_getaddrinfo(*_args, **_kwargs):
    raise OfflineViolation(
        "IOC Extractor работает строго офлайн: DNS/getaddrinfo запрещены."
    )


def enforce_offline() -> None:
    """Fail-closed: block socket connect, DNS, and SSL wrap that implies I/O."""
    socket.create_connection = _blocked  # type: ignore[assignment]
    socket.socket.connect = _blocked  # type: ignore[method-assign, assignment]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign, assignment]
    socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]
    try:
        socket.gethostbyname = _blocked_getaddrinfo  # type: ignore[assignment]
        socket.gethostbyname_ex = _blocked_getaddrinfo  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass
    try:
        ssl.SSLContext.wrap_socket = _blocked  # type: ignore[method-assign, assignment]
    except Exception:  # noqa: BLE001
        pass

    for mod_name in ("urllib.request", "http.client"):
        try:
            __import__(mod_name)
            import sys

            mod = sys.modules[mod_name]
            for attr in ("urlopen", "Request", "HTTPConnection", "HTTPSConnection"):
                if hasattr(mod, attr):
                    try:
                        setattr(mod, attr, _blocked)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            continue
