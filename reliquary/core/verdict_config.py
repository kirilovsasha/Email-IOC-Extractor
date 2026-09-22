"""VerdictConfig + local JSON overrides (offline, no DB)."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from reliquary.core.paths import app_dir

URGENCY_RE = re.compile(
    r"(?i)\b("
    r"urgent|immediately|verify your account|password.{0,10}expir|"
    r"confirm your identity|suspend|locked|invoice attached|"
    r"срочно|немедленно|подтвердите|пароль.{0,15}истек|"
    r"заблокир|счёт|счет|оплатите|выписка|безопасность аккаунта"
    r")\b"
)

_EXTRA_NAME = "verdict_extra.json"


@dataclass
class VerdictConfig:
    threshold_malicious: int = 60
    threshold_suspicious: int = 30
    threshold_unknown: int = 10
    weight_header_critical: int = 35
    weight_header_high: int = 25
    weight_header_medium: int = 12
    weight_header_low: int = 4
    weight_attachment_flag: int = 20
    weight_attachment_soft: int = 8
    weight_encrypted_archive: int = 22
    weight_url_rewrite: int = 5
    weight_url_raw_ip: int = 18
    weight_suspicious_tld: int = 10
    weight_urgency: int = 15
    weight_links_and_attachments: int = 10
    weight_credential_harvest: int = 14
    weight_bec_payment: int = 20
    weight_href_mismatch: int = 18
    weight_hidden_text: int = 10
    weight_html_form: int = 8
    weight_qr_only: int = 16
    weight_qr_present: int = 8
    weight_lookalike: int = 22
    weight_idn: int = 12
    weight_attachment_iso: int = 18
    weight_attachment_lnk: int = 16
    weight_attachment_onenote: int = 14
    weight_pdf_javascript: int = 18
    weight_html_smuggling: int = 20
    weight_html_attachment: int = 10
    weight_url_shortener: int = 10
    weight_messenger_only: int = 14
    weight_display_spoof: int = 20
    weight_pdf_uri_action: int = 12
    weight_cab_archive: int = 14
    weight_lnk_dangerous: int = 22
    weight_archive_nested_email: int = 16
    weight_zip_bomb: int = 18
    weight_archive_password: int = 8
    weight_archive_password_match: int = 22
    weight_oob_delivery: int = 16
    weight_tnef: int = 10
    weight_iso_lnk: int = 18
    weight_allowlisted_from: int = -10
    weight_office_hyperlink: int = 12
    weight_nested_archive: int = 14
    weight_archive_double_extension: int = 16
    weight_script_attachment: int = 20
    weight_disk_image: int = 16
    weight_cloud_lure: int = 14
    weight_yara_match: int = 25
    weight_messenger_lure: int = 12
    weight_qr_lure: int = 12
    weight_qr_credential: int = 18
    weight_iso_exe: int = 16
    weight_office_remote_template: int = 20
    weight_html_polyglot: int = 18
    weight_rar_archive: int = 10
    weight_spf_lookalike: int = 14
    weight_reply_to_spoof: int = 10
    # 2.17 — wrap×lure, ARC/reply-chain, campaign, attachment/HTML depth
    weight_wrap_lure: int = 12
    weight_return_path_mismatch: int = 10
    weight_arc_fail: int = 12
    weight_reply_chain_anomaly: int = 14
    weight_campaign_divergence: int = 10
    weight_office_dde: int = 18
    weight_ole_package: int = 16
    weight_pdf_openaction_uri: int = 14
    weight_cid_phishing: int = 12
    weight_form_action_suspicious: int = 14
    # Mitigating (negative) signals — reduce score when auth/path looks trusted
    weight_dmarc_pass_aligned: int = -12
    weight_auth_full_pass: int = -6
    weight_internal_relay: int = -8
    weight_auto_reply: int = -10
    weight_calendar_invite: int = -8
    weight_corp_signature: int = -5
    weight_thread_reply: int = -4
    weight_mailing_list: int = -8
    # Per-category caps (evidence stacking without score explosion)
    cap_headers: int = 45
    cap_attachments: int = 40
    cap_urls: int = 30
    cap_content: int = 40
    cap_lookalike: int = 30
    # Display-spoof alone should not pin every spoof case at 100
    cap_display_spoof: int = 28
    # Max absolute mitigation (floor on how much score can be reduced)
    cap_mitigation: int = 30


_CONFIG_KEYS = frozenset(f.name for f in fields(VerdictConfig))


def default_extra_verdict_path() -> Path:
    return app_dir() / _EXTRA_NAME


def resolve_verdict_path(explicit: str | Path | None = None) -> Path | None:
    """Explicit path wins; otherwise ``verdict_extra.json`` next to app if present."""
    if explicit is not None and str(explicit).strip():
        return Path(str(explicit).strip())
    candidate = default_extra_verdict_path()
    return candidate if candidate.is_file() else None


def parse_verdict_overrides(data: dict) -> dict[str, int]:
    """Keep only known VerdictConfig int fields from a JSON object."""
    out: dict[str, int] = {}
    for key, raw in data.items():
        if key.startswith("_") or key not in _CONFIG_KEYS:
            continue
        try:
            out[key] = int(raw)
        except (TypeError, ValueError):
            continue
    return out


def validate_verdict_extra(data: dict) -> list[str]:
    """Lightweight schema check for ``verdict_extra.json`` (no external jsonschema).

    Returns human-readable warnings; empty list means OK. Unknown keys under
    ``_`` prefix are ignored (comments). Integer fields must be in a sane range.
    """
    warnings: list[str] = []
    if not isinstance(data, dict):
        return ["корень должен быть объектом JSON"]
    for key, raw in data.items():
        if key.startswith("_"):
            continue
        if key not in _CONFIG_KEYS:
            warnings.append(f"неизвестный ключ: {key}")
            continue
        try:
            val = int(raw)
        except (TypeError, ValueError):
            warnings.append(f"{key}: ожидалось целое, получено {raw!r}")
            continue
        if key.startswith("threshold_"):
            if not 0 <= val <= 100:
                warnings.append(f"{key}: порог вне 0..100 ({val})")
        elif key.startswith("cap_"):
            if not 0 <= val <= 100:
                warnings.append(f"{key}: cap вне 0..100 ({val})")
        elif key.startswith("weight_"):
            if not -50 <= val <= 100:
                warnings.append(f"{key}: вес вне −50..100 ({val})")
    return warnings


def load_verdict_overrides(path: str | Path | None) -> dict[str, int]:
    overrides, _warnings = load_verdict_overrides_report(path)
    return overrides


def load_verdict_overrides_report(
    path: str | Path | None,
) -> tuple[dict[str, int], list[str]]:
    """Load overrides and return (overrides, RU validation warnings)."""
    if path is None:
        return {}, []
    p = Path(path)
    if not p.is_file():
        return {}, [f"файл не найден: {p.name}"]
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [f"не удалось прочитать {p.name}: {exc}"]
    except json.JSONDecodeError as exc:
        return {}, [f"битый JSON в {p.name}: {exc}"]
    if not isinstance(raw, dict):
        return {}, [f"{p.name}: корень должен быть объектом JSON"]
    warnings = validate_verdict_extra(raw)
    return parse_verdict_overrides(raw), warnings


def load_verdict_config(path: str | Path | None = None) -> VerdictConfig:
    """Built-in weights merged with optional JSON override file."""
    cfg = VerdictConfig()
    resolved = resolve_verdict_path(path)
    overrides, _warnings = load_verdict_overrides_report(resolved)
    if overrides:
        base = asdict(cfg)
        base.update(overrides)
        return VerdictConfig(**base)
    return cfg


def probe_verdict_extra_warnings(path: str | Path | None = None) -> list[str]:
    """Warnings for UI / About when ``verdict_extra.json`` is present beside EXE."""
    resolved = resolve_verdict_path(path)
    if resolved is None:
        return []
    _overrides, warnings = load_verdict_overrides_report(resolved)
    return warnings


def default_verdict_config() -> VerdictConfig:
    return load_verdict_config()


