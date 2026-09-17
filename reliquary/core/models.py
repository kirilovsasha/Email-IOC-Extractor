"""Shared data models for Reliquary analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IocType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    IP_PORT = "ip_port"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    FILENAME = "filename"
    FILEPATH = "filepath"
    UNC = "unc"
    REGISTRY = "registry"
    MUTEX = "mutex"
    BITCOIN = "bitcoin"
    MONERO = "monero"
    MESSENGER = "messenger"
    COMMAND_LINE = "command_line"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class Ioc:
    value: str
    ioc_type: IocType
    source: str = ""
    context: str = ""
    rewritten_from: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ioc_type"] = self.ioc_type.value
        return data


@dataclass
class HeaderFinding:
    name: str
    value: str
    severity: Severity
    note: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class AttachmentInfo:
    filename: str
    size: int
    mime_guess: str
    md5: str
    sha1: str
    sha256: str
    risk_flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    data: bytes | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "size": self.size,
            "mime_guess": self.mime_guess,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "risk_flags": self.risk_flags,
            "notes": self.notes,
        }


@dataclass
class MailIdentity:
    """Compact card: what this email looks like for SOC triage."""

    from_header: str = ""
    return_path: str = ""
    reply_to: str = ""
    subject: str = ""
    message_id: str = ""
    date: str = ""
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    received_hops: int = 0
    first_received: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UrlRewriteResult:
    original: str
    unwrapped: str
    rewriter: str
    changed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionRecommendation:
    priority: int
    action: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    level: VerdictLevel
    score: int
    summary: str
    reasons: list[str] = field(default_factory=list)
    actions: list[ActionRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "summary": self.summary,
            "reasons": self.reasons,
            "actions": [a.to_dict() for a in self.actions],
        }


@dataclass
class AnalysisResult:
    source_path: str
    source_kind: str
    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    iocs: list[Ioc] = field(default_factory=list)
    headers: list[HeaderFinding] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    mail_identity: MailIdentity | None = None
    url_rewrites: list[UrlRewriteResult] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    verdict: Verdict | None = None
    raw_text_preview: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "source_kind": self.source_kind,
            "subject": self.subject,
            "sender": self.sender,
            "recipients": self.recipients,
            "iocs": [i.to_dict() for i in self.iocs],
            "headers": [h.to_dict() for h in self.headers],
            "raw_headers": self.raw_headers,
            "mail_identity": self.mail_identity.to_dict() if self.mail_identity else None,
            "url_rewrites": [u.to_dict() for u in self.url_rewrites],
            "attachments": [a.to_dict() for a in self.attachments],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "raw_text_preview": self.raw_text_preview,
            "errors": self.errors,
        }
