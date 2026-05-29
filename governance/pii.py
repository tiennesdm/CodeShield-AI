"""
PII and secret detection / redaction.

Addresses the "security aspects, especially around AI and data handling"
concern: before any text is sent to an external LLM, sensitive data is detected
and replaced with stable, type-tagged placeholders (e.g. ``[REDACTED_EMAIL_1]``).

This is intentionally regex-based so it has zero external dependencies and runs
anywhere, including air-gapped EC2 instances. It is not a substitute for a
dedicated DLP system, but it provides a defensible first line of defence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple


@dataclass
class PIIFinding:
    """A single piece of detected sensitive data."""

    pii_type: str
    placeholder: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "pii_type": self.pii_type,
            "placeholder": self.placeholder,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class RedactionResult:
    """The outcome of redacting a block of text."""

    redacted_text: str
    findings: List[PIIFinding] = field(default_factory=list)
    # Maps placeholder -> original value, so trusted callers can re-hydrate.
    mapping: Dict[str, str] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    def counts_by_type(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.pii_type] = out.get(f.pii_type, 0) + 1
        return out


# Ordering matters: more specific / longer patterns first so they win.
_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("AWS_SECRET_KEY", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("PHONE", re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}\b")),
]

# Connection-string style secrets ("password=..." / "Bearer ...").
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\b"
    r"\s*[:=]\s*['\"]?([^\s'\"&]{4,})['\"]?"
)


class PIIRedactor:
    """Detects and redacts PII/secrets, with optional re-hydration."""

    def __init__(self, *, redact_ip: bool = True) -> None:
        # IP addresses are common in code/logs and noisy; allow opt-out.
        self._redact_ip = redact_ip

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(redacted_text=text)

        findings: List[PIIFinding] = []
        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}
        # Work on a list to apply non-overlapping replacements predictably.
        spans: List[Tuple[int, int, str, str]] = []
        occupied: List[Tuple[int, int]] = []

        def _overlaps(s: int, e: int) -> bool:
            return any(not (e <= os_ or s >= oe) for os_, oe in occupied)

        def _collect(pii_type: str, value: str, s: int, e: int) -> None:
            if _overlaps(s, e):
                return
            counters[pii_type] = counters.get(pii_type, 0) + 1
            placeholder = f"[REDACTED_{pii_type}_{counters[pii_type]}]"
            spans.append((s, e, placeholder, value))
            occupied.append((s, e))
            mapping[placeholder] = value
            findings.append(PIIFinding(pii_type, placeholder, s, e))

        for pii_type, pattern in _PATTERNS:
            if pii_type == "IPV4" and not self._redact_ip:
                continue
            for match in pattern.finditer(text):
                value = match.group(0)
                if pii_type == "CREDIT_CARD" and not self._luhn_ok(value):
                    continue
                _collect(pii_type, value, match.start(), match.end())

        for match in _KV_SECRET.finditer(text):
            value = match.group(2)
            s, e = match.span(2)
            _collect("SECRET", value, s, e)

        # Apply replacements from the end so indices stay valid.
        spans.sort(key=lambda x: x[0], reverse=True)
        redacted = text
        for s, e, placeholder, _ in spans:
            redacted = redacted[:s] + placeholder + redacted[e:]

        findings.sort(key=lambda f: f.start)
        return RedactionResult(
            redacted_text=redacted, findings=findings, mapping=mapping
        )

    @staticmethod
    def rehydrate(text: str, mapping: Dict[str, str]) -> str:
        """Restore original values from a redaction mapping (trusted use only)."""
        for placeholder, original in mapping.items():
            text = text.replace(placeholder, original)
        return text

    @staticmethod
    def _luhn_ok(candidate: str) -> bool:
        """Validate a credit-card-like number via the Luhn checksum."""
        digits = [int(c) for c in candidate if c.isdigit()]
        if not 13 <= len(digits) <= 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
