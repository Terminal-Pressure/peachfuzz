"""Defensive guardrails for harness execution."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Dynamically sync with the targets registry rather than hardcoding
_ALLOWED_TARGETS: frozenset[str] | None = None


def _get_allowed_targets() -> frozenset[str]:
    """Lazy-load allowed targets from the registry to avoid circular imports."""
    global _ALLOWED_TARGETS
    if _ALLOWED_TARGETS is None:
        from .targets import target_names
        _ALLOWED_TARGETS = frozenset(target_names())
    return _ALLOWED_TARGETS


def validate_target_name(target_name: str) -> str:
    """Allow only local registered targets."""
    cleaned = (target_name or "").strip().lower()
    allowed = _get_allowed_targets()
    if cleaned not in allowed:
        raise ValueError(f"Unknown target '{target_name}'. Valid targets: {sorted(allowed)}")
    return cleaned


def classify_finding_text(text: str, authorized: bool = False) -> str:
    """Route a finding using Hancock-style critic logic.

    This is parser/safety logic only. It never executes exploits or tools.
    """
    text = text or ""
    has_cve = bool(_CVE_RE.search(text))
    has_ip = bool(_IPV4_RE.search(text))
    if "VULNERABILITY_CONFIRMED" in text:
        if has_cve and has_ip:
            return "executor" if authorized else "human_intervention"
        return "reporter"
    if "INSUFFICIENT_DATA" in text:
        return "recon"
    return "reporter"


def validate_local_only_url(url: str) -> bool:
    """Accept only file URLs or local paths for corpus-like resources."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return True
    return parsed.scheme == "file"
