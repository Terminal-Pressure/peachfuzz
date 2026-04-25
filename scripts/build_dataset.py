import json
from collections import defaultdict
from pathlib import Path
from typing import Any

OUT = Path("data/datasets/peachfuzz.jsonl")
OUT.parent.mkdir(parents=True, exist_ok=True)


def classify_crash(crash: dict[str, Any]) -> str:
    etype = crash.get("exception_type", "")
    msg = crash.get("message", "").lower()
    payload = crash.get("payload_preview", "").lower()

    if etype == "JSONDecodeError":
        if "extra data" in msg:
            return "json_extra_data"
        if "unterminated string" in msg:
            return "json_unterminated_string"
        if "invalid control character" in msg:
            return "json_invalid_control_character"
        if "expecting value" in msg:
            return "json_empty_payload"
        if "expecting ',' delimiter" in msg:
            return "json_missing_delimiter"
        return "json_parse_error"

    if etype == "UnicodeDecodeError":
        return "unicode_decode_error"

    if etype == "KeyError":
        return "missing_endpoint_key"

    if etype == "PermissionError":
        return "external_url_endpoint"

    if "javascript:" in payload:
        return "script_scheme_endpoint"
    if "http://127.0.0.1" in payload or "localhost" in payload:
        return "loopback_url_endpoint"
    if "../" in payload or "etc/passwd" in payload:
        return "path_traversal_like_endpoint"

    if '"endpoint": null' in payload:
        return "null_endpoint"
    if '"endpoint": true' in payload or '"endpoint": false' in payload:
        return "boolean_endpoint"
    if '"endpoint": 123' in payload or '"endpoint": 0' in payload:
        return "numeric_endpoint"
    if '"endpoint": [' in payload:
        return "array_endpoint"
    if '"endpoint": {' in payload:
        return "object_endpoint"
    if '"endpoint": ""' in payload:
        return "empty_endpoint"

    return "invalid_relative_endpoint"


def assign_severity(category: str) -> str:
    if category in {
        "path_traversal_like_endpoint",
        "script_scheme_endpoint",
        "external_url_endpoint",
    }:
        return "high"

    if category in {
        "missing_endpoint_key",
        "json_parse_error",
        "json_missing_delimiter",
    }:
        return "medium"

    return "low"


def severity_weight(severity: str) -> float:
    return {
        "high": 1.0,
        "medium": 0.6,
        "low": 0.3,
    }.get(severity, 0.5)


def root_key(crash: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        crash.get("target_name", "unknown"),
        crash.get("exception_type", "unknown"),
        crash.get("message", "unknown"),
        classify_crash(crash),
    )


def main() -> None:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for f in Path("reports").glob("*-summary.json"):
        data = json.loads(f.read_text(encoding="utf-8"))
        for crash in data.get("crashes", []):
            crash["_source"] = str(f)
            groups[root_key(crash)].append(crash)

    with OUT.open("w", encoding="utf-8") as fh:
        for (target, exception, message, category), crashes in sorted(groups.items()):
            rep = crashes[0]
            examples = list(dict.fromkeys(c.get("payload_preview", "") for c in crashes))[:5]

            severity = assign_severity(category)

            record = {
                "instruction": "Analyze this fuzzing failure and explain the root cause.",
                "input": rep.get("payload_preview", ""),
                "output": (
                    f"Crash family: {category}. Exception: {exception}. "
                    f"Root cause: {message}."
                ),
                "metadata": {
                    "target_name": target,
                    "category": category,
                    "variant_count": len(crashes),
                    "severity": severity,
                    "weight": severity_weight(severity),
                    "exception": exception,
                    "message": message,
                    "examples": examples,
                    "source": rep.get("_source"),
                },
            }
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"[+] classified dataset: {OUT} ({len(groups)} records)")


if __name__ == "__main__":
    main()
