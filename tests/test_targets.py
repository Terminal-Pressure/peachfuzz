import pytest

from peachfuzz_ai.targets import bytes_target, findings_target, get_target, json_api_target


def test_json_api_target_rejects_bad_endpoint():
    with pytest.raises(ValueError):
        json_api_target(b'{"endpoint":"v1/ask"}')


def test_json_api_target_blocks_unauthenticated_diagnostics():
    with pytest.raises(PermissionError):
        json_api_target(b'{"endpoint":"/internal/diagnostics","auth":false}')


def test_findings_target_never_routes_unauthorized_to_executor():
    findings_target(b"VULNERABILITY_CONFIRMED: CVE-2021-44228 on 192.168.1.1")


def test_bytes_sentinel():
    with pytest.raises(ValueError):
        bytes_target(b"PEACHFUZZ_CRASH_SENTINEL")


def test_get_target_unknown():
    with pytest.raises(ValueError):
        get_target("shell")


def test_structured_targets_reject_bad_shapes():
    from peachfuzz_ai.targets import graphql_target, openapi_target, webhook_target
    import pytest

    with pytest.raises(ValueError):
        openapi_target(b'{"openapi":"3.1.0","paths":{"relative":{"get":{}}}}')
    with pytest.raises(ValueError):
        graphql_target(b"query X { field ")
    with pytest.raises(ValueError):
        webhook_target(b'{"event": 123}')
