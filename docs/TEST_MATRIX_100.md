# 100-Test Tool Matrix

PeachFuzz/CactusFuzz v0.4.6 adds exactly 100 individually named tests for the new toolchain built from v0.4.1 through v0.4.5.

## Coverage groups

| Range | Tool area | Count |
|---:|---|---:|
| 001-015 | Backend adapters | 15 |
| 016-030 | CactusFuzz agent guardrail pack | 15 |
| 031-050 | Schema-aware mutators | 20 |
| 051-070 | PeachTrace dependency-free trace backend | 20 |
| 071-085 | Crash minimizer | 15 |
| 086-100 | Pytest reproducer + CLI integration | 15 |

## Run

```bash
pytest -q tests/test_tool_matrix_100.py
pytest -q
```

## Safety

All tests are local-only. They do not scan networks, execute shells, contact third parties, or deliver payloads.
