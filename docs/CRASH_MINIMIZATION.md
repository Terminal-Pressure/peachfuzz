# Crash Minimization and Pytest Reproducers

PeachFuzz/CactusFuzz v0.4.5 adds local-only crash minimization and pytest reproducer generation.

## Why it matters

Raw fuzz crashes are noisy. v0.4.5 turns crash artifacts into:

- smaller payloads
- stable reproducer tests
- JSON metadata
- CI-ready regression coverage

## Commands

Minimize one crash:

```bash
peachfuzz minimize --target graphql reports/crashes/graphql-example.bin
```

Generate one pytest reproducer:

```bash
peachfuzz reproduce --target graphql reports/minimized/graphql-example.bin --output tests/regression
```

Bulk process crash reports:

```bash
peachfuzz minimize-reports --report-dir reports --output reports/minimized --generate-reproducers --reproducer-output tests/regression
```

## Output

```text
reports/minimized/<target>-<sha>.bin
reports/minimized/<target>-<sha>.json
tests/regression/test_repro_<target>_<exception>_<sha>.py
```

## Safety

The minimizer and reproducer generator are local-only:

- no network access
- no shell execution
- no exploit delivery
- no third-party target contact
- no credential access

They only call registered in-process PeachFuzz target functions.

## Recommended workflow

```bash
peachfuzz run --target graphql --backend deterministic --runs 250 corpus/generated/schema/graphql || true
peachfuzz minimize-reports --report-dir reports --generate-reproducers --reproducer-output tests/regression
pytest -q tests/regression
```

Review generated tests before committing them.
