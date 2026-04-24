# PeachTrace

PeachTrace is PeachFuzz's dependency-free Atheris-inspired fuzz backend.

It uses only the Python standard library:

- `sys.settrace` for line/function feedback
- deterministic mutation scheduling
- interesting-input corpus growth
- crash dedupe
- standard PeachFuzz reports

## Why PeachTrace exists

Atheris is excellent, but it adds a native dependency and libFuzzer-style runtime assumptions. PeachFuzz/CactusFuzz aims to stay lightweight and portable, especially on Chromebooks, containers, CI, and low-friction blue-team environments.

## Run

```bash
peachfuzz run --target json --backend peachtrace --runs 500 corpus/json_api
peachfuzz peachtrace --target openapi --runs 500 corpus/openapi
peachfuzz peachtrace --target graphql --runs 500 corpus/graphql
peachfuzz peachtrace --target webhook --runs 500 corpus/webhook
```

## Output

PeachTrace writes:

```text
reports/<target>-peachtrace-summary.json
reports/<target>-summary.json
reports/interesting/<target>/*.bin
reports/crashes/*
```

## Safety

PeachTrace is local-only and in-process. It does not:

- contact networks
- execute shell commands
- deliver payloads
- scan third-party systems
- require Atheris or native fuzzing dependencies

## Limits

PeachTrace is not a drop-in libFuzzer clone. It gives useful Python-level line/function feedback for local parser targets, but it does not provide compiled-code edge coverage.
