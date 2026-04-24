# Schema-aware Mutators

PeachFuzz/CactusFuzz v0.4.3 adds structured, local-only mutators for:

- JSON API envelopes
- OpenAPI JSON documents
- GraphQL documents
- webhook envelopes

## Generate corpus

```bash
peachfuzz schemas --kind all --count 4 --output corpus/generated/schema
peachfuzz schemas --kind openapi --count 8 --output corpus/generated/openapi
```

## Run structured targets

```bash
peachfuzz run --target json --backend deterministic --runs 250 corpus/generated/schema/json
peachfuzz run --target openapi --backend deterministic --runs 250 corpus/generated/schema/openapi
peachfuzz run --target graphql --backend deterministic --runs 250 corpus/generated/schema/graphql
peachfuzz run --target webhook --backend deterministic --runs 250 corpus/generated/schema/webhook
```

## Import OpenAPI JSON

```bash
peachfuzz schemas --import-openapi openapi.json --output corpus/imported
```

YAML import is intentionally deferred until a safe optional YAML parser is added.

## Safety

The mutators are offline and parser-focused:

- no network calls
- no tool execution
- no exploit delivery
- no third-party target contact
- no credential access
