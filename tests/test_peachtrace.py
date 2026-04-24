import json
from pathlib import Path

from peachfuzz_ai.backends import BackendRunRequest, backend_names, get_backend
from peachfuzz_ai.cli import main
from peachfuzz_ai.peachtrace import PeachTraceEngine
from peachfuzz_ai.targets import get_target


def test_peachtrace_engine_discovers_coverage(tmp_path: Path):
    engine = PeachTraceEngine(get_target("json"), "json", report_dir=tmp_path, seed=1)
    result = engine.run([b'{"endpoint":"/v1/workflows","body":{}}'], runs=25)
    assert result.stats.coverage_points > 0
    assert (tmp_path / "json-peachtrace-summary.json").exists()
    assert (tmp_path / "interesting" / "json").exists()


def test_peachtrace_backend_registered():
    assert "peachtrace" in backend_names()
    assert "atheris-legacy" in backend_names()
    assert "atheris" not in backend_names()


def test_peachtrace_backend_runs(tmp_path: Path):
    backend = get_backend("peachtrace")
    outcome = backend.run(
        BackendRunRequest(
            target_name="webhook",
            target=get_target("webhook"),
            corpus=[b'{"event":"x","headers":{},"body":{}}'],
            runs=10,
            report_dir=tmp_path,
            seed=2,
        )
    )
    assert outcome.status == "ok"
    assert outcome.result is not None
    assert "coverage_points=" in outcome.detail


def test_atheris_legacy_is_optional_not_required():
    backend = get_backend("atheris-legacy")
    outcome = backend.run(
        BackendRunRequest(
            target_name="bytes",
            target=get_target("bytes"),
            corpus=[b"seed"],
            runs=1,
        )
    )
    assert outcome.status in {"unavailable", "ok"}
    if outcome.status == "unavailable":
        assert "prefer dependency-free --backend peachtrace" in outcome.detail


def test_peachtrace_cli_shortcut(tmp_path: Path, capsys):
    rc = main([
        "peachtrace",
        "--target",
        "webhook",
        "--runs",
        "5",
        "--report-dir",
        str(tmp_path),
        "corpus/webhook",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"target_name": "webhook"' in out


def test_run_backend_peachtrace_cli(tmp_path: Path, capsys):
    rc = main([
        "run",
        "--target",
        "openapi",
        "--backend",
        "peachtrace",
        "--runs",
        "5",
        "--report-dir",
        str(tmp_path),
        "corpus/openapi",
    ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["target_name"] == "openapi"


def test_peachtrace_crash_dedupe(tmp_path: Path):
    engine = PeachTraceEngine(get_target("bytes"), "bytes", report_dir=tmp_path, seed=3)
    result = engine.run([b"PEACHFUZZ_CRASH_SENTINEL"], runs=5)
    assert result.stats.crashes >= 1
    assert (tmp_path / "crashes").exists()
