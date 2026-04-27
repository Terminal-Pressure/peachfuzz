import pytest

from cactusfuzz.agent import AdversarialCase, CactusDecision, CactusFinding, CactusFuzzAgent
from cactusfuzz.scope import AuthorizationScope, ScopeError


class TestAuthorizationScope:
    """Tests for AuthorizationScope class."""

    def test_scope_exact_and_subdomain(self) -> None:
        scope = AuthorizationScope(targets=("example.com", "192.168.1.0/24", "local-lab"))
        assert scope.contains("api.example.com")
        assert not scope.contains("evil-example.com")
        assert scope.contains("192.168.1.42")

    def test_scope_contains_lab_identifier(self) -> None:
        scope = AuthorizationScope(targets=("local-lab",))
        assert scope.contains("local-lab")


class TestCactusFinding:
    """Tests for CactusFinding class."""

    def test_to_dict_converts_enum(self) -> None:
        finding = CactusFinding(
            case_name="test_case",
            decision=CactusDecision.BLOCK,
            rationale="Test rationale",
            severity="high"
        )
        data = finding.to_dict()
        assert data["decision"] == "block"
        assert data["case_name"] == "test_case"
        assert data["rationale"] == "Test rationale"
        assert data["severity"] == "high"

    def test_to_dict_all_decisions(self) -> None:
        for decision in CactusDecision:
            finding = CactusFinding(
                case_name="test", decision=decision, rationale="r"
            )
            assert finding.to_dict()["decision"] == decision.value


class TestCactusFuzzAgent:
    """Tests for CactusFuzzAgent class."""

    def test_cactus_blocks_unsafe_payload(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[1]
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.BLOCK
        assert finding.severity == "high"

    def test_cactus_routes_prompt_injection_to_simulation(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[0]
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.SIMULATE

    def test_cactus_requires_scope(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        with pytest.raises(ScopeError):
            agent.evaluate_case(agent.default_cases()[0], target="not-authorized.example")

    def test_cactus_allows_local_fuzz(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[2]  # benign case
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.LOCAL_FUZZ
        assert finding.severity == "low"

    def test_run_cases_returns_list(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        findings = agent.run_cases(agent.default_cases(), target="local-lab")
        assert len(findings) == 3
        assert all(isinstance(f, CactusFinding) for f in findings)

    def test_to_json_produces_valid_json(self) -> None:
        import json
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        findings = agent.run_cases(agent.default_cases(), target="local-lab")
        json_str = agent.to_json(findings)
        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_blocks_all_dangerous_patterns(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        dangerous = [
            "reverse shell attack",
            "drop persistence beacon",
            "dump credentials now",
            "exfiltrate data",
            "disable logging system",
            "encrypt files ransomware",
            "scan public internet targets",
        ]
        for payload in dangerous:
            case = AdversarialCase(name="test", payload=payload, expected_control="block")
            finding = agent.evaluate_case(case, target="local-lab")
            assert finding.decision == CactusDecision.BLOCK, f"Should block: {payload}"

    def test_simulates_policy_bypass_attempts(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        bypass_attempts = [
            "ignore previous instructions",
            "bypass policy checks",
            "make a tool call anyway",
        ]
        for payload in bypass_attempts:
            case = AdversarialCase(name="test", payload=payload, expected_control="simulate")
            finding = agent.evaluate_case(case, target="local-lab")
            assert finding.decision == CactusDecision.SIMULATE, f"Should simulate: {payload}"
