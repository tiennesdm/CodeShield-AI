"""
Tests for AgentFactory.
"""

import pytest

from agents.dave_dast import DaveDASTAgent
from agents.factory import DEFAULT_AGENT_ORDER, AgentFactory
from agents.john_sast import JohnSASTAgent
from agents.pam_sca import PamSCAAgent
from agents.results import ScanContext
from agents.sade_llm import SadeLLMSecurityAgent
from agents.sam_secrets import SamSecretsAgent
from agents.tina_taint import TinaTaintAgent


@pytest.fixture
def factory():
    return AgentFactory()


@pytest.fixture
def sample_context(tmp_path):
    (tmp_path / "test.py").write_text("x = 1")
    return ScanContext(
        scan_id="factory-test-001",
        source_path=str(tmp_path),
        source_type="zip",
    )


class TestAgentFactory:
    """Test the AgentFactory."""

    def test_factory_initialization(self, factory):
        agents = factory.list_agents()
        assert len(agents) == 6

    def test_create_agent(self, factory):
        agent = factory.create_agent("john_sast")
        assert isinstance(agent, JohnSASTAgent)
        assert agent.name == "john_sast"

    def test_create_agent_dave(self, factory):
        agent = factory.create_agent("dave_dast")
        assert isinstance(agent, DaveDASTAgent)

    def test_create_agent_sam(self, factory):
        agent = factory.create_agent("sam_secrets")
        assert isinstance(agent, SamSecretsAgent)

    def test_create_agent_pam(self, factory):
        agent = factory.create_agent("pam_sca")
        assert isinstance(agent, PamSCAAgent)

    def test_create_agent_tina(self, factory):
        agent = factory.create_agent("tina_taint")
        assert isinstance(agent, TinaTaintAgent)

    def test_create_agent_sade(self, factory):
        agent = factory.create_agent("sade_llm")
        assert isinstance(agent, SadeLLMSecurityAgent)

    def test_create_agent_with_config(self, factory):
        agent = factory.create_agent("john_sast", config={"timeout": 60})
        assert agent.config == {"timeout": 60}

    def test_create_agent_invalid(self, factory):
        with pytest.raises(ValueError, match="Unknown agent"):
            factory.create_agent("nonexistent")

    def test_create_all_agents(self, factory):
        agents = factory.create_all_agents()
        assert len(agents) == 6
        names = [a.name for a in agents]
        assert names == list(DEFAULT_AGENT_ORDER)

    def test_create_all_agents_sorted_by_priority(self, factory):
        agents = factory.create_all_agents()
        priorities = [a.priority for a in agents]
        assert priorities == sorted(priorities)

    def test_create_agent_subset(self, factory):
        agents = factory.create_agent_subset(["john_sast", "sam_secrets"])
        assert len(agents) == 2
        names = [a.name for a in agents]
        assert "john_sast" in names
        assert "sam_secrets" in names

    def test_create_agent_subset_maintains_order(self, factory):
        agents = factory.create_agent_subset(["sade_llm", "john_sast"])
        names = [a.name for a in agents]
        # john_sast (priority 10) should come before sade_llm (priority 30)
        assert names.index("john_sast") < names.index("sade_llm")

    def test_pool_get_or_create(self, factory):
        a1 = factory.get_or_create("john_sast")
        a2 = factory.get_or_create("john_sast")
        assert a1 is a2  # Same instance from pool

    def test_pool_different_configs(self, factory):
        a1 = factory.get_or_create("john_sast", config={"x": 1})
        a2 = factory.get_or_create("john_sast", config={"x": 2})
        assert a1 is not a2  # Different configs = different instances

    def test_clear_pool(self, factory):
        factory.get_or_create("john_sast")
        factory.clear_pool()
        # Pool is empty, new create should return fresh instance
        a1 = factory.get_or_create("john_sast")
        a2 = factory.get_or_create("john_sast")
        assert a1 is a2  # Fresh pool, same instance

    def test_list_agents(self, factory):
        agents = factory.list_agents()
        assert len(agents) == 6
        for a in agents:
            assert "name" in a
            assert "role" in a
            assert "tools" in a
            assert "priority" in a

    def test_register_agent(self, factory):
        class TestAgent(factory._registry["john_sast"].__bases__[0]):
            name = "test_special"
            role = "Test"
            tools = []
            priority = 99

            async def scan(self, context):
                from agents.results import AgentResult
                return AgentResult(agent_name="test_special", agent_role="Test", scan_id=context.scan_id)

        factory.register_agent("test_special", TestAgent)
        agent = factory.create_agent("test_special")
        assert agent.name == "test_special"

    def test_register_invalid(self, factory):
        with pytest.raises(ValueError, match="must inherit"):
            factory.register_agent("bad", str)

    def test_unregister_agent(self, factory):
        factory.unregister_agent("john_sast")
        with pytest.raises(ValueError):
            factory.create_agent("john_sast")

    @pytest.mark.asyncio
    async def test_run_agents_concurrently(self, factory, sample_context):
        agents = factory.create_agent_subset(["john_sast", "sam_secrets"])
        results = await factory.run_agents_concurrently(agents, sample_context)
        assert len(results) == 2
        for r in results:
            assert r.status in ("success", "partial", "failed")
            assert r.scan_id == "factory-test-001"

    @pytest.mark.asyncio
    async def test_run_agents_sequentially(self, factory, sample_context):
        agents = factory.create_agent_subset(["john_sast", "sam_secrets"])
        results = await factory.run_agents_sequentially(agents, sample_context)
        assert len(results) == 2
        for r in results:
            assert r.status in ("success", "partial", "failed")

    @pytest.mark.asyncio
    async def test_run_agents_handles_crashes(self, factory, sample_context):
        class CrashingAgent(factory._registry["john_sast"].__bases__[0]):
            name = "crasher"
            role = "Crasher"
            tools = []
            priority = 1

            async def scan(self, context):
                raise RuntimeError("Simulated crash")

        factory.register_agent("crasher", CrashingAgent)
        agents = [factory.create_agent("crasher")]
        results = await factory.run_agents_concurrently(agents, sample_context)
        assert len(results) == 1
        assert results[0].status == "failed"
        assert "Simulated crash" in results[0].errors[0]

    def test_repr(self, factory):
        assert "AgentFactory" in repr(factory)
