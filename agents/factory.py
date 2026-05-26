"""
Agent Factory for CodeShield AI Multi-Agent Swarm.

Provides dynamic agent creation, configuration, and pooling
for concurrent scan execution. HAL Orchestrator uses this
factory to instantiate and manage agents.
"""

import asyncio
from typing import Any, Dict, List, Optional, Type

from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.dave_dast import DaveDASTAgent
from agents.john_sast import JohnSASTAgent
from agents.pam_sca import PamSCAAgent
from agents.results import AgentResult, ScanContext
from agents.sade_llm import SadeLLMSecurityAgent
from agents.sam_secrets import SamSecretsAgent
from agents.tina_taint import TinaTaintAgent

logger = get_logger(__name__)

# Registry of all available agent classes
AGENT_REGISTRY: Dict[str, Type[BaseSecurityAgent]] = {
    "john_sast": JohnSASTAgent,
    "dave_dast": DaveDASTAgent,
    "sam_secrets": SamSecretsAgent,
    "pam_sca": PamSCAAgent,
    "tina_taint": TinaTaintAgent,
    "sade_llm": SadeLLMSecurityAgent,
}

# Default execution order (by priority)
DEFAULT_AGENT_ORDER = [
    "sam_secrets",   # Priority 5  - Secrets first (critical)
    "john_sast",     # Priority 10 - SAST early
    "pam_sca",       # Priority 15 - SCA dependencies
    "dave_dast",     # Priority 20 - DAST after SAST
    "tina_taint",    # Priority 25 - Deep taint analysis
    "sade_llm",      # Priority 30 - LLM/container analysis
]


class AgentFactory:
    """
    Factory for creating and managing security scanning agents.

    Provides:
    - Agent creation by name
    - Configuration injection
    - Agent pooling for concurrent execution
    - Batch scanning across multiple agents

    Example:
        factory = AgentFactory()
        agents = factory.create_all_agents()
        results = await factory.run_agents_concurrently(agents, context)
    """

    def __init__(self) -> None:
        self._registry = AGENT_REGISTRY.copy()
        self._agent_pool: Dict[str, BaseSecurityAgent] = {}
        logger.info("AgentFactory initialized with %d agents", len(self._registry))

    # ------------------------------------------------------------------
    # Agent creation
    # ------------------------------------------------------------------

    def create_agent(
        self,
        agent_name: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> BaseSecurityAgent:
        """
        Create a single agent instance by name.

        Args:
            agent_name: Registered agent name (e.g., 'john_sast')
            config: Optional agent-specific configuration

        Returns:
            Instantiated BaseSecurityAgent subclass

        Raises:
            ValueError: If agent_name is not registered
        """
        if agent_name not in self._registry:
            available = ", ".join(self._registry.keys())
            raise ValueError(
                f"Unknown agent: {agent_name!r}. Available: {available}"
            )

        agent_class = self._registry[agent_name]
        agent = agent_class(config=config)
        logger.debug("Created agent: %s", agent_name)
        return agent

    def create_all_agents(
        self,
        configs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[BaseSecurityAgent]:
        """
        Create all registered agents.

        Args:
            configs: Optional dict of agent_name -> config mappings

        Returns:
            List of all instantiated agents, sorted by priority
        """
        configs = configs or {}
        agents: List[BaseSecurityAgent] = []

        for name in DEFAULT_AGENT_ORDER:
            if name in self._registry:
                agent = self.create_agent(name, config=configs.get(name))
                agents.append(agent)

        return agents

    def create_agent_subset(
        self,
        agent_names: List[str],
        configs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[BaseSecurityAgent]:
        """
        Create a subset of agents by name.

        Args:
            agent_names: List of agent names to create
            configs: Optional dict of agent_name -> config mappings

        Returns:
            List of instantiated agents, sorted by priority
        """
        configs = configs or {}
        agents: List[BaseSecurityAgent] = []

        # Sort by default order to maintain priority
        for name in DEFAULT_AGENT_ORDER:
            if name in agent_names and name in self._registry:
                agent = self.create_agent(name, config=configs.get(name))
                agents.append(agent)

        # Add any remaining agents not in default order
        for name in agent_names:
            if name not in DEFAULT_AGENT_ORDER and name in self._registry:
                agent = self.create_agent(name, config=configs.get(name))
                agents.append(agent)

        return agents

    # ------------------------------------------------------------------
    # Agent pool management
    # ------------------------------------------------------------------

    def get_or_create(
        self,
        agent_name: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> BaseSecurityAgent:
        """
        Get an agent from the pool or create a new one.

        Args:
            agent_name: Agent name
            config: Optional configuration (used only on creation)

        Returns:
            BaseSecurityAgent instance
        """
        cache_key = f"{agent_name}_{hash(str(sorted((config or {}).items())))}"
        if cache_key not in self._agent_pool:
            self._agent_pool[cache_key] = self.create_agent(agent_name, config)
        return self._agent_pool[cache_key]

    def clear_pool(self) -> None:
        """Clear the agent pool."""
        count = len(self._agent_pool)
        self._agent_pool.clear()
        logger.info("Cleared agent pool (%d agents)", count)

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    async def run_agents_sequentially(
        self,
        agents: List[BaseSecurityAgent],
        context: ScanContext,
    ) -> List[AgentResult]:
        """
        Run agents one after another (sequential execution).

        Each agent receives the context with previous findings.

        Args:
            agents: List of agent instances
            context: ScanContext

        Returns:
            List of AgentResult, one per agent
        """
        results: List[AgentResult] = []
        all_findings: List[Any] = []

        for agent in agents:
            logger.info("[%s] Running agent: %s", context.scan_id, agent.name)
            try:
                # Pass accumulated findings for cross-agent correlation
                context.previous_findings = all_findings
                result = await agent.scan(context)
                results.append(result)
                all_findings.extend(result.findings)
            except Exception as e:
                logger.error("[%s] Agent %s crashed: %s", context.scan_id, agent.name, e)
                from agents.results import AgentResult, ScanSummary
                results.append(
                    AgentResult(
                        agent_name=agent.name,
                        agent_role=agent.role,
                        scan_id=context.scan_id,
                        status="failed",
                        errors=[str(e)],
                    )
                )

        return results

    async def run_agents_concurrently(
        self,
        agents: List[BaseSecurityAgent],
        context: ScanContext,
    ) -> List[AgentResult]:
        """
        Run all agents in parallel (concurrent execution).

        Agents run independently without cross-agent correlation.

        Args:
            agents: List of agent instances
            context: ScanContext

        Returns:
            List of AgentResult, one per agent
        """
        logger.info(
            "[%s] Running %d agents concurrently",
            context.scan_id,
            len(agents),
        )

        async def _run_single(agent: BaseSecurityAgent) -> AgentResult:
            try:
                return await agent.scan(context)
            except Exception as e:
                logger.error("[%s] Agent %s crashed: %s", context.scan_id, agent.name, e)
                return AgentResult(
                    agent_name=agent.name,
                    agent_role=agent.role,
                    scan_id=context.scan_id,
                    status="failed",
                    errors=[str(e)],
                )

        coros = [_run_single(agent) for agent in agents]
        results = await asyncio.gather(*coros, return_exceptions=True)

        # Convert exceptions to failed results
        final_results: List[AgentResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                agent = agents[i]
                logger.error("[%s] Agent %s exception: %s", context.scan_id, agent.name, result)
                final_results.append(
                    AgentResult(
                        agent_name=agent.name,
                        agent_role=agent.role,
                        scan_id=context.scan_id,
                        status="failed",
                        errors=[str(result)],
                    )
                )
            else:
                final_results.append(result)

        return final_results

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------

    def register_agent(
        self,
        name: str,
        agent_class: Type[BaseSecurityAgent],
    ) -> None:
        """
        Register a new agent class.

        Args:
            name: Agent name/identifier
            agent_class: Class inheriting from BaseSecurityAgent
        """
        if not issubclass(agent_class, BaseSecurityAgent):
            raise ValueError(f"Agent class must inherit from BaseSecurityAgent")
        self._registry[name] = agent_class
        logger.info("Registered agent: %s -> %s", name, agent_class.__name__)

    def unregister_agent(self, name: str) -> None:
        """Remove an agent from the registry."""
        if name in self._registry:
            del self._registry[name]
            logger.info("Unregistered agent: %s", name)

    def list_agents(self) -> List[Dict[str, Any]]:
        """
        List all available agents with their capabilities.

        Returns:
            List of agent capability dicts
        """
        agents = []
        for name in DEFAULT_AGENT_ORDER:
            if name in self._registry:
                try:
                    agent = self.create_agent(name)
                    caps = agent.get_capabilities()
                    agents.append({
                        "name": caps.agent_name,
                        "role": caps.agent_role,
                        "tools": caps.tools,
                        "supported_languages": caps.supported_languages,
                        "categories": caps.categories,
                        "priority": caps.priority,
                        "requires_network": caps.requires_network,
                        "requires_external_tools": caps.requires_external_tools,
                    })
                except Exception as e:
                    logger.warning("Failed to get capabilities for %s: %s", name, e)
        return agents

    def __repr__(self) -> str:
        return f"<AgentFactory(registered={list(self._registry.keys())})>"
