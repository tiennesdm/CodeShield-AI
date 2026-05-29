"""
CodeShield AI - Multi-Agent Swarm Package.

Provides 14 specialized agents:
  Security Scanning:
    - john_sast: Static Application Security Testing
    - dave_dast: Dynamic Application Security Testing
    - sam_secrets: Secret Detection
    - pam_sca: Software Composition Analysis
    - tina_taint: Taint Analysis
    - sade_llm: LLM Security & Container Scanning
  Test Generation:
    - test_parser: Code Parser & Test Target Extractor
    - test_generator: Intelligent Test Case Generator
    - test_generator_ai: LLM-Enhanced Test Case Generator
    - pr_agent: GitHub Pull Request Automation
  Self-Improving:
    - test_runner: Test Execution & Coverage Reporter
    - coverage_analyzer: Coverage Gap Identifier
    - mutation_tester: Weak Test Detector via Mutation Testing
    - test_improver: Test Case Improver & Gap Filler
    - feedback_loop: Self-Improving Test Orchestrator

Plus the base infrastructure:
  - BaseSecurityAgent: Abstract base for all agents
  - AgentFactory: Dynamic agent creation and execution
  - AgentResult: Standardized result format
  - ScanContext: Execution context for scans
"""

from agents.base import BaseSecurityAgent
from agents.dave_dast import DaveDASTAgent
from agents.factory import AgentFactory
from agents.john_sast import JohnSASTAgent
from agents.pam_sca import PamSCAAgent
from agents.pr_agent import PRAgent
from agents.results import (
    AgentCapabilities,
    AgentResult,
    HealthState,
    HealthStatus,
    ScanContext,
    ScanSummary,
    ToolExecutionSummary,
)
from agents.sade_llm import SadeLLMSecurityAgent
from agents.sam_secrets import SamSecretsAgent
from agents.test_generator import TestGeneratorAgent
from agents.test_parser import TestParserAgent
from agents.tina_taint import TinaTaintAgent

__all__ = [
    # Base
    "BaseSecurityAgent",
    # Security Agents
    "JohnSASTAgent",
    "DaveDASTAgent",
    "SamSecretsAgent",
    "PamSCAAgent",
    "TinaTaintAgent",
    "SadeLLMSecurityAgent",
    # Test Generation Agents
    "TestParserAgent",
    "TestGeneratorAgent",
    "PRAgent",
    # Results
    "AgentResult",
    "ScanContext",
    "ScanSummary",
    "HealthStatus",
    "HealthState",
    "AgentCapabilities",
    "ToolExecutionSummary",
    # Factory
    "AgentFactory",
]
