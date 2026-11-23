"""
NEXUS Engine - Autonomous AI Agent & Text-to-SQL Architecture
============================================================
Package Initialization for Phase 4 Agent modules.
"""

from src.agent.llm_router import (
    LLMRouter,
    LLMConfig,
    LLMResponse,
    LLMRouterError,
    LLMConnectionError,
    LLMAuthenticationError,
    LLMTimeoutError,
    LLMRateLimitError,
)
from src.agent.chart_engine import (
    ChartSpec,
    ChartEngine,
    ChartValidationError,
)
from src.agent.sql_chain import (
    SQLAgentChain,
    AgentRunResult,
    ConversationTurn,
    extract_sql_from_response,
    generate_starter_questions,
)

__all__ = [
    # Router & Transport
    "LLMRouter",
    "LLMConfig",
    "LLMResponse",
    "LLMRouterError",
    "LLMConnectionError",
    "LLMAuthenticationError",
    "LLMTimeoutError",
    "LLMRateLimitError",
    # Declarative Chart Engine
    "ChartSpec",
    "ChartEngine",
    "ChartValidationError",
    # Autonomous SQL Chain
    "SQLAgentChain",
    "AgentRunResult",
    "ConversationTurn",
    "extract_sql_from_response",
    "generate_starter_questions",
]
