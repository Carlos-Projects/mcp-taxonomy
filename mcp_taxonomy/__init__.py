"""
mcp-taxonomy — Canonical classification system for the MCP security ecosystem.

Provides shared enums, types, and mapping adapters so that findings from
palisade-scanner, MCPGuard, MCPwn, and agentgate can be correlated,
compared, and displayed in a unified view (MCPscop).
"""

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    RiskScore,
    Severity,
    TaxonomyEvent,
    severity_from_score,
    severity_weight,
)
from mcp_taxonomy.map_agentgate import agentgate_signal_to_taxonomy
from mcp_taxonomy.map_mcpguard import mcpguard_event_to_taxonomy
from mcp_taxonomy.map_mcpwn import mcpwn_finding_to_taxonomy
from mcp_taxonomy.map_palisade import palisade_finding_to_taxonomy
from mcp_taxonomy.map_raguard import raguard_finding_to_taxonomy

__all__ = [
    "AttackCategory",
    "Confidence",
    "DetectionMethod",
    "RiskScore",
    "Severity",
    "TaxonomyEvent",
    "severity_from_score",
    "severity_weight",
    "agentgate_signal_to_taxonomy",
    "mcpguard_event_to_taxonomy",
    "mcpwn_finding_to_taxonomy",
    "palisade_finding_to_taxonomy",
    "raguard_finding_to_taxonomy",
]
