"""ADK agent entry point — must export `root_agent` at module level.

The root agent is the Orchestrator, which delegates to:
- Worker Agent (data operations — authorize then execute)
- Gateway Agent (security queries — stats, chain, keys, verify)
"""

import sys
import os

# Add project root to path so gateway/worker packages are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.orchestrator import orchestrator_agent

# ADK 2.1 requires this exact name
root_agent = orchestrator_agent
