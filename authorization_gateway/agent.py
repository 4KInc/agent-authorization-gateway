"""ADK agent entry point — must export `agent` at module level."""

import sys
import os

# Add project root to path so gateway package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.agent import gateway_agent

# ADK requires this exact name
agent = gateway_agent
