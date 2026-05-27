"""ADK agent entry point — must export `root_agent` at module level."""

import sys
import os

# Add project root to path so gateway package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.agent import gateway_agent

# ADK 2.1 requires this exact name
root_agent = gateway_agent
