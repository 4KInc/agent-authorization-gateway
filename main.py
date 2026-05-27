"""Entry point for the Agent Authorization Gateway.

Run with: python main.py
Or with ADK: adk run main:gateway_agent
"""

from gateway.agent import gateway_agent

# ADK expects the agent to be importable at module level
agent = gateway_agent

if __name__ == "__main__":
    print("Agent Authorization Gateway")
    print("===========================")
    print()
    print("Run with ADK:")
    print("  adk web main:agent")
    print()
    print("Or run the demo scenario:")
    print("  python demo.py")
