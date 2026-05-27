"""Serve the ADK agent on Cloud Run.

Usage:
    python serve_adk.py              # Runs on port 8080
    python serve_adk.py --port 9000  # Custom port

This starts the full ADK web UI (chat interface + API endpoints)
backed by the orchestrator agent (Worker + Gateway sub-agents).
"""

import argparse
import os

import uvicorn

from google.adk.cli.fast_api import get_fast_api_app


def main():
    parser = argparse.ArgumentParser(description="Agent Authorization Gateway — ADK Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    app = get_fast_api_app(
        agents_dir=os.path.join(os.path.dirname(__file__), "authorization_gateway"),
        web=True,
        host=args.host,
        port=args.port,
    )

    print(f"Agent Authorization Gateway — ADK Agent")
    print(f"Listening on {args.host}:{args.port}")
    print()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
