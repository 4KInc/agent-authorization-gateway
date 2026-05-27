"""Run the HTTP API server for direct REST access.

Usage:
    python serve.py              # Runs on port 8080
    python serve.py --port 9000  # Custom port

The API server provides REST endpoints for authorization and verification,
independent of the ADK agent. Both can run simultaneously:
- ADK agent: adk web authorization_gateway  (port 8000)
- HTTP API:  python serve.py                (port 8080)
"""

import argparse

import uvicorn

from gateway.api import api_app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Authorization Gateway — HTTP API")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    print(f"Agent Authorization Gateway — HTTP API")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Docs: http://localhost:{args.port}/docs")
    print()

    uvicorn.run(api_app, host=args.host, port=args.port)
