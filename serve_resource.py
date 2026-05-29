"""Run the protected resource server.

Usage:
    python serve_resource.py              # Runs on PORT (default 8080)

Env vars:
    PORT           — port to listen on (default 8080, Cloud Run sets this)
    GATEWAY_URL    — base URL of the gateway REST API for key fetching
"""

import os
import uvicorn

# Ensure examples package is importable
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from examples.protected_resource.main import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"Protected Resource Server")
    print(f"Listening on 0.0.0.0:{port}")
    print(f"Gateway keys: {os.environ.get('GATEWAY_URL', 'http://localhost:8080')}/keys")
    print()
    uvicorn.run(app, host="0.0.0.0", port=port)
