FROM python:3.13-slim

WORKDIR /app

# Install dependencies (ADK + MCP + gateway deps)
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir google-adk mcp cryptography PyJWT google-cloud-firestore google-cloud-secret-manager google-cloud-logging google-genai web3 eth-account uvicorn httpx fastapi pydantic reportlab

# Copy source
COPY gateway/ gateway/
COPY worker/ worker/
COPY authorization_gateway/ authorization_gateway/
COPY examples/ examples/
COPY serve.py serve_adk.py serve_mcp.py serve_resource.py serve_combined.py ./

EXPOSE 8080

# Default: serve the REST API + dashboard
# Override CMD for other modes:
#   MCP server:         ["python", "serve_mcp.py"]
#   ADK agent:          ["python", "serve_adk.py"]
#   Protected resource: ["python", "serve_resource.py"]
CMD ["python", "serve.py", "--port", "8080", "--host", "0.0.0.0"]
