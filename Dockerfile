FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir cryptography PyJWT google-cloud-firestore uvicorn httpx fastapi pydantic

# Copy source
COPY gateway/ gateway/
COPY serve.py .

EXPOSE 8080

CMD ["python", "serve.py", "--port", "8080", "--host", "0.0.0.0"]
