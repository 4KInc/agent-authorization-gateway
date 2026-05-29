FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "a2a-sdk[fastapi]" \
    google-cloud-firestore \
    google-cloud-secret-manager \
    cryptography \
    PyJWT \
    uvicorn \
    fastapi \
    httpx

# Copy gateway code (needed for GatewayService, signing_key, verify, etc.)
COPY gateway/ gateway/

ENV PYTHONUNBUFFERED=1
ENV PORT=8080
EXPOSE 8080

CMD exec uvicorn gateway.a2a.a2a_server:app \
    --host 0.0.0.0 --port ${PORT} \
    --workers 1
