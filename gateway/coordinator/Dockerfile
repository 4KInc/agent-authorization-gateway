FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    google-cloud-firestore \
    google-cloud-secret-manager \
    google-adk \
    google-genai \
    fastapi \
    uvicorn \
    cryptography \
    pydantic \
    httpx \
    google-cloud-logging \
    "a2a-sdk[fastapi]"

COPY . gateway/coordinator/

# Need __init__.py for the gateway package
RUN mkdir -p gateway && touch gateway/__init__.py

ENV PYTHONUNBUFFERED=1
ENV PORT=8080
EXPOSE 8080

CMD exec uvicorn gateway.coordinator.coordinator_service:app \
    --host 0.0.0.0 --port ${PORT} \
    --workers 1 --timeout-keep-alive 75
