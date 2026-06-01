FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    google-cloud-firestore \
    google-cloud-secret-manager \
    google-cloud-pubsub \
    google-adk \
    google-genai \
    google-auth \
    fastapi \
    uvicorn \
    httpx \
    cryptography \
    pydantic

COPY . gateway/investigator/

# Need __init__.py for the gateway package
RUN mkdir -p gateway && touch gateway/__init__.py

ENV PYTHONUNBUFFERED=1
ENV PORT=8080
EXPOSE 8080

CMD exec uvicorn gateway.investigator.investigator_service:app \
    --host 0.0.0.0 --port ${PORT} \
    --workers 1 --timeout-keep-alive 75
