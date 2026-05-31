FROM python:3.13-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx cryptography pydantic PyJWT
COPY main.py .
ENV PORT=8080
CMD ["python", "main.py"]
