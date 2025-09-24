FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    structlog==23.2.0 \
    pydantic==2.5.0 \
    pydantic[email]==2.5.0 \
    pyjwt==2.8.0 \
    cryptography==41.0.8

COPY main.py .

RUN useradd -r -s /bin/false appuser
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health/live || exit 1

EXPOSE 8081

CMD ["python", "main.py"]
