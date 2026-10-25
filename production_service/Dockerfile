FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system paca && useradd --system --gid paca --home-dir /app paca \
    && mkdir -p /app /var/lib/paca/files \
    && chown -R paca:paca /app /var/lib/paca

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY paca_service /app/paca_service
RUN pip install --no-cache-dir .

USER paca
EXPOSE 8000
CMD ["uvicorn", "paca_service.bootstrap:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
