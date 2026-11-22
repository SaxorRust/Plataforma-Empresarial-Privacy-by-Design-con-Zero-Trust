FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10002 siemgroup \
    && useradd --uid 10002 --gid siemgroup --shell /usr/sbin/nologin --create-home siemuser \
    && mkdir -p /data && chown -R siemuser:siemgroup /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN chown -R siemuser:siemgroup /app

USER siemuser

EXPOSE 8080 5514

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
