FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    psycopg2-binary \
    prometheus-client

COPY exporter.py .

EXPOSE 8000

CMD ["python", "exporter.py"]
