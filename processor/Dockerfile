FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir \
    kafka-python \
    psycopg2-binary \
    requests

# Copy stream processor
COPY processor/stream_processor.py .

# Copy v3 feature modules (analyzers, clients)
COPY analyzers/ ./analyzers/
COPY clients/ ./clients/

CMD ["python", "stream_processor.py", "--replay"]
