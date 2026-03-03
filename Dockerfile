FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt requirements.txt

RUN   pip install --no-cache-dir -U pip && \
      pip install --no-cache-dir -r requirements.txt

COPY hardax.py hardax.py
COPY templates templates
COPY commands commands

ENTRYPOINT ["python3", "/app/hardax.py"]