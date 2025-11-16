# Python slim, fără cache-uri și cu un user non-root
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# deps minime de sistem (pentru wheel-uri)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# creează un user non-root
RUN useradd -m -u 10001 appuser

WORKDIR /app

# dependențe
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# codul aplicației
COPY app/ ./app

# permisiuni pentru userul non-root
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Gunicorn + UvicornWorker; ajustează -w după CPU
CMD ["gunicorn","app.main:app","-k","uvicorn.workers.UvicornWorker","-w","4","-b","0.0.0.0:8000","--timeout","60"]

