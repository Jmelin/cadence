FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN addgroup -S app && adduser -S -G app app

COPY requirements.txt ./
RUN pip install --no-compile -r requirements.txt

COPY --chown=app:app app.py ./app.py
COPY --chown=app:app templates ./templates
RUN mkdir -p /data && chown app:app /data

USER app

EXPOSE 5000

CMD ["gunicorn", "--bind=0.0.0.0:5000", "--workers=2", "--threads=4", "--timeout=60", "app:app"]
