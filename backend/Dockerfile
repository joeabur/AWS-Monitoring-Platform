FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --create-home app \
    && chown app:app /app
COPY --chown=app:app app ./app
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini .

EXPOSE 8000
USER app
CMD ["sh", "-c", "if [ \"${MIGRATIONS_ON_STARTUP:-true}\" = true ]; then alembic upgrade head || exit; fi; exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
