FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt && pip install --no-cache-dir build twine

COPY backend/ /app
COPY publish_cli.py /app/publish_cli.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PORT=8000 \
	AUDIT_LOG_ENABLED=true \
	AUDIT_LOG_STORE_OUTPUT=false \
	AUDIT_LOG_PATH=audit_log.jsonl \
	DATA_RESIDENCY=us-west1 \
	SETTINGS_SCOPE=user \
	SETTINGS_STORE_PATH=settings.enc \
	REQUIRE_AI_REVIEW_DEFAULT=false
EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
