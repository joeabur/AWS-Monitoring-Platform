import json
import logging
from collections.abc import Mapping
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.database import get_session_factory
from app.ingestion.cloudtrail import EventNormalizationError
from app.ingestion.service import ingest_cloudtrail_event

logger = logging.getLogger(__name__)


def lambda_handler(event: dict[str, Any], _: object) -> dict[str, list[dict[str, str]]]:
    """Process an SQS Lambda batch; failed records are retried independently."""
    database_url = get_settings().database_url
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise RuntimeError("The SQS worker requires a PostgreSQL DATABASE_URL")

    records = event.get("Records")
    if not isinstance(records, list):
        raise TypeError("SQS event must contain a Records list")

    failures: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise TypeError("Every SQS record must be an object")
        message_id = record.get("messageId")
        body_text = record.get("body")
        if not isinstance(message_id, str) or not message_id or not isinstance(body_text, str):
            raise ValueError("Every SQS record must contain messageId")
        try:
            body = json.loads(body_text)
            if not isinstance(body, dict):
                raise EventNormalizationError("SQS message body must be a JSON object")
            session = get_session_factory()()
            try:
                result = ingest_cloudtrail_event(session, body)
            finally:
                session.close()
            logger.info(
                "Processed CloudTrail SQS message",
                extra={
                    "message_id": message_id,
                    "event_id": result.event.cloudtrail_event_id,
                    "duplicate": result.duplicate,
                },
            )
        except (KeyError, json.JSONDecodeError, EventNormalizationError, SQLAlchemyError):
            logger.exception(
                "Failed to process CloudTrail SQS message",
                extra={"message_id": message_id},
            )
            failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failures}
