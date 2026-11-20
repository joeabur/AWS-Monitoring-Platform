import json
import logging
import time
from collections.abc import Mapping
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.database import get_session_factory, is_postgres_database
from app.ingestion.cloudtrail import EventNormalizationError, expand_securityhub_event
from app.ingestion.service import ingest_cloudtrail_event
from app.telemetry import emit_emf_metric

logger = logging.getLogger(__name__)


def lambda_handler(event: dict[str, Any], _: object) -> dict[str, list[dict[str, str]]]:
    """Process an SQS Lambda batch; failed records are retried independently."""
    if not is_postgres_database(get_settings()):
        raise RuntimeError("The SQS worker requires a PostgreSQL DATABASE_URL")

    records = event.get("Records")
    if not isinstance(records, list):
        raise TypeError("SQS event must contain a Records list")

    failures: list[dict[str, str]] = []
    processed_count = 0
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
                envelopes = expand_securityhub_event(body)
                results = [ingest_cloudtrail_event(session, envelope) for envelope in envelopes]
            finally:
                session.close()
            logger.info(
                "Processed AWS security event SQS message",
                extra={
                    "message_id": message_id,
                    "event_ids": [result.event.cloudtrail_event_id for result in results],
                    "duplicate_count": sum(result.duplicate for result in results),
                },
            )
            processed_count += 1
        except (KeyError, json.JSONDecodeError, EventNormalizationError, SQLAlchemyError):
            logger.exception(
                "Failed to process CloudTrail SQS message",
                extra={"message_id": message_id},
            )
            failures.append({"itemIdentifier": message_id})

    emit_emf_metric(
        {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": "AWSMonitoringPlatform",
                        "Dimensions": [["Service"]],
                        "Metrics": [
                            {"Name": "WorkerMessagesProcessed", "Unit": "Count"},
                            {"Name": "WorkerMessagesFailed", "Unit": "Count"},
                        ],
                    }
                ],
            },
            "Service": "worker",
            "WorkerMessagesProcessed": processed_count,
            "WorkerMessagesFailed": len(failures),
        }
    )
    return {"batchItemFailures": failures}
