import html
import json
import smtplib
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import DetectionAlert, Incident, NotificationDelivery

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_MAX_ATTEMPTS = 5


class NotificationDeliveryError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


NotificationSender = Callable[[NotificationDelivery, DetectionAlert, Incident, Settings], None]


def configured_channels(settings: Settings) -> tuple[str, ...]:
    channels: list[str] = []
    if settings.slack_webhook_url is not None:
        channels.append("slack")
    if settings.teams_webhook_url is not None:
        channels.append("teams")
    if settings.smtp_host and settings.notification_email_from and settings.notification_email_to:
        channels.append("email")
    return tuple(channels)


def enqueue_alert_notifications(
    db: Session,
    alert: DetectionAlert,
    incident: Incident,
    settings: Settings,
) -> None:
    if _SEVERITY_RANK[alert.severity] < _SEVERITY_RANK[settings.notification_min_severity]:
        return
    now = datetime.now(UTC)
    for channel in configured_channels(settings):
        existing = db.scalar(
            select(NotificationDelivery).where(
                NotificationDelivery.alert_id == alert.id,
                NotificationDelivery.channel == channel,
            )
        )
        if existing is not None:
            continue
        delivery = NotificationDelivery(
            alert_id=alert.id,
            incident_id=incident.id,
            channel=channel,
            status="pending",
            attempt_count=0,
            next_attempt_at=now,
        )
        try:
            with db.begin_nested():
                db.add(delivery)
                db.flush()
        except IntegrityError:
            existing = db.scalar(
                select(NotificationDelivery).where(
                    NotificationDelivery.alert_id == alert.id,
                    NotificationDelivery.channel == channel,
                )
            )
            if existing is None:
                raise


def _message(alert: DetectionAlert, incident: Incident) -> str:
    return (
        f"{alert.severity.upper()} AWS security alert: {alert.title}\n"
        f"Account: {alert.account_id} | Region: {alert.region}\n"
        f"Incident: {incident.id} | Detection: {alert.rule_id}"
    )


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _send_webhook(
    webhook: str,
    payload: dict[str, str],
) -> None:
    parsed = urlsplit(webhook)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NotificationDeliveryError("InvalidWebhookUrl")
    request = urllib.request.Request(
        webhook,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_RejectRedirectHandler)
    try:
        with opener.open(request, timeout=8) as response:
            if not 200 <= response.status < 300:
                raise NotificationDeliveryError(f"HttpStatus{response.status}")
    except urllib.error.HTTPError as exc:
        raise NotificationDeliveryError(f"HttpStatus{exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise NotificationDeliveryError(type(exc).__name__) from exc


def _send_slack(
    delivery: NotificationDelivery,
    alert: DetectionAlert,
    incident: Incident,
    settings: Settings,
) -> None:
    del delivery
    if settings.slack_webhook_url is None:
        raise NotificationDeliveryError("ChannelNotConfigured")
    _send_webhook(
        settings.slack_webhook_url.get_secret_value(),
        {"text": _message(alert, incident)},
    )


def _send_teams(
    delivery: NotificationDelivery,
    alert: DetectionAlert,
    incident: Incident,
    settings: Settings,
) -> None:
    del delivery
    if settings.teams_webhook_url is None:
        raise NotificationDeliveryError("ChannelNotConfigured")
    text = _message(alert, incident)
    _send_webhook(
        settings.teams_webhook_url.get_secret_value(),
        {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": alert.title,
            "title": f"{alert.severity.upper()} AWS security alert",
            "text": html.escape(text).replace("\n", "<br>"),
        },
    )


def _send_email(
    delivery: NotificationDelivery,
    alert: DetectionAlert,
    incident: Incident,
    settings: Settings,
) -> None:
    del delivery
    if not settings.smtp_host or not settings.notification_email_from:
        raise NotificationDeliveryError("ChannelNotConfigured")
    recipients = [recipient.strip() for recipient in settings.notification_email_to.split(",")]
    recipients = [recipient for recipient in recipients if recipient]
    if not recipients:
        raise NotificationDeliveryError("ChannelNotConfigured")

    message = EmailMessage()
    subject = f"{alert.severity.upper()} AWS security alert: {' '.join(alert.title.splitlines())}"
    message["Subject"] = subject[:250]
    message["From"] = settings.notification_email_from
    message["To"] = ", ".join(recipients)
    message.set_content(_message(alert, incident))
    try:
        if settings.smtp_port == 465:
            with smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=8,
                context=ssl.create_default_context(),
            ) as client:
                _send_smtp_message(client, settings, message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=8) as client:
                client.starttls(context=ssl.create_default_context())
                _send_smtp_message(client, settings, message)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        raise NotificationDeliveryError(type(exc).__name__) from exc


def _send_smtp_message(client: smtplib.SMTP, settings: Settings, message: EmailMessage) -> None:
    if settings.smtp_username and settings.smtp_password:
        client.login(settings.smtp_username, settings.smtp_password.get_secret_value())
    refused = client.send_message(message)
    if refused:
        raise NotificationDeliveryError("EmailRecipientRejected")


def _sender(channel: str) -> NotificationSender:
    return {
        "slack": _send_slack,
        "teams": _send_teams,
        "email": _send_email,
    }[channel]


def dispatch_due_notifications(
    db: Session,
    settings: Settings,
    *,
    limit: int = 20,
    senders: dict[str, NotificationSender] | None = None,
) -> dict[str, int]:
    now = datetime.now(UTC)
    deliveries = db.scalars(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.status.in_(("pending", "retrying")),
            NotificationDelivery.next_attempt_at <= now,
        )
        .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).all()
    sent = 0
    retrying = 0
    failed = 0
    for delivery in deliveries:
        alert = db.get(DetectionAlert, delivery.alert_id)
        incident = db.get(Incident, delivery.incident_id)
        delivery.attempt_count += 1
        delivery.last_attempt_at = now
        if alert is None or incident is None:
            error_code = "NotificationSubjectNotFound"
        else:
            try:
                (senders or {}).get(delivery.channel, _sender(delivery.channel))(
                    delivery, alert, incident, settings
                )
            except NotificationDeliveryError as exc:
                error_code = exc.code
            else:
                delivery.status = "delivered"
                delivery.delivered_at = now
                delivery.last_error_code = None
                sent += 1
                db.commit()
                continue

        delivery.last_error_code = error_code[:128]
        delivery.status = "failed" if delivery.attempt_count >= _MAX_ATTEMPTS else "retrying"
        if delivery.status == "failed":
            failed += 1
        else:
            retrying += 1
            delay_seconds = min(3600, 30 * (2 ** (delivery.attempt_count - 1)))
            delivery.next_attempt_at = now + timedelta(seconds=delay_seconds)
        db.commit()
    return {"selected": len(deliveries), "sent": sent, "retrying": retrying, "failed": failed}
