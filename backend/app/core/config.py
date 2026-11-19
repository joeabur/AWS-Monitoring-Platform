import ipaddress
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitoredAwsAccount(BaseModel):
    account_id: str = Field(pattern=r"^\d{12}$")
    name: str = Field(min_length=1, max_length=128)
    role_arn: str | None = None
    external_id: SecretStr | None = None
    response_role_arn: str | None = None
    response_external_id: SecretStr | None = None
    response_allowed_iam_users: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_role(self) -> "MonitoredAwsAccount":
        for field_name in ("role_arn", "response_role_arn"):
            role_arn = getattr(self, field_name)
            if role_arn is not None:
                parts = role_arn.split(":", 5)
                if (
                    len(parts) != 6
                    or parts[0] != "arn"
                    or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
                    or parts[2] != "iam"
                    or parts[4] != self.account_id
                    or not parts[5].startswith("role/")
                    or len(parts[5]) == len("role/")
                ):
                    raise ValueError(
                        f"{field_name} must be an IAM role ARN in the configured account"
                    )
        if self.external_id is not None and self.role_arn is None:
            raise ValueError("external_id requires role_arn")
        if self.response_external_id is not None and self.response_role_arn is None:
            raise ValueError("response_external_id requires response_role_arn")
        if self.response_role_arn is not None and self.response_external_id is None:
            raise ValueError("response_role_arn requires a separate response_external_id")
        if self.response_role_arn == self.role_arn and self.response_role_arn is not None:
            raise ValueError("monitoring and response roles must be separate IAM roles")
        if self.response_allowed_iam_users and self.response_role_arn is None:
            raise ValueError("response_allowed_iam_users requires response_role_arn")
        if any(
            not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,128}", user_name)
            for user_name in self.response_allowed_iam_users
        ):
            raise ValueError("response_allowed_iam_users contains an invalid IAM username")
        if len(set(self.response_allowed_iam_users)) != len(self.response_allowed_iam_users):
            raise ValueError("response_allowed_iam_users cannot contain duplicates")
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./monitoring.db"
    jwt_secret_key: SecretStr | None = Field(default=None, min_length=32)
    jwt_expire_minutes: int = Field(default=30, gt=0)
    cors_origins: str = "http://localhost:3000"
    environment: str = "development"
    expected_iam_users: str = ""
    trusted_ip_cidrs: str = ""
    sensitive_resource_arns: str = ""
    monitored_aws_accounts: list[MonitoredAwsAccount] = Field(default_factory=list)
    response_actions_enabled: bool = False
    response_dry_run: bool = True
    notification_min_severity: str = "high"
    slack_webhook_url: SecretStr | None = None
    teams_webhook_url: SecretStr | None = None
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    notification_email_from: str | None = None
    notification_email_to: str = ""
    mcp_enabled: bool = False

    @field_validator("notification_min_severity")
    @classmethod
    def validate_notification_min_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"critical", "high", "medium", "low", "informational"}:
            raise ValueError("notification_min_severity is invalid")
        return normalized

    @field_validator("slack_webhook_url", "teams_webhook_url")
    @classmethod
    def empty_webhook_is_not_configured(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            return None
        if value is not None:
            try:
                parsed = urlsplit(value.get_secret_value())
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                ):
                    raise ValueError
            except ValueError as exc:
                raise ValueError(
                    "Notification webhook URLs must use HTTPS and omit credentials"
                ) from exc
        return value

    @model_validator(mode="after")
    def validate_notification_delivery_configuration(self) -> "Settings":
        smtp_fields = (self.smtp_host, self.notification_email_from, self.notification_email_to)
        if any(smtp_fields) and not all(smtp_fields):
            raise ValueError(
                "SMTP_HOST, NOTIFICATION_EMAIL_FROM, and NOTIFICATION_EMAIL_TO are required together"
            )
        has_username = bool(self.smtp_username)
        has_password = self.smtp_password is not None and bool(
            self.smtp_password.get_secret_value()
        )
        if has_username != has_password:
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
        if (has_username or has_password) and not self.smtp_host:
            raise ValueError("SMTP credentials require SMTP_HOST")
        return self

    @field_validator("trusted_ip_cidrs")
    @classmethod
    def validate_trusted_ip_cidrs(cls, value: str) -> str:
        for cidr in value.split(","):
            normalized = cidr.strip()
            if normalized:
                try:
                    ipaddress.ip_network(normalized, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid trusted IP CIDR: {normalized}") from exc
        return value

    @field_validator("monitored_aws_accounts")
    @classmethod
    def validate_unique_aws_accounts(
        cls, value: list[MonitoredAwsAccount]
    ) -> list[MonitoredAwsAccount]:
        account_ids = [account.account_id for account in value]
        if len(account_ids) != len(set(account_ids)):
            raise ValueError("MONITORED_AWS_ACCOUNTS cannot contain duplicate account IDs")
        return value

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        if self.environment.strip().lower() != "production":
            return self
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("Production requires a PostgreSQL DATABASE_URL")
        try:
            database_query = parse_qs(urlsplit(self.database_url).query)
        except ValueError as exc:
            raise ValueError("Production DATABASE_URL is invalid") from exc
        if database_query.get("sslmode", [None])[-1] not in {
            "require",
            "verify-ca",
            "verify-full",
        }:
            raise ValueError("Production DATABASE_URL must require TLS using sslmode")

        origins = self.allowed_origins
        if not origins:
            raise ValueError("Production requires at least one HTTPS CORS origin")
        for origin in origins:
            try:
                parsed = urlsplit(origin)
                hostname = parsed.hostname
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("Production CORS origins must be valid HTTPS origins") from exc
            try:
                loopback = bool(hostname and ipaddress.ip_address(hostname).is_loopback)
            except ValueError:
                loopback = False
            if (
                parsed.scheme != "https"
                or not hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
                or hostname.lower() == "localhost"
                or hostname.lower().endswith(".localhost")
                or loopback
            ):
                raise ValueError(
                    "Production CORS origins must be exact HTTPS origins without credentials, "
                    "paths, or localhost"
                )
        return self

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def require_jwt_secret(self) -> str:
        if self.jwt_secret_key is None:
            raise ValueError("JWT_SECRET_KEY must be configured for the API")
        return self.jwt_secret_key.get_secret_value()


@lru_cache
def get_settings() -> Settings:
    return Settings()
