import ipaddress
from functools import lru_cache

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitoredAwsAccount(BaseModel):
    account_id: str = Field(pattern=r"^\d{12}$")
    name: str = Field(min_length=1, max_length=128)
    role_arn: str | None = None
    external_id: SecretStr | None = None

    @model_validator(mode="after")
    def validate_role(self) -> "MonitoredAwsAccount":
        if self.role_arn is not None:
            parts = self.role_arn.split(":", 5)
            if (
                len(parts) != 6
                or parts[0] != "arn"
                or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
                or parts[2] != "iam"
                or parts[4] != self.account_id
                or not parts[5].startswith("role/")
                or len(parts[5]) == len("role/")
            ):
                raise ValueError("role_arn must be an IAM role ARN in the configured account")
        elif self.external_id is not None:
            raise ValueError("external_id requires role_arn")
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
