import ipaddress
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
