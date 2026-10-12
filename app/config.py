"""Application configuration loaded from environment variables."""
from __future__ import annotations

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    SITE_NAME: str = "LinkPlatform"
    SITE_TAGLINE: str = "Shorten, track, and manage your links."
    PORT: int = 8000
    DATA_DIR: str = "/data"
    SECRET_KEY: str = ""
    BASE_URL: str = ""
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    TRUST_PROXY: bool = False
    REGISTRATION_OPEN: bool = True
    SECURE_COOKIES: str = "auto"
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    CLICK_RETENTION_DAYS: int = 90
    SESSION_DAYS: int = 7

    @model_validator(mode="after")
    def _validate_secret(self) -> "Settings":
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ValueError(
                "SECRET_KEY environment variable is required and must be "
                "at least 32 characters long"
            )
        return self

    @property
    def allowed_hosts(self) -> list[str]:
        """Allowed Host header values, including the BASE_URL host when set."""
        hosts = [h.strip().lower() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]
        if self.BASE_URL:
            try:
                from urllib.parse import urlsplit

                host = urlsplit(self.BASE_URL).hostname
                if host and host.lower() not in hosts:
                    hosts.append(host.lower())
            except Exception:
                pass
        return hosts

    def cookie_secure(self, scheme: str = "", forwarded_proto: str = "") -> bool:
        """Whether auth cookies should carry the Secure flag.

        Mode "auto" enables Secure when the current request arrived over
        HTTPS or BASE_URL itself is https.
        """
        mode = self.SECURE_COOKIES.strip().lower()
        if mode == "true":
            return True
        if mode == "false":
            return False
        if scheme == "https" or forwarded_proto == "https":
            return True
        return self.BASE_URL.startswith("https://")


settings = Settings()
