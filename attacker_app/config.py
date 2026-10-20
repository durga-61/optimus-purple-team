"""Configuration settings for Part 2 AI Attacker Application."""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class AttackerConfig:
    """Attacker application configuration."""

    HOST: str = os.getenv("ATTACKER_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("ATTACKER_PORT", "8001"))
    GATEWAY_BASE_URL: str = os.getenv(
        "ATTACKER_GATEWAY_BASE_URL", "http://127.0.0.1:8000/api/attacker"
    ).rstrip("/")
    GATEWAY_TOKEN: str | None = os.getenv("ATTACK_GATEWAY_TOKEN", None)
    OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY", os.getenv("ATTACKER_LLM_API_KEY", None))
    ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY", None)
    ATTACKER_LLM_PROVIDER: str = os.getenv("ATTACKER_LLM_PROVIDER", "openai")
    ATTACKER_LLM_MODEL: str = os.getenv("ATTACKER_LLM_MODEL", "gpt-4o-mini")
    REQUEST_TIMEOUT: float = float(os.getenv("ATTACKER_TIMEOUT", "10.0"))
    ATTACKER_API_KEY: str | None = os.getenv("ATTACKER_API_KEY", None)
    LOCAL_DEMO_MODE: bool = os.getenv("LOCAL_DEMO_MODE", "true").lower() in ("true", "1", "yes")
    CORS_ORIGINS: list[str] = None  # type: ignore

    def __post_init__(self):
        if self.CORS_ORIGINS is None:
            raw = os.getenv(
                "ATTACKER_CORS_ORIGINS",
                "http://localhost:8001,http://127.0.0.1:8001,http://localhost:3000,http://127.0.0.1:3000",
            )
            self.CORS_ORIGINS = [o.strip() for o in raw.split(",") if o.strip()]


config = AttackerConfig()

