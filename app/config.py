from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NG_", extra="ignore")

    environment: str = "dev"
    target_server: str = "http://localhost:3000"
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8000

    request_timeout_seconds: float = 15.0
    max_body_bytes: int = 1024 * 1024
    model_path: str = "app/models/neural_gate_cnn.pt"

    malicious_threshold: float = 0.85
    entropy_threshold: float = 7.0
    exfiltration_entropy_threshold: float = 7.5

    enable_phase2_pcap: bool = False
    blocklist_ttl_seconds: int = 1800
    ddos_window_seconds: int = 10
    ddos_max_requests: int = 120

    attack_demo_allowlist: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    allowed_staging_hosts: list[str] = Field(default_factory=list)


settings = Settings()
