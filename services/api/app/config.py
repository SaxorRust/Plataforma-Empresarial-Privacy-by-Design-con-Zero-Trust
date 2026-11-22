from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_name: str = "Hospital-Privacy-ZeroTrust"
    database_url: str = "postgresql://zt_app_user:dev_postgres_change_me@postgres:5432/hospital_zt"
    vault_addr: str = "http://vault:8200"
    vault_dev_root_token_id: str = "dev_vault_token_change_me"
    vault_transit_mount: str = "transit"
    vault_transit_key: str = "hospital-pii-key"
    vault_kv_mount: str = "secret"
    vault_kv_prefix: str = "patients"
    vault_timeout_seconds: float = 5.0
    opa_url: str = "http://opa:8181/v1/data/hospital/authz/decision"
    siem_host: str = "siem-collector"
    siem_port: int = 5514
    argon2_pepper: str = "dev_pepper_change_me"
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 2
    argon2_hash_len: int = 32
    argon2_salt_len: int = 16
    jwt_secret_key: str = "dev_jwt_secret_change_me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    webauthn_rp_id: str = "tralaleritosmigajeros.uk"
    webauthn_rp_name: str = "Hospital Privacy Zero Trust BUAP"
    webauthn_origin: str = "https://tralaleritosmigajeros.uk"
    webauthn_expected_origins: str = ""
    webauthn_challenge_ttl_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def get_webauthn_origins(self) -> list[str]:
        origins: list[str] = [self.webauthn_origin]
        if self.webauthn_expected_origins:
            origins.extend(
                origin.strip()
                for origin in self.webauthn_expected_origins.split(",")
                if origin.strip()
            )
        if self.app_env == "development":
            origins.extend(["http://localhost:8000", "http://127.0.0.1:8000"])
        return sorted(set(origins))


settings = Settings()
