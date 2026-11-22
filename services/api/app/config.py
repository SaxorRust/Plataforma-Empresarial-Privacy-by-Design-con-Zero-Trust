from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_name: str = "Hospital-Privacy-ZeroTrust"
    database_url: str = "postgresql://zt_app_user:dev_postgres_change_me@postgres:5432/hospital_zt"
    vault_addr: str = "http://vault:8200"
    vault_dev_root_token_id: str = "dev_vault_token_change_me"
    opa_url: str = "http://opa:8181/v1/data/hospital/authz/decision"
    siem_host: str = "siem-collector"
    siem_port: int = 5514
    argon2_pepper: str = "dev_pepper_change_me"
    jwt_secret_key: str = "dev_jwt_secret_change_me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    webauthn_rp_id: str = "tralaleritosmigajeros.uk"
    webauthn_rp_name: str = "Hospital Privacy Zero Trust BUAP"
    webauthn_origin: str = "https://tralaleritosmigajeros.uk"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
