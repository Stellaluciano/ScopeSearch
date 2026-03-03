from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://scopesearch:scopesearch@postgres:5432/scopesearch"
    redis_url: str = "redis://redis:6379/0"
    scope_file: str = "/app/scope.yml"
    scan_queue_name: str = "scan_jobs"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
