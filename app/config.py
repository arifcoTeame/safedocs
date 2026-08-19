# Author: Arif Alsuhaimi
"""Central configuration, loaded from environment / .env."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    use_dws: bool = False
    dws_api_key: str = ""            # Processor key (redact / sign / parse-fallback)
    dws_extract_api_key: str = ""    # Data Extraction key (parse); optional

    app_host: str = "127.0.0.1"
    app_port: int = 8000
    storage_dir: str = "storage"


settings = Settings()
