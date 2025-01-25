from pydantic_settings import BaseSettings
from typing import Dict

class Settings(BaseSettings):
    SECRET_KEY: str = "your-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

    CLIENTS: dict = {
            "client123": {
                "name": "Client App",
                "uri": "http://localhost:8001",
                "secret": "client-secret",
                "redirect_uri": "http://localhost:8001/callback"
            }
        }

settings = Settings()