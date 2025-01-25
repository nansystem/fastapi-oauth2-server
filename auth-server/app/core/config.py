from pydantic_settings import BaseSettings
from typing import Dict, Set


class Settings(BaseSettings):
    SECRET_KEY: str = "your-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

    # 利用可能なスコープの定義
    AVAILABLE_SCOPES: Set[str] = {
        "profile",  # ユーザープロフィール情報
        "email",  # メールアドレス
    }

    CLIENTS: Dict = {
        "client123": {
            "name": "Client App",
            "uri": "http://localhost:8001",
            "secret": "client-secret",
            "redirect_uri": "http://localhost:8001/callback",
            "allowed_scopes": [
                "profile",
                "email",
            ],  # クライアントごとに許可するスコープ
        }
    }


settings = Settings()
