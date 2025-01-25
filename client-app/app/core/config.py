from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str = "your-secret-key"
    DATABASE_URL: str = "sqlite:///./client.db"

    # OAuth2設定
    CLIENT_ID: str = "client123"
    CLIENT_SECRET: str = "client-secret"
    REDIRECT_URI: str = "http://localhost:8001/auth/callback"
    AUTH_SERVER_URL: str = "http://localhost:8000"
    SCOPE: str = "profile email"


settings = Settings()
