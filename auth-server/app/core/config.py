from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "xxxxxx"
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

settings = Settings()