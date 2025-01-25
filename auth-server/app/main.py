from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth
from app.core.config import settings

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="session",
    max_age=3600,
    same_site="lax",
    https_only=True
)

app.include_router(auth.router)
