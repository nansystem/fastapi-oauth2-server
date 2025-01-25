from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth
from app.core.config import settings
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="session",
    max_age=3600,
    same_site="lax",
    secure=True
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
