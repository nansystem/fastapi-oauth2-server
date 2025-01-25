from fastapi import FastAPI
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth, user
from app.core.config import settings
from app.database import engine, Base


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield  # アプリケーションのシャットダウン時に実行される処理があればyieldの後に記述


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="session",
    max_age=3600,
    same_site="lax",
    https_only=True,
)

app.include_router(auth.router, tags=["認証"])
app.include_router(user.router, tags=["ユーザー管理"])
