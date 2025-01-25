from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth, user, oauth
from app.core.config import settings

app = FastAPI()

allowed_origins = [client["uri"] for client in settings.CLIENTS.values()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # 全てのクライアントのURIを許可
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# セッションミドルウェアの設定
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="__Host-session",
    max_age=3600,
    same_site="Lax",
    https_only=True,
)

app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(user.router)
