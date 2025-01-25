from fastapi import APIRouter, Request, Depends, HTTPException, status, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from app import models, security
from app.security import get_password_hash
from fastapi.templating import Jinja2Templates
from app.core.config import oauth_settings
from urllib.parse import urlencode
from app.database import get_db
import httpx

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


# 認証関連ルートの定義
@router.get("/", response_class=HTMLResponse)
async def show_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
async def show_dashboard(request: Request):
    if "user" not in request.session:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.post("/login")
async def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user or not security.verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.session["user"] = username
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/register", response_class=HTMLResponse)
async def show_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
async def handle_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(models.User).filter(models.User.username == username).first()
    )
    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "このユーザー名は既に使用されています"},
        )

    hashed_password = get_password_hash(password)
    new_user = models.User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/session-check")
async def session_check(request: Request):
    return {"session": dict(request.session)}


# OAuthでログイン
@router.get("/auth/login")
async def login_via_oauth(request: Request):
    state = security.generate_state()
    request.session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": oauth_settings.client_id,
        "redirect_uri": oauth_settings.redirect_uri,
        "scope": "openid profile",
        "state": state,
    }
    return RedirectResponse(f"{oauth_settings.authorize_url}?{urlencode(params)}")


@router.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
):
    if error:
        raise HTTPException(status_code=400, detail=error)

    # State検証
    if state != request.session.get("oauth_state"):
        raise HTTPException(status_code=400, detail="Invalid state")
    del request.session["oauth_state"]

    # トークン取得
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            oauth_settings.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth_settings.redirect_uri,
                "client_id": oauth_settings.client_id,
                "client_secret": oauth_settings.client_secret,
            },
        )

    if token_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Token fetch failed")

    token_data = token_response.json()
    access_token = token_data["access_token"]

    # ユーザー情報取得
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            oauth_settings.user_info_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    user_info = user_response.json()
    request.session["user"] = user_info["username"]

    return RedirectResponse(url="/dashboard")
