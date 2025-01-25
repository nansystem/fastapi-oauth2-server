from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User, OAuthAccount
from app.core.config import settings
import httpx
import secrets
from app.core.security import get_password_hash

router = APIRouter(prefix="/auth", tags=["認証"])
templates = Jinja2Templates(directory="app/templates")


# ログインページ
@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# OAuth2.0認証フロー
@router.get("/oauth")
async def oauth_login(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    return RedirectResponse(
        f"{settings.AUTH_SERVER_URL}/oauth/authorize?"
        f"response_type=code&"
        f"client_id={settings.CLIENT_ID}&"
        f"redirect_uri={settings.REDIRECT_URI}&"
        f"scope={settings.SCOPE}&"
        f"state={state}"
    )


@router.get("/callback")
async def oauth_callback(
    request: Request,
    error: str = None,
    code: str = None,
    state: str = None,
    db: Session = Depends(get_db),
):
    stored_state = request.session.pop("oauth_state", None)
    if not stored_state or stored_state != state:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "不正なリクエスト",
                "message": "CSRF検証に失敗しました",
            },
        )

    if error:
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": "認可エラー", "message": error}
        )

    if not code:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "認可コードがありません",
                "message": "認可サーバーからの応答が不正です",
            },
        )

    # デバッグ用に長めのタイムアウトを設定
    timeout_settings = httpx.Timeout(timeout=120.0)
    async with httpx.AsyncClient(timeout=timeout_settings) as client:
        token_response = await client.post(
            f"{settings.AUTH_SERVER_URL}/oauth/token",
            data={
                "client_id": settings.CLIENT_ID,
                "client_secret": settings.CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )

        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="トークン交換に失敗しました")

        try:
            token_data = token_response.json()

            # OAuth 2.0仕様で必須のパラメータを検証
            if not token_data.get("access_token"):
                raise ValueError("access_tokenが必要です")
            if not token_data.get("token_type"):
                raise ValueError("token_typeが必要です")

            access_token = token_data["access_token"]

            # Bearer以外のtoken_typeは現在サポートしていない
            if token_data["token_type"].lower() != "bearer":
                raise ValueError("Bearerトークンタイプのみサポートしています")

            user_response = await client.get(
                f"{settings.AUTH_SERVER_URL}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=400, detail="ユーザー情報取得に失敗しました"
                )

            user_data = user_response.json()

            # OAuthアカウントを検索
            oauth_account = (
                db.query(OAuthAccount)
                .filter(
                    OAuthAccount.provider == "auth_server",
                    OAuthAccount.sub == user_data["sub"],
                )
                .first()
            )

            if oauth_account:
                # 既存のOAuthアカウントが見つかった場合
                user = oauth_account.user
                # プロバイダーのユーザー名が変更されている可能性があるため更新
                oauth_account.provider_username = user_data["preferred_username"]
                db.commit()
            else:
                # 新規ユーザー登録が必要
                return templates.TemplateResponse(
                    "register.html",
                    {
                        "request": request,
                        "oauth_provider": "auth_server",
                        "oauth_sub": user_data["sub"],
                        "oauth_username": user_data["preferred_username"],
                    },
                )

            request.session["user"] = {"id": user.id, "username": user.username}

            return RedirectResponse("/")
        except Exception as e:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "トークン処理に失敗しました",
                    "message": str(e),
                },
            )


# ユーザー登録
@router.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
async def register(
    request: Request,
    display_name: str = Form(...),
    email: str = Form(None),
    password: str = Form(None),
    oauth_provider: str = Form(None),
    oauth_sub: str = Form(None),
    oauth_username: str = Form(None),
    db: Session = Depends(get_db),
):
    try:
        # メールアドレスの重複チェック（通常登録の場合）
        if email:
            if db.query(User).filter(User.email == email).first():
                return templates.TemplateResponse(
                    "register.html",
                    {
                        "request": request,
                        "error": "このメールアドレスは既に使用されています",
                    },
                    status_code=400,
                )

        # ユーザー名の重複チェック
        if db.query(User).filter(User.username == display_name).first():
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "この表示名は既に使用されています",
                    # OAuth情報がある場合は保持
                    "oauth_provider": oauth_provider,
                    "oauth_sub": oauth_sub,
                    "oauth_username": oauth_username,
                },
                status_code=400,
            )

        # 新規ユーザーを作成
        user = User(
            username=display_name,
            email=email,
            password_hash=get_password_hash(password) if password else None,
        )
        db.add(user)
        db.flush()  # IDを生成

        # OAuth認証情報がある場合は保存
        if oauth_provider and oauth_sub:
            oauth_account = OAuthAccount(
                user_id=user.id,
                provider=oauth_provider,
                sub=oauth_sub,
                provider_username=oauth_username,
            )
            db.add(oauth_account)

        db.commit()

        request.session["user"] = {"id": user.id, "username": user.username}

        return RedirectResponse("/", status_code=303)

    except Exception as e:
        print(f"エラーが発生しました: {str(e)}")
        db.rollback()
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "登録に失敗しました。もう一度お試しください。",
                # OAuth情報がある場合は保持
                "oauth_provider": oauth_provider,
                "oauth_sub": oauth_sub,
                "oauth_username": oauth_username,
            },
            status_code=400,
        )


# ログアウト
@router.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse("/")
