from fastapi import APIRouter, Request, HTTPException, Depends, Form, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.services.oauth_service import OAuthService
from app.core.config import settings
from app.database import get_db
from app.models.user import User
from urllib.parse import urlencode
from app.core.templates import templates
from app.core.security import generate_csrf_token, verify_csrf_token
import httpx

router = APIRouter(prefix="/oauth", tags=["OAuth認証"])


@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: str = Query(None),
    scope: str = Query(...),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login?next=/oauth/authorize", status_code=303)

    if client_id not in settings.CLIENTS:
        return RedirectResponse(
            f"{redirect_uri}?error=unauthorized_client",
            status_code=303,
        )

    if redirect_uri != settings.CLIENTS[client_id]["redirect_uri"]:
        return RedirectResponse(
            f"{redirect_uri}?error=invalid_redirect_uri",
            status_code=303,
        )

    if response_type != "code":
        return RedirectResponse(
            f"{redirect_uri}?error=unsupported_response_type",
            status_code=303,
        )

    requested_scopes = set(scope.split())
    invalid_scopes = requested_scopes - settings.AVAILABLE_SCOPES
    if invalid_scopes:
        return RedirectResponse(
            f"{redirect_uri}?error=invalid_scope&error_description=Unsupported+scopes:{'+'.join(invalid_scopes)}",
            status_code=303,
        )

    client_allowed_scopes = set(settings.CLIENTS[client_id]["allowed_scopes"])
    unauthorized_scopes = requested_scopes - client_allowed_scopes
    if unauthorized_scopes:
        return RedirectResponse(
            f"{redirect_uri}?error=insufficient_scope&error_description=Client+not+authorized+for+scopes:{'+'.join(unauthorized_scopes)}",
            status_code=303,
        )

    # OAuth認可フローの状態を保存
    request.session["oauth_state"] = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }

    csrf_token = generate_csrf_token()
    request.session["csrf_token"] = csrf_token

    return templates.TemplateResponse(
        "consent.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "scope": scope,  # 同意画面での表示用にscopeのみ渡す
        },
    )


@router.post("/authorize")
async def authorize_action(
    request: Request,
    csrf_token: str = Form(...),
    action: str = Form(...),
):
    if not verify_csrf_token(csrf_token, request.session["csrf_token"]):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    request.session.pop("csrf_token", None)

    # セッションからOAuth状態を取得
    oauth_state = request.session.get("oauth_state", {})
    client_id = oauth_state.get("client_id")
    redirect_uri = oauth_state.get("redirect_uri")
    scope = oauth_state.get("scope")
    state = oauth_state.get("state")

    if not all([client_id, redirect_uri, scope]):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    if action != "allow":
        params = {"error": "access_denied"}
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)

    # 認可コード生成
    code = OAuthService.generate_authorization_code(
        client_id=client_id,
        user_id=request.session["user"]["id"],
        redirect_uri=redirect_uri,
        scope=scope,
    )

    params = {"code": code}
    if state:
        params["state"] = state

    # OAuth状態をクリア
    request.session.pop("oauth_state", None)

    return RedirectResponse(
        f"{redirect_uri}?{urlencode(params)}",
        status_code=303,
    )


@router.post("/token")
async def token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    grant_type: str = Form(...),
):
    # クライアント認証
    if (
        client_id not in settings.CLIENTS
        or client_secret != settings.CLIENTS[client_id]["client_secret"]
    ):
        raise HTTPException(status_code=401, detail="Invalid client authentication")

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    # 認可コードの検証とトークンの生成
    try:
        return OAuthService.exchange_code_for_token(
            code=code, client_id=client_id, redirect_uri=redirect_uri
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/userinfo")
async def userinfo_endpoint(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    token = auth_header.split(" ")[1]
    try:
        # profileスコープの検証
        token_data = OAuthService.validate_token(token, required_scope="profile")
        user = db.query(User).filter(User.id == token_data["user_id"]).first()

        # OpenID Connect
        response_data = {
            "sub": user.sub,
            "name": user.username,
            "preferred_username": user.username,
            "updated_at": int(user.updated_at.timestamp()),
        }

        # emailスコープがある場合
        token_scopes = set(token_data["scope"].split())
        if "email" in token_scopes and user.email:
            response_data.update(
                {"email": user.email, "email_verified": user.email_verified}
            )

        return response_data
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/callback")
async def oauth_callback(
    request: Request,
    error: str = None,
    code: str = None,
    state: str = None,
):
    if error == "access_denied":
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "アプリケーションの認可が拒否されました",
                "message": "サービスを利用するには認可を許可する必要があります",
            },
        )

    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is required")

    # クライアントアプリのコールバックURLを取得
    client_id = request.session.get("oauth_client_id")
    if not client_id or client_id not in settings.CLIENTS:
        raise HTTPException(status_code=400, detail="Invalid client")

    client_redirect_uri = settings.CLIENTS[client_id]["redirect_uri"]

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            f"{settings.AUTH_SERVER_URL}/oauth/token",
            data={
                "client_id": client_id,
                "client_secret": settings.CLIENTS[client_id]["client_secret"],
                "code": code,
                "redirect_uri": client_redirect_uri,
                "grant_type": "authorization_code",
            },
        )

        if token_response.status_code != 200:
            # エラーの場合はクライアントアプリにエラーを返す
            return RedirectResponse(
                f"{client_redirect_uri}?error=invalid_grant&state={state}",
                status_code=303,
            )

        # 成功した場合はクライアントアプリにコードを返す
        return RedirectResponse(
            f"{client_redirect_uri}?code={code}&state={state}", status_code=303
        )
