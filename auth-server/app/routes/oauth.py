from fastapi import APIRouter, Request, HTTPException, Depends, Form, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.services.oauth_service import OAuthService
from app.core.config import settings
from app.database import get_db
from app.models.user import User
from urllib.parse import urlencode
from app.core.templates import templates

router = APIRouter(prefix="/oauth")


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

    if response_type != "code":
        return RedirectResponse(
            f"{redirect_uri}?error=unsupported_response_type&state={state}",
            status_code=303,
        )

    if client_id not in settings.CLIENTS:
        return RedirectResponse(
            f"{redirect_uri}?error=unauthorized_client&state={state}", status_code=303
        )

    if redirect_uri != settings.CLIENTS[client_id]["redirect_uri"]:
        return RedirectResponse(
            f"{redirect_uri}?error=invalid_redirect_uri&state={state}", status_code=303
        )

    requested_scopes = set(scope.split())

    # 1. 要求されたスコープが有効なスコープか確認
    invalid_scopes = requested_scopes - settings.AVAILABLE_SCOPES
    if invalid_scopes:
        return RedirectResponse(
            f"{redirect_uri}?error=invalid_scope&error_description=Unsupported+scopes:{'+'.join(invalid_scopes)}&state={state}",
            status_code=303,
        )

    # 2. クライアントに許可されたスコープか確認
    client_allowed_scopes = set(settings.CLIENTS[client_id]["allowed_scopes"])
    unauthorized_scopes = requested_scopes - client_allowed_scopes
    if unauthorized_scopes:
        return RedirectResponse(
            f"{redirect_uri}?error=insufficient_scope&error_description=Client+not+authorized+for+scopes:{'+'.join(unauthorized_scopes)}&state={state}",
            status_code=303,
        )

    # 同意画面の表示
    return templates.TemplateResponse(
        "consent.html",
        {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "state": state,
            "requested_scopes": requested_scopes,
        },
    )


@router.post("/authorize")
async def authorize_action(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    action: str = Form(...),
    state: str = Form(None),
):
    if action != "allow":
        # ユーザーが拒否した場合
        params = {"error": "access_denied"}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)

    # 認可コード生成
    code = OAuthService.generate_authorization_code(
        client_id=client_id,
        user_id=request.session["user"]["id"],
        redirect_uri=redirect_uri,
    )

    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")


@router.post("/token")
async def token_endpoint(
    request: Request,
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
):
    # クライアント認証
    if (
        client_id not in settings.CLIENTS
        or settings.CLIENTS[client_id]["secret"] != client_secret
    ):
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    try:
        token = OAuthService.exchange_code_for_token(
            code=code, client_id=client_id, redirect_uri=redirect_uri
        )
        return {"access_token": token, "token_type": "bearer", "expires_in": 3600}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/userinfo")
async def userinfo_endpoint(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    token = auth_header.split(" ")[1]
    try:
        token_data = OAuthService.validate_token(token)
        user = db.query(User).filter(User.id == token_data["user_id"]).first()
        return {"user_id": user.id, "username": user.username}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
