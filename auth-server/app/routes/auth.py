from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.core.security import get_password_hash, verify_password
from app.core.templates import templates

# 通常の認証用ルーター
router = APIRouter(tags=["認証"])


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "user": request.session.get("user")}
    )


# 通常のログイン/登録関連
@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "ユーザー名またはパスワードが正しくありません",
            },
            status_code=400,
        )

    request.session["user"] = {"id": user.id, "username": user.username}

    next_url = request.query_params.get("next", "/")
    return RedirectResponse(next_url, status_code=303)


@router.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "このユーザー名は既に使用されています"},
            status_code=400,
        )

    user = User(username=username, password=get_password_hash(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    request.session["user"] = {"id": user.id, "username": user.username}

    next_url = request.query_params.get("next", "/")
    return RedirectResponse(next_url, status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse("/")
