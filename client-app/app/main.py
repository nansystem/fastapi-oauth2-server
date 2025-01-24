from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app import models, security
from app.database import get_db, engine
from contextlib import asynccontextmanager
from app.security import get_password_hash
from starlette.middleware.sessions import SessionMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # テーブル作成
    models.Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(lifespan=lifespan)

# セッションミドルウェアの追加
app.add_middleware(
    SessionMiddleware, secret_key="your-secret-key-here", session_cookie="session"
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
async def show_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def show_dashboard(request: Request):
    if "user" not in request.session:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.post("/login")
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

    # セッションにユーザー情報を保存
    request.session["user"] = username
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# 登録ページ表示
@app.get("/register", response_class=HTMLResponse)
async def show_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# 登録処理
@app.post("/register")
async def handle_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    # 既存ユーザーチェック
    existing_user = (
        db.query(models.User).filter(models.User.username == username).first()
    )
    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "このユーザー名は既に使用されています"},
        )

    # パスワードハッシュ化
    hashed_password = get_password_hash(password)

    # 新規ユーザー作成
    new_user = models.User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()

    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    # セッションデータを完全に削除
    request.session.clear()
    # ログインページへリダイレクト
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/session-check")
async def session_check(request: Request):
    return {"session": dict(request.session)}
