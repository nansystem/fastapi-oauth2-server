from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.core.security import verify_password, get_password_hash

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": request.session.get("user")
        }
    )

@router.get("/login")
async def login_page(request: Request, next: str = None):
    return templates.TemplateResponse(
        "login.html", 
        {"request": request, "next": next}
    )

@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(None),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "next": next,
                "error": "ユーザー名またはパスワードが正しくありません"
            },
            status_code=401
        )
    
    request.session["user"] = {
        "id": user.id,
        "username": user.username
    }
    
    return RedirectResponse(next or "/", status_code=303)

@router.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request}
    )

@router.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "このユーザー名は既に使用されています"
            },
            status_code=400
        )
    
    user = User(
        username=username,
        password=get_password_hash(password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    request.session["user"] = {
        "id": user.id,
        "username": user.username
    }
    
    next_url = request.query_params.get("next", "/")
    return RedirectResponse(next_url, status_code=303)

@router.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse("/", status_code=303) 