from fastapi import APIRouter, Request
from app.core.templates import templates

router = APIRouter(tags=["ユーザー管理"])


@router.get("/")
async def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})
