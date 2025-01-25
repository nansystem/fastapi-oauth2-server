from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates


router = APIRouter(tags=["ユーザー管理"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/")
async def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})
