from fastapi import APIRouter, Request
from app.core.templates import templates

router = APIRouter(tags=["ユーザー管理"])


@router.get("/")
async def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request, "user": user},
    )
