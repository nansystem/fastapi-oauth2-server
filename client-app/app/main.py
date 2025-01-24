# app/main.py
from fastapi import FastAPI

app = FastAPI()  # ← この変数名が一致しているか確認

@app.get("/")
async def root():
    return {"message": "Hello World"}