# fastapi-oauth2-server

## ディレクトリ構成
```
├── auth-server/          # 認証認可サーバー
├── client-app/ 　　　　   # クライアントサーバー
```

``` sh
# 認証サーバーの起動
cd auth-server
poetry run uvicorn app.main:app --port 8000

# クライアントサーバーの起動
cd ../client-app
poetry run uvicorn app.main:app --port 8001
```

## 認証サーバー

テストデータ作成
``` sh
cd auth-server && poetry run python -m app.scripts.init_db
```
