from datetime import datetime, timedelta
import secrets
from typing import Dict


class OAuthService:
    _auth_codes: Dict[str, dict] = {}  # 認可コードの一時保存
    _tokens: Dict[str, dict] = {}  # アクセストークンの保存

    @classmethod
    def generate_authorization_code(
        cls, client_id: str, user_id: str, redirect_uri: str, scope: str
    ) -> str:
        code = secrets.token_urlsafe(32)
        cls._auth_codes[code] = {
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "expires_at": datetime.now() + timedelta(minutes=10),
        }
        return code

    @classmethod
    def exchange_code_for_token(
        cls, code: str, client_id: str, redirect_uri: str
    ) -> str:
        # 認可コードの検証
        code_data = cls._auth_codes.get(code)
        if not code_data:
            raise ValueError("Invalid authorization code")
        if code_data["client_id"] != client_id:
            raise ValueError("Client ID mismatch")
        if code_data["redirect_uri"] != redirect_uri:
            raise ValueError("Redirect URI mismatch")
        if datetime.now() > code_data["expires_at"]:
            raise ValueError("Authorization code expired")

        # アクセストークン生成
        token = secrets.token_urlsafe(32)
        cls._tokens[token] = {
            "client_id": client_id,
            "user_id": code_data["user_id"],
            "scope": code_data["scope"],
            "expires_at": datetime.now() + timedelta(hours=1),
        }

        # 使用済みの認可コードを削除
        del cls._auth_codes[code]
        return token

    @classmethod
    def validate_token(cls, token: str, required_scope: str = None) -> dict:
        token_data = cls._tokens.get(token)
        if not token_data:
            raise ValueError("Invalid token")
        if datetime.now() > token_data["expires_at"]:
            raise ValueError("Token expired")

        # スコープの検証
        if required_scope:
            token_scopes = set(token_data["scope"].split())
            if required_scope not in token_scopes:
                raise ValueError(
                    f"Token does not have required scope: {required_scope}"
                )

        return {
            "client_id": token_data["client_id"],
            "user_id": token_data["user_id"],
            "scope": token_data["scope"],
        }
