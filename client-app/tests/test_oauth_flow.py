from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.routes import auth


class TokenClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def post(self, url, data):
        return httpx.Response(
            200, json={"access_token": "test-access-token", "token_type": "Bearer"}
        )

    async def get(self, url, headers):
        return httpx.Response(
            200,
            json={"sub": "test-sub", "preferred_username": "sample-user"},
        )


def test_oauth_callback_rejects_a_mismatched_state():
    with TestClient(app, base_url="https://testserver", follow_redirects=False) as client:
        response = client.get(
            "/auth/callback", params={"code": "test-code", "state": "wrong-state"}
        )

    assert response.status_code == 200
    assert "CSRF検証に失敗しました" in response.text


def test_oauth_callback_accepts_state_and_uses_the_authorization_code(monkeypatch):
    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kwargs: TokenClient())

    with TestClient(app, base_url="https://testserver", follow_redirects=False) as client:
        authorize = client.get("/auth/oauth")
        state = parse_qs(urlparse(authorize.headers["location"]).query)["state"][0]
        response = client.get(
            "/auth/callback", params={"code": "test-code", "state": state}
        )

    assert response.status_code == 200
    assert "sample-user" in response.text
