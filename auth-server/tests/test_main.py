from fastapi.testclient import TestClient
from app.main import app
from app.core.security import get_password_hash, verify_password

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200


def test_password_hash_round_trips():
    password = "correct horse battery staple"
    password_hash = get_password_hash(password)

    assert password_hash != password
    assert verify_password(password, password_hash)
    assert not verify_password("wrong password", password_hash)
