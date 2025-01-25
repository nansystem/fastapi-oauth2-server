import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.main import app
from fastapi.testclient import TestClient

# テスト用のデータベースURL
TEST_DATABASE_URL = "sqlite:///./test.db"


@pytest.fixture
def test_db():
    # テスト用DBの作成
    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()
        # テスト後にテーブルを削除
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)
