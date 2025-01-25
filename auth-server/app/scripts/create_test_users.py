from app.database import get_db
from app.models.user import User
from app.core.security import get_password_hash
import uuid


def create_test_users():
    print("テストユーザー作成開始")
    db = next(get_db())

    # テストユーザーの作成
    test_users = [
        {
            "username": "test1",
            "password": get_password_hash("test1"),
            "email": "test1@example.com",
            "email_verified": True,
            "sub": str(uuid.uuid4()),
        },
        {
            "username": "test2",
            "password": get_password_hash("test2"),
            "email": "test2@example.com",
            "email_verified": False,
            "sub": str(uuid.uuid4()),
        },
    ]

    for user_data in test_users:
        # 既存のユーザーをスキップ
        if not db.query(User).filter(User.username == user_data["username"]).first():
            user = User(**user_data)
            db.add(user)

    db.commit()


if __name__ == "__main__":
    create_test_users()
