from app.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

def create_test_users():
    print("テストユーザー作成開始")
    db = SessionLocal()
    try:
        # テストユーザーのリスト
        test_users = [
            {"username": "test1", "password": "test1"},
            {"username": "test2", "password": "test2"},
            {"username": "test3", "password": "test3"},
        ]
        
        for user_data in test_users:
            # ユーザーが存在しない場合のみ作成
            if not db.query(User).filter(User.username == user_data["username"]).first():
                user = User(
                    username=user_data["username"],
                    password=get_password_hash(user_data["password"])
                )
                db.add(user)
                print(f"Created test user: {user_data['username']}")
        
        db.commit()
        print("テストユーザー作成完了")
        
    finally:
        db.close()

if __name__ == "__main__":
    create_test_users() 
    