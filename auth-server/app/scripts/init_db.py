from app.database import Base, engine
from app.models.user import User
from app.scripts.create_test_users import create_test_users

def init_db():
    print("データベース初期化開始")
    Base.metadata.create_all(bind=engine)
    print("テーブル作成完了")
    
    create_test_users()
    print("データベース初期化完了")

if __name__ == "__main__":
    init_db()