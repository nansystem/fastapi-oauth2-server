from app.database import Base, engine


def init_db():
    # 全てのテーブルを作り直し
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("データベースを初期化しました")


if __name__ == "__main__":
    init_db()
