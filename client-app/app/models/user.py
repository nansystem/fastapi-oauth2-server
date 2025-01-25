from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String, nullable=True)  # FIXME nullable
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # OAuthアカウントとの関連
    oauth_accounts = relationship("OAuthAccount", back_populates="user")


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    provider = Column(String)  # "auth_server" など
    sub = Column(String, index=True)  # 認可サーバーのsub
    provider_username = Column(String)  # 認可サーバーのpreferred_username
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # ユーザーとの関連
    user = relationship("User", back_populates="oauth_accounts")

    # プロバイダーとsubの組み合わせでユニーク制約
    __table_args__ = (
        UniqueConstraint("provider", "sub", name="uq_oauth_account_provider_sub"),
    )
