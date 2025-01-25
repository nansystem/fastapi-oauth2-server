from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
import uuid
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    sub = Column(
        String, unique=True, index=True, default=lambda: str(uuid.uuid4())
    )  # OIDC Subject Identifier
    username = Column(String, unique=True, index=True)
    password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.sub:
            self.sub = str(uuid.uuid4())
