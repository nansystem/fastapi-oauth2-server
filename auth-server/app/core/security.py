from passlib.context import CryptContext
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf_token(csrf_token: str, stored_token: str) -> bool:
    return stored_token == csrf_token
