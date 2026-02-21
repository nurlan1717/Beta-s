"""Authentication security utilities for RansomRun."""

import secrets
import re
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
from jose import JWTError, jwt

# Use bcrypt directly instead of passlib to avoid initialization issues
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings for session tokens
SECRET_KEY = secrets.token_urlsafe(32)  # In production, load from env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    # Convert password to bytes and hash
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Requirements:
    - Minimum 10 characters
    - At least 1 digit
    - At least 1 special symbol
    
    Returns:
        (is_valid, error_message)
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]', password):
        return False, "Password must contain at least one special symbol"
    
    return True, ""


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(token: str, session_token: str) -> bool:
    """Verify CSRF token matches session token."""
    return secrets.compare_digest(token, session_token)


# Simple in-memory rate limiting for login attempts
login_attempts = {}  # {ip: [(timestamp, success), ...]}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


def check_rate_limit(ip: str) -> tuple[bool, Optional[str]]:
    """
    Check if IP is rate limited for login attempts.
    
    Returns:
        (is_allowed, error_message)
    """
    now = datetime.utcnow()
    
    if ip not in login_attempts:
        login_attempts[ip] = []
    
    # Clean old attempts
    login_attempts[ip] = [
        (ts, success) for ts, success in login_attempts[ip]
        if now - ts < LOCKOUT_DURATION
    ]
    
    # Count recent failed attempts
    recent_failures = [
        ts for ts, success in login_attempts[ip]
        if not success and now - ts < LOCKOUT_DURATION
    ]
    
    if len(recent_failures) >= MAX_LOGIN_ATTEMPTS:
        return False, f"Too many failed login attempts. Please try again in {LOCKOUT_DURATION.seconds // 60} minutes."
    
    return True, None


def record_login_attempt(ip: str, success: bool):
    """Record a login attempt for rate limiting."""
    now = datetime.utcnow()
    
    if ip not in login_attempts:
        login_attempts[ip] = []
    
    login_attempts[ip].append((now, success))
    
    # Keep only recent attempts
    login_attempts[ip] = [
        (ts, s) for ts, s in login_attempts[ip]
        if now - ts < LOCKOUT_DURATION
    ]
