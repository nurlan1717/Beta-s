"""Authentication dependencies for route protection."""

from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuthUser
from ..auth.security import decode_access_token


def get_current_user_optional(request: Request) -> Optional[AuthUser]:
    """
    Get current user from session cookie (optional - returns None if not logged in).
    Does not raise exceptions.
    """
    token = request.cookies.get("session_token")
    if not token:
        return None
    
    payload = decode_access_token(token)
    if not payload:
        return None
    
    user_id = payload.get("sub")
    if not user_id:
        return None
    
    # Get DB session
    db = next(get_db())
    try:
        user = db.query(AuthUser).filter(
            AuthUser.id == int(user_id),
            AuthUser.is_active == True
        ).first()
        return user
    finally:
        db.close()


def get_current_user(request: Request) -> AuthUser:
    """
    Get current user from session cookie (required - raises exception if not logged in).
    
    For HTML pages: Redirects to /login
    For API calls: Returns 401 JSON
    """
    user = get_current_user_optional(request)
    
    if not user:
        # Check if this is an API call (AJAX/fetch)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or \
           request.headers.get("Accept", "").startswith("application/json"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated"
            )
        
        # For HTML pages, redirect to login
        return RedirectResponse(
            url=f"/login?next={request.url.path}",
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    return user


def require_user(request: Request) -> AuthUser:
    """
    Dependency to require authenticated user.
    Use in route dependencies: Depends(require_user)
    """
    result = get_current_user(request)
    
    # If it's a redirect response, raise it
    if isinstance(result, RedirectResponse):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Authentication required",
            headers={"Location": result.headers["location"]}
        )
    
    return result


def require_admin(request: Request) -> AuthUser:
    """
    Dependency to require admin user.
    Use in route dependencies: Depends(require_admin)
    """
    user = require_user(request)
    
    if isinstance(user, RedirectResponse):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Authentication required",
            headers={"Location": user.headers["location"]}
        )
    
    from ..models import UserRole
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return user


def get_csrf_token(request: Request) -> str:
    """Get or create CSRF token for the session."""
    from ..auth.security import generate_csrf_token
    
    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = generate_csrf_token()
        request.session["csrf_token"] = csrf_token
    
    return csrf_token


def verify_csrf(request: Request, form_token: str) -> bool:
    """Verify CSRF token from form matches session token."""
    from ..auth.security import verify_csrf_token
    
    session_token = request.session.get("csrf_token")
    if not session_token:
        return False
    
    return verify_csrf_token(form_token, session_token)
