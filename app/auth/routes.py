"""Authentication routes for login, signup, logout, and account management."""

import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuthUser, UserRole, DemoRequest
from ..deps.auth import get_current_user_optional, require_user, get_csrf_token
from .security import (
    hash_password, verify_password, validate_password_strength,
    validate_email, create_access_token, check_rate_limit, record_login_attempt
)

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory="app/templates")

# Environment variables for invite code (optional feature)
REQUIRE_INVITE_CODE = os.getenv("REQUIRE_INVITE_CODE", "false").lower() == "true"
VALID_INVITE_CODE = os.getenv("INVITE_CODE", "RANSOMRUN2024")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = None):
    """Display login page."""
    # If already logged in, redirect to dashboard
    user = get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    csrf_token = get_csrf_token(request)
    
    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "csrf_token": csrf_token,
        "next": next or "/dashboard",
        "error": None
    })


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    next: str = Form(default="/dashboard"),
    db: Session = Depends(get_db)
):
    """Process login form."""
    # Verify CSRF token
    session_csrf = request.session.get("csrf_token")
    if not session_csrf or csrf_token != session_csrf:
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "next": next,
            "error": "Invalid security token. Please try again."
        }, status_code=400)
    
    # Check rate limiting
    client_ip = request.client.host
    allowed, error_msg = check_rate_limit(client_ip)
    if not allowed:
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "next": next,
            "error": error_msg
        }, status_code=429)
    
    # Find user by email
    user = db.query(AuthUser).filter(AuthUser.email == email.lower()).first()
    
    # Verify password
    if not user or not verify_password(password, user.password_hash):
        record_login_attempt(client_ip, False)
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "next": next,
            "error": "Invalid email or password"
        }, status_code=401)
    
    # Check if user is active
    if not user.is_active:
        record_login_attempt(client_ip, False)
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "next": next,
            "error": "Account is disabled. Please contact administrator."
        }, status_code=403)
    
    # Successful login
    record_login_attempt(client_ip, True)
    
    # Update last login
    user.last_login_at = datetime.utcnow()
    db.commit()
    
    # Create session token
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )
    
    # Redirect to next page
    response = RedirectResponse(url=next, status_code=303)
    
    # Set secure cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",  # Set to true in production with HTTPS
        max_age=60 * 60 * 24 * 7  # 7 days
    )
    
    return response


@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    """Display signup page."""
    # If already logged in, redirect to dashboard
    user = get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    csrf_token = get_csrf_token(request)
    
    return templates.TemplateResponse("auth/signup.html", {
        "request": request,
        "csrf_token": csrf_token,
        "require_invite": REQUIRE_INVITE_CODE,
        "error": None
    })


@router.post("/signup")
async def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    invite_code: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Process signup form."""
    # Verify CSRF token
    session_csrf = request.session.get("csrf_token")
    if not session_csrf or csrf_token != session_csrf:
        return templates.TemplateResponse("auth/signup.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "require_invite": REQUIRE_INVITE_CODE,
            "error": "Invalid security token. Please try again."
        }, status_code=400)
    
    # Validate invite code if required
    if REQUIRE_INVITE_CODE:
        if not invite_code or invite_code != VALID_INVITE_CODE:
            return templates.TemplateResponse("auth/signup.html", {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "require_invite": REQUIRE_INVITE_CODE,
                "error": "Invalid invite code"
            }, status_code=400)
    
    # Validate email format
    if not validate_email(email):
        return templates.TemplateResponse("auth/signup.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "require_invite": REQUIRE_INVITE_CODE,
            "error": "Invalid email format"
        }, status_code=400)
    
    # Check if email already exists
    existing_user = db.query(AuthUser).filter(AuthUser.email == email.lower()).first()
    if existing_user:
        return templates.TemplateResponse("auth/signup.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "require_invite": REQUIRE_INVITE_CODE,
            "error": "Email already registered"
        }, status_code=400)
    
    # Validate passwords match
    if password != confirm_password:
        return templates.TemplateResponse("auth/signup.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "require_invite": REQUIRE_INVITE_CODE,
            "error": "Passwords do not match"
        }, status_code=400)
    
    # Validate password strength
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        return templates.TemplateResponse("auth/signup.html", {
            "request": request,
            "csrf_token": get_csrf_token(request),
            "require_invite": REQUIRE_INVITE_CODE,
            "error": error_msg
        }, status_code=400)
    
    # Create new user
    password_hash = hash_password(password)
    
    new_user = AuthUser(
        email=email.lower(),
        password_hash=password_hash,
        role=UserRole.USER,
        is_active=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Auto-login after signup
    access_token = create_access_token(
        data={"sub": str(new_user.id), "email": new_user.email, "role": new_user.role.value}
    )
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        max_age=60 * 60 * 24 * 7
    )
    
    return response


@router.get("/logout")
async def logout(request: Request):
    """Logout user and clear session."""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session_token")
    return response


@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request, user: AuthUser = Depends(require_user)):
    """Display account settings page."""
    if isinstance(user, RedirectResponse):
        return user
    
    csrf_token = get_csrf_token(request)
    
    return templates.TemplateResponse("auth/account.html", {
        "request": request,
        "user": user,
        "csrf_token": csrf_token,
        "success": None,
        "error": None
    })


@router.post("/account/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    user: AuthUser = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Change user password."""
    if isinstance(user, RedirectResponse):
        return user
    
    # Verify CSRF token
    session_csrf = request.session.get("csrf_token")
    if not session_csrf or csrf_token != session_csrf:
        return templates.TemplateResponse("auth/account.html", {
            "request": request,
            "user": user,
            "csrf_token": get_csrf_token(request),
            "success": None,
            "error": "Invalid security token"
        }, status_code=400)
    
    # Verify current password
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse("auth/account.html", {
            "request": request,
            "user": user,
            "csrf_token": get_csrf_token(request),
            "success": None,
            "error": "Current password is incorrect"
        }, status_code=400)
    
    # Validate new passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse("auth/account.html", {
            "request": request,
            "user": user,
            "csrf_token": get_csrf_token(request),
            "success": None,
            "error": "New passwords do not match"
        }, status_code=400)
    
    # Validate new password strength
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return templates.TemplateResponse("auth/account.html", {
            "request": request,
            "user": user,
            "csrf_token": get_csrf_token(request),
            "success": None,
            "error": error_msg
        }, status_code=400)
    
    # Update password
    user.password_hash = hash_password(new_password)
    db.commit()
    
    return templates.TemplateResponse("auth/account.html", {
        "request": request,
        "user": user,
        "csrf_token": get_csrf_token(request),
        "success": "Password changed successfully",
        "error": None
    })


@router.post("/demo-request")
async def submit_demo_request(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    organization: Optional[str] = Form(None),
    message: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Submit demo request from landing page."""
    # Validate email
    if not validate_email(email):
        return {"success": False, "error": "Invalid email format"}
    
    # Create demo request
    demo_request = DemoRequest(
        name=name,
        email=email,
        organization=organization,
        message=message
    )
    
    db.add(demo_request)
    db.commit()
    
    return {"success": True, "message": "Thank you! We'll be in touch soon."}
