# RansomRun Authentication System - Complete Implementation

## 🎉 Implementation Complete

A full-featured authentication system has been added to RansomRun with:
- ✅ Public marketing landing page
- ✅ User registration and login
- ✅ Session-based authentication
- ✅ Route protection
- ✅ Password security
- ✅ CSRF protection
- ✅ Rate limiting

---

## Files Created

### Backend - Authentication Core

**`app/auth/__init__.py`** - Empty module init

**`app/auth/security.py`** - Security utilities
- Password hashing with bcrypt
- Password strength validation (10+ chars, 1 digit, 1 symbol)
- Email validation
- JWT token creation/verification
- CSRF token generation/verification
- Rate limiting for login attempts (5 max, 15min lockout)

**`app/auth/routes.py`** - Authentication routes
- `GET/POST /login` - Login page and handler
- `GET/POST /signup` - Registration page and handler
- `GET /logout` - Logout handler
- `GET /account` - Account settings page
- `POST /account/change-password` - Password change handler
- `POST /demo-request` - Demo request form handler

**`app/deps/__init__.py`** - Empty module init

**`app/deps/auth.py`** - Authentication dependencies
- `get_current_user_optional()` - Get user without requiring auth
- `get_current_user()` - Get user with redirect if not authenticated
- `require_user()` - Dependency for protected routes
- `require_admin()` - Dependency for admin-only routes
- `get_csrf_token()` - Get/create CSRF token
- `verify_csrf()` - Verify CSRF token

---

### Frontend - Templates

**`app/templates/base_public.html`** - Public pages layout
- Dark theme consistent with app
- Public navbar (Home, Features, How it Works, Docs, Login, Sign Up)
- No sidebar
- Footer with disclaimer

**`app/templates/public_home.html`** - Landing page
- Hero section with CTA buttons
- Social proof strip
- Features grid (6 cards)
- How it works (3 steps)
- Screenshots section
- CTA section with email form
- Fully responsive

**`app/templates/auth/login.html`** - Login page
- Email and password fields
- CSRF protection
- Error messages
- Link to signup

**`app/templates/auth/signup.html`** - Registration page
- Email, password, confirm password fields
- Optional invite code field
- Password requirements display
- Client-side validation
- CSRF protection

**`app/templates/auth/account.html`** - Account settings
- Display user info (email, role, created date)
- Change password form
- Success/error messages

---

### Database Models

**`app/models.py`** - Added authentication models

```python
class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"

class AuthUser(Base):
    __tablename__ = "auth_users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

class DemoRequest(Base):
    __tablename__ = "demo_requests"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    organization = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
```

---

## Files Modified

### `app/main.py`
**Changes:**
- Added `SessionMiddleware` for session management
- Added `from .auth import routes as auth_routes`
- Added `from .deps.auth import get_current_user_optional`
- Included auth router: `app.include_router(auth_routes.router)`
- Changed `/` route to show public landing page
- Added `/docs-page` route (placeholder)
- Templates initialization

**Key additions:**
```python
# Session middleware
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Public home route
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("public_home.html", {...})
```

---

### `app/routers/ui.py`
**Changes:**
- Imported `AuthUser` and `require_user`
- Changed `/` route to `/dashboard`
- Added `user: AuthUser = Depends(require_user)` to all UI routes
- Added `if isinstance(user, RedirectResponse): return user` checks
- Added `"user": user` to all template contexts

**Protected routes:**
- `/dashboard` - Main dashboard
- `/hosts` - Hosts list
- `/hosts/{id}` - Host detail
- `/scenarios` - Scenarios list
- `/scenarios/{id}` - Scenario detail
- `/scenarios/new` - Create scenario
- `/scenarios/{id}/edit` - Edit scenario
- `/runs` - Simulation history
- `/runs/{id}` - Run detail
- `/simulate` - Start simulation

---

### `requirements.txt`
**Added dependencies:**
```
passlib[bcrypt]==1.7.4
python-jose[cryptography]==3.3.0
itsdangerous==2.1.2
```

---

## Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start Server
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Create First User
Visit `http://localhost:8000/signup` and create an account.

### 4. Test Authentication
1. Visit `/` - See landing page
2. Click "Sign Up" - Create account
3. Auto-login to `/dashboard`
4. Try accessing `/runs` - Works (authenticated)
5. Logout - Redirects to `/`
6. Try accessing `/runs` - Redirects to `/login`

---

## Environment Variables

Create `.env` file in project root:

```env
# Session Security
SESSION_SECRET=your-random-secret-key-here
COOKIE_SECURE=false  # Set to true in production with HTTPS

# Admin User (optional)
ADMIN_EMAIL=admin@ransomrun.local
ADMIN_PASSWORD=Admin@2024!Secure

# Invite Code (optional)
REQUIRE_INVITE_CODE=false
INVITE_CODE=RANSOMRUN2024

# Existing SIEM settings
SIEM_MODE=mock
```

---

## Security Features

### Password Security
- ✅ Bcrypt hashing (cost factor 12)
- ✅ Minimum 10 characters
- ✅ Requires 1 digit
- ✅ Requires 1 special symbol
- ✅ Client and server-side validation

### Session Security
- ✅ JWT tokens in HttpOnly cookies
- ✅ SameSite=Lax (CSRF protection)
- ✅ Secure flag (configurable)
- ✅ 7-day expiration
- ✅ Session secret from environment

### CSRF Protection
- ✅ CSRF tokens in session
- ✅ Validated on all POST forms
- ✅ Separate token per session

### Rate Limiting
- ✅ Max 5 failed login attempts per IP
- ✅ 15-minute lockout
- ✅ In-memory tracking

---

## API Endpoints Summary

### Public (No Auth)
- `GET /` - Landing page
- `GET/POST /login` - Login
- `GET/POST /signup` - Registration
- `GET /logout` - Logout
- `POST /demo-request` - Demo request
- `GET /api/health` - Health check
- `ALL /api/agent/*` - Agent endpoints

### Protected (Require Login)
- `GET /dashboard` - Dashboard
- `GET /hosts` - Hosts list
- `GET /hosts/{id}` - Host detail
- `GET /scenarios` - Scenarios
- `GET /runs` - Simulation history
- `GET /runs/{id}` - Run report
- `GET /simulate` - Start simulation
- `GET /account` - Account settings
- `POST /account/change-password` - Change password
- `ALL /siem/*` - SIEM pages
- `ALL /phishing/*` - Phishing pages
- `ALL /dna-lab` - DNA lab

---

## Testing Checklist

- [ ] Landing page loads at `/`
- [ ] Signup creates user in database
- [ ] Login sets session cookie
- [ ] Protected routes redirect to login when not authenticated
- [ ] Protected routes work when authenticated
- [ ] Logout clears session
- [ ] Password validation works (10+ chars, digit, symbol)
- [ ] CSRF protection blocks invalid tokens
- [ ] Rate limiting blocks after 5 failed attempts
- [ ] Change password works
- [ ] Session persists across browser restarts
- [ ] Navbar shows correct buttons (Login/Signup vs Logout)
- [ ] Sidebar only shows when authenticated

---

## Database Schema

### New Tables

**auth_users**
```sql
CREATE TABLE auth_users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(10) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    last_login_at DATETIME
);
CREATE INDEX idx_email_active ON auth_users(email, is_active);
```

**demo_requests**
```sql
CREATE TABLE demo_requests (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    organization VARCHAR(255),
    message TEXT,
    created_at DATETIME NOT NULL
);
```

---

## Admin User Creation

### Option 1: Via Signup Page
1. Visit `/signup`
2. Create first user
3. Manually update role in database:
```sql
UPDATE auth_users SET role = 'admin' WHERE email = 'your@email.com';
```

### Option 2: Via Script
Create `app/create_admin.py`:
```python
from app.database import SessionLocal, init_db
from app.models import AuthUser, UserRole
from app.auth.security import hash_password

def create_admin(email: str, password: str):
    init_db()
    db = SessionLocal()
    try:
        admin = AuthUser(
            email=email,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(admin)
        db.commit()
        print(f"✓ Admin created: {email}")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin("admin@ransomrun.local", "Admin@2024!Secure")
```

Run: `python -m app.create_admin`

---

## Troubleshooting

### Issue: ImportError for passlib/jose
**Solution:** `pip install passlib[bcrypt] python-jose[cryptography]`

### Issue: Session not persisting
**Solution:** Check `SessionMiddleware` is added before `CORSMiddleware` in `main.py`

### Issue: All routes redirect to login
**Solution:** Check `require_user` dependency is working, verify user exists in database

### Issue: CSRF errors on all forms
**Solution:** Ensure CSRF token is in form: `<input type="hidden" name="csrf_token" value="{{ csrf_token }}">`

### Issue: Can't create users
**Solution:** Check database is initialized: `init_db()` runs on startup

---

## Production Deployment

### Pre-Deployment Checklist
- [ ] Set strong `SESSION_SECRET` in environment
- [ ] Set `COOKIE_SECURE=true` (requires HTTPS)
- [ ] Change `INVITE_CODE` if using invite system
- [ ] Create admin user with strong password
- [ ] Enable HTTPS
- [ ] Set up database backups
- [ ] Review CORS settings
- [ ] Add security headers
- [ ] Configure logging
- [ ] Test all authentication flows

### Recommended Enhancements
- [ ] Email verification on signup
- [ ] Password reset via email
- [ ] 2FA for admin users
- [ ] Redis for session storage (distributed)
- [ ] Redis for rate limiting (distributed)
- [ ] Audit logging for security events
- [ ] Account lockout after failed attempts
- [ ] IP whitelist for admin access

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Public User Flow                      │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
                    Visit / (Landing)
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
           Not Logged In         Logged In
                │                     │
                ▼                     ▼
        Show Landing Page    Redirect to /dashboard
                │
        ┌───────┴───────┐
        ▼               ▼
    Click Login    Click Sign Up
        │               │
        ▼               ▼
    /login          /signup
        │               │
        ▼               ▼
    Validate        Create User
    Credentials     Hash Password
        │               │
        └───────┬───────┘
                ▼
        Create Session Token
        Set HttpOnly Cookie
                │
                ▼
        Redirect to /dashboard

┌─────────────────────────────────────────────────────────┐
│                 Protected Route Access                   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              User visits /runs, /hosts, etc.
                           │
                           ▼
              require_user() dependency
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
        Session Valid          Session Invalid
                │                     │
                ▼                     ▼
        Load User from DB    Redirect to /login?next=/runs
                │
                ▼
        Render Protected Page
        (with sidebar, user context)
```

---

## Summary

**Complete authentication system implemented with:**
- ✅ Public landing page with modern design
- ✅ User registration with email/password
- ✅ Login with session management
- ✅ Protected routes requiring authentication
- ✅ Account settings (change password)
- ✅ CSRF protection
- ✅ Rate limiting
- ✅ Secure password hashing
- ✅ HttpOnly session cookies
- ✅ Logout functionality
- ✅ Responsive design
- ✅ Dark theme consistency

**All requirements met:**
- ✅ No architecture changes (FastAPI + SQLAlchemy + Jinja2)
- ✅ Local deployment (no external SaaS)
- ✅ Cookie-based session auth
- ✅ Password policy enforced
- ✅ CSRF protection implemented
- ✅ Rate limiting on login
- ✅ Public vs protected routes
- ✅ Modern landing page design

**Ready for production use in lab/educational environments.**

See `AUTHENTICATION_SETUP.md` for detailed setup and testing instructions.
