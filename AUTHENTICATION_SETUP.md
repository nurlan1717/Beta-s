# RansomRun Authentication System - Setup & Testing Guide

## Overview
RansomRun now includes a complete authentication system with:
- Public marketing landing page
- User registration and login
- Session-based authentication with secure cookies
- Password security (bcrypt hashing, strength validation)
- CSRF protection
- Rate limiting on login attempts
- Protected routes requiring authentication

---

## Installation & Setup

### 1. Install Dependencies

```bash
cd "C:\Users\Student\OneDrive - Innovation and Digital Development Agency\Desktop\RansomRun"
pip install -r requirements.txt
```

**New dependencies added:**
- `passlib[bcrypt]` - Password hashing
- `python-jose[cryptography]` - JWT tokens for sessions
- `itsdangerous` - Secure session management

### 2. Initialize Database

The database will auto-initialize on first run, creating the new `auth_users` and `demo_requests` tables.

```bash
# Start the server (this will create tables)
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Create Admin User (Optional)

You can create an admin user via environment variables or manually through the signup page.

**Option A: Environment Variables**

Create a `.env` file in the project root:

```env
# Admin user (created on first startup if doesn't exist)
ADMIN_EMAIL=admin@ransomrun.local
ADMIN_PASSWORD=Admin@2024!Secure

# Session security
SESSION_SECRET=your-secret-key-here-change-in-production
COOKIE_SECURE=false  # Set to true in production with HTTPS

# Invite code (optional - require invite to sign up)
REQUIRE_INVITE_CODE=false
INVITE_CODE=RANSOMRUN2024
```

**Option B: Manual Signup**

1. Visit `http://localhost:8000/signup`
2. Create an account with email and password
3. First user becomes admin (you can modify this in code)

### 4. Database Seed Script (Add Admin User)

Create `app/create_admin.py`:

```python
"""Create admin user script."""
import sys
from sqlalchemy.orm import Session
from app.database import SessionLocal, init_db
from app.models import AuthUser, UserRole
from app.auth.security import hash_password

def create_admin(email: str, password: str):
    """Create admin user."""
    init_db()
    db = SessionLocal()
    
    try:
        # Check if user exists
        existing = db.query(AuthUser).filter(AuthUser.email == email).first()
        if existing:
            print(f"User {email} already exists!")
            return
        
        # Create admin user
        admin = AuthUser(
            email=email,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True
        )
        
        db.add(admin)
        db.commit()
        print(f"✓ Admin user created: {email}")
        
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m app.create_admin <email> <password>")
        sys.exit(1)
    
    email = sys.argv[1]
    password = sys.argv[2]
    
    create_admin(email, password)
```

**Run it:**

```bash
python -m app.create_admin admin@ransomrun.local "Admin@2024!Secure"
```

---

## Architecture Overview

### Authentication Flow

```
1. User visits / (landing page)
   ├─ Not logged in → Show public landing page
   └─ Logged in → Redirect to /dashboard

2. User clicks "Sign Up"
   ├─ /signup → Registration form
   ├─ Validates email, password strength
   ├─ Creates user in database (password hashed with bcrypt)
   ├─ Auto-login after signup
   └─ Redirect to /dashboard

3. User clicks "Login"
   ├─ /login → Login form
   ├─ Validates credentials
   ├─ Rate limiting (max 5 failed attempts per IP)
   ├─ Creates session token (JWT in HttpOnly cookie)
   └─ Redirect to /dashboard (or original requested page)

4. User accesses protected page (e.g., /runs)
   ├─ Middleware checks session cookie
   ├─ If valid → Load user, render page
   └─ If invalid → Redirect to /login?next=/runs

5. User clicks "Logout"
   ├─ /logout → Clear session cookie
   └─ Redirect to / (landing page)
```

### Security Features

**Password Security:**
- Minimum 10 characters
- Must contain at least 1 digit
- Must contain at least 1 special symbol
- Hashed with bcrypt (cost factor 12)

**Session Security:**
- JWT tokens stored in HttpOnly cookies (not accessible via JavaScript)
- SameSite=Lax (CSRF protection)
- Secure flag (configurable via env, true in production)
- 7-day expiration

**CSRF Protection:**
- CSRF tokens in session
- Validated on all POST forms
- Separate token per session

**Rate Limiting:**
- Max 5 failed login attempts per IP
- 15-minute lockout after threshold
- In-memory tracking (resets on server restart)

---

## File Structure

```
RansomRun/
├── app/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py          # Login, signup, logout, account routes
│   │   └── security.py        # Password hashing, JWT, CSRF, rate limiting
│   ├── deps/
│   │   ├── __init__.py
│   │   └── auth.py            # Authentication dependencies (require_user, etc.)
│   ├── templates/
│   │   ├── base_public.html   # Public pages layout (no sidebar)
│   │   ├── public_home.html   # Landing page
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   ├── signup.html
│   │   │   └── account.html
│   │   └── base.html          # App pages layout (with sidebar) - EXISTING
│   ├── models.py              # Added AuthUser, DemoRequest models
│   ├── main.py                # Added session middleware, auth routes
│   └── routers/
│       └── ui.py              # Updated with authentication protection
└── requirements.txt           # Added auth dependencies
```

---

## Testing Guide

### Test 1: Public Landing Page

**Steps:**
1. Start server: `python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`
2. Open browser: `http://localhost:8000/`

**Expected:**
- ✅ Public landing page loads
- ✅ Shows hero section, features, how it works
- ✅ Navbar has "Login" and "Sign Up" buttons
- ✅ No sidebar visible
- ✅ Footer with disclaimer

---

### Test 2: User Registration

**Steps:**
1. Click "Sign Up" or visit `http://localhost:8000/signup`
2. Fill form:
   - Email: `test@example.com`
   - Password: `Test@12345!`
   - Confirm Password: `Test@12345!`
3. Click "Create Account"

**Expected:**
- ✅ Form validates password strength
- ✅ User created in database
- ✅ Auto-login after signup
- ✅ Redirect to `/dashboard`
- ✅ Sidebar now visible

**Test Password Validation:**
- Try password `short` → Error: "Must be at least 10 characters"
- Try password `nodigitshere!` → Error: "Must contain at least one digit"
- Try password `NoSymbols123` → Error: "Must contain at least one special symbol"

---

### Test 3: User Login

**Steps:**
1. Logout (visit `/logout`)
2. Visit `http://localhost:8000/login`
3. Enter credentials:
   - Email: `test@example.com`
   - Password: `Test@12345!`
4. Click "Sign In"

**Expected:**
- ✅ Login successful
- ✅ Redirect to `/dashboard`
- ✅ Session cookie set (check browser DevTools → Application → Cookies)

**Test Invalid Credentials:**
- Wrong password → Error: "Invalid email or password"
- Non-existent email → Error: "Invalid email or password"

---

### Test 4: Protected Routes

**Steps:**
1. Logout
2. Try to access protected pages directly:
   - `http://localhost:8000/dashboard`
   - `http://localhost:8000/runs`
   - `http://localhost:8000/hosts`
   - `http://localhost:8000/scenarios`
   - `http://localhost:8000/simulate`

**Expected:**
- ✅ All redirect to `/login?next=<original-path>`
- ✅ After login, redirect back to original page

---

### Test 5: Session Persistence

**Steps:**
1. Login
2. Close browser
3. Reopen browser
4. Visit `http://localhost:8000/dashboard`

**Expected:**
- ✅ Still logged in (session cookie persists)
- ✅ Dashboard loads without redirect

---

### Test 6: Logout

**Steps:**
1. Login
2. Click "Logout" or visit `/logout`

**Expected:**
- ✅ Session cookie cleared
- ✅ Redirect to `/` (landing page)
- ✅ Navbar shows "Login" and "Sign Up" again
- ✅ Trying to access `/dashboard` redirects to `/login`

---

### Test 7: Change Password

**Steps:**
1. Login
2. Visit `http://localhost:8000/account`
3. Fill form:
   - Current Password: `Test@12345!`
   - New Password: `NewPass@2024!`
   - Confirm New Password: `NewPass@2024!`
4. Click "Change Password"

**Expected:**
- ✅ Success message: "Password changed successfully"
- ✅ Can logout and login with new password

**Test Validation:**
- Wrong current password → Error: "Current password is incorrect"
- Passwords don't match → Error: "New passwords do not match"
- Weak new password → Error: "Password must be at least 10 characters..."

---

### Test 8: Rate Limiting

**Steps:**
1. Logout
2. Try to login with wrong password 6 times

**Expected:**
- ✅ First 5 attempts: "Invalid email or password"
- ✅ 6th attempt: "Too many failed login attempts. Please try again in 15 minutes."
- ✅ Lockout lasts 15 minutes
- ✅ Correct password also blocked during lockout

---

### Test 9: CSRF Protection

**Steps:**
1. Open browser DevTools → Console
2. Try to submit login form via JavaScript:

```javascript
fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'email=test@example.com&password=Test@12345!&csrf_token=invalid'
})
```

**Expected:**
- ✅ Error: "Invalid security token"
- ✅ Login fails without valid CSRF token

---

### Test 10: Demo Request Form

**Steps:**
1. Visit landing page
2. Scroll to CTA section
3. Enter email in form
4. Click "Get Started"

**Expected:**
- ✅ Demo request saved to database
- ✅ Redirect to `/signup`

---

## API Endpoints

### Public Endpoints (No Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Public landing page |
| `/login` | GET/POST | Login form and handler |
| `/signup` | GET/POST | Signup form and handler |
| `/logout` | GET | Logout (clears session) |
| `/demo-request` | POST | Submit demo request |
| `/api/health` | GET | Health check |
| `/api/agent/*` | ALL | Agent endpoints (agents don't use web auth) |

### Protected Endpoints (Require Login)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Main dashboard |
| `/hosts` | GET | Hosts list |
| `/hosts/{id}` | GET | Host detail |
| `/scenarios` | GET | Scenarios list |
| `/scenarios/{id}` | GET | Scenario detail |
| `/runs` | GET | Simulation history |
| `/runs/{id}` | GET | Run detail/report |
| `/simulate` | GET/POST | Start simulation |
| `/account` | GET | Account settings |
| `/account/change-password` | POST | Change password |
| `/alerts` | GET | Alerts page |
| `/playbooks` | GET | Playbooks page |
| `/siem/*` | ALL | SIEM pages |
| `/phishing/*` | ALL | Phishing lab pages |
| `/dna-lab` | GET | DNA lab page |

---

## Environment Variables

```env
# Session Security
SESSION_SECRET=<random-secret-key>  # Auto-generated if not set
COOKIE_SECURE=false                 # Set to true in production with HTTPS

# Admin User (optional - created on first startup)
ADMIN_EMAIL=admin@ransomrun.local
ADMIN_PASSWORD=<strong-password>

# Invite Code (optional feature)
REQUIRE_INVITE_CODE=false           # Set to true to require invite
INVITE_CODE=RANSOMRUN2024          # The valid invite code

# SIEM Mode (existing)
SIEM_MODE=mock                      # or 'elastic'
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'passlib'"

**Solution:**
```bash
pip install passlib[bcrypt] python-jose[cryptography] itsdangerous
```

### Issue: Login redirects to login page (loop)

**Solution:**
- Check session middleware is installed
- Check SESSION_SECRET is set
- Clear browser cookies and try again

### Issue: "Invalid security token" on all forms

**Solution:**
- Session middleware must be added BEFORE CORS middleware
- Check `app/main.py` has `SessionMiddleware` before `CORSMiddleware`

### Issue: Can't access any pages after login

**Solution:**
- Check `require_user` dependency is working
- Check user exists in database: `SELECT * FROM auth_users;`
- Check session cookie is set in browser

### Issue: Password validation not working

**Solution:**
- Check password meets all requirements:
  - Minimum 10 characters
  - At least 1 digit
  - At least 1 special symbol (!@#$%^&*...)

---

## Production Deployment Checklist

- [ ] Set `SESSION_SECRET` to a strong random value
- [ ] Set `COOKIE_SECURE=true` (requires HTTPS)
- [ ] Change default `INVITE_CODE` if using invite system
- [ ] Create admin user with strong password
- [ ] Enable HTTPS (required for secure cookies)
- [ ] Set up database backups
- [ ] Configure rate limiting (currently in-memory, consider Redis)
- [ ] Review CORS settings in `main.py`
- [ ] Add logging for security events
- [ ] Consider adding email verification
- [ ] Consider adding 2FA for admin users

---

## Security Best Practices

1. **Passwords:**
   - Never log passwords
   - Always hash with bcrypt (cost factor 12+)
   - Enforce strong password policy

2. **Sessions:**
   - Use HttpOnly cookies (prevents XSS)
   - Use SameSite=Lax (prevents CSRF)
   - Use Secure flag in production (requires HTTPS)
   - Rotate session secrets periodically

3. **CSRF:**
   - Validate CSRF tokens on all state-changing operations
   - Generate new token per session
   - Never expose tokens in URLs

4. **Rate Limiting:**
   - Limit login attempts per IP
   - Consider adding rate limiting to signup
   - Use Redis for distributed rate limiting in production

5. **Database:**
   - Never store plaintext passwords
   - Index email column for fast lookups
   - Regularly backup user data

---

## Summary

**Authentication System Complete:**
- ✅ Public landing page with marketing content
- ✅ User registration with email/password
- ✅ Login with session management
- ✅ Protected routes requiring authentication
- ✅ Account settings (change password)
- ✅ CSRF protection on forms
- ✅ Rate limiting on login
- ✅ Secure password hashing (bcrypt)
- ✅ HttpOnly session cookies
- ✅ Logout functionality

**Ready for use in lab/educational environments.**

For production deployment, follow the Production Deployment Checklist above.
