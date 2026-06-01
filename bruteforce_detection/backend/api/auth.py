"""
Authentication Routes - Fixed version
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.ip_blocker import _get_client_ip, classify_and_block
from backend.ml.pipeline import run_inference_for_ip
from backend.models.database import get_db
from backend.models.models import (
    ActiveSession, LoginLog, LoginStatus, AttackType, User, UserRole,
)
from backend.utils.security import (
    create_access_token, decode_access_token, hash_password, verify_password,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

# Still used by API clients sending Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterIn(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_len(cls, v):
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3-64 characters")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    redirect_to: str  # FIX 2: frontend needs this to route admin vs user


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime


# ── Token extraction helper ────────────────────────────────────────────────────

def _extract_token(request: Request) -> str | None:
    """
    FIX 3 & 4: Check Authorization header first (API clients),
    then fall back to the HttpOnly cookie (browser sessions).
    """
    # 1. Authorization header — API / Swagger / external clients
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1]

    # 2. HttpOnly cookie — browser sessions set by /login
    cookie_val = request.cookies.get("access_token")
    if cookie_val and cookie_val.startswith("Bearer "):
        return cookie_val.split(" ", 1)[1]

    return None


# ── Auth dependencies ──────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FIX 4: Reads token from cookie OR Authorization header,
    not just the header via oauth2_scheme.
    """
    print("\n" + "=" * 50)
    print("GET_CURRENT_USER CALLED")

    token = _extract_token(request)

    print("Token found:", bool(token))
    if token:
        print("Token preview:", token[:40] + "...")

    if not token:
        print("NO TOKEN FOUND")
        print("=" * 50)
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_access_token(token)
    print("Decoded payload:", payload)

    if not payload:
        print("TOKEN DECODE FAILED")
        print("=" * 50)
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # FIX 6: sub is stored as int but decoded from JWT as string — cast it
    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        print("INVALID SUB IN TOKEN")
        print("=" * 50)
        raise HTTPException(status_code=401, detail="Invalid token payload")

    print("User ID from token:", user_id)

    user_q = await db.execute(select(User).where(User.id == user_id))
    user = user_q.scalar_one_or_none()

    print("User found:", bool(user))

    if not user or not user.is_active:
        print("USER DISABLED OR NOT FOUND")
        print("=" * 50)
        raise HTTPException(status_code=401, detail="User not found or disabled")

    print("AUTHENTICATION SUCCESS")
    print("=" * 50)
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=UserOut, status_code=201)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)):
    existing_q = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing_q.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already taken")

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=UserRole.USER,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.value,
        created_at=user.created_at,
    )


@router.post("/login", response_model=TokenOut)
async def login(
    request: Request,
    response: Response,  # FIX 3: needed to set the HttpOnly cookie
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    username = form_data.username

    print("\n" + "=" * 50)
    print("LOGIN ATTEMPT")
    print("Username:", username)
    print("IP Address:", ip)
    print("User-Agent:", ua)

    user_q = await db.execute(select(User).where(User.username == username))
    user = user_q.scalar_one_or_none()

    login_success = bool(
        user and user.is_active and
        verify_password(form_data.password, user.hashed_password)
    )

    print("User exists:", bool(user))
    if user:
        print("User active:", user.is_active)
    print("Password verified:", login_success)

    attack_type = AttackType.NONE
    ml_score = None

    if not login_success:
        attack_type = await classify_and_block(db, ip, username)
        try:
            is_threat, ml_score = await run_inference_for_ip(db, ip)
            if is_threat and attack_type == AttackType.NONE:
                attack_type = AttackType.ANOMALY
        except Exception as exc:
            log.warning("ML inference error: %s", exc)

    log_entry = LoginLog(
        ip_address=ip,
        attempted_username=username,
        status=LoginStatus.SUCCESS if login_success else LoginStatus.FAILURE,
        attack_type=attack_type,
        user_agent=ua,
        ml_score=ml_score,
        user_id=user.id if user else None,
    )
    db.add(log_entry)

    if not login_success:
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token, jti = create_access_token(
        {"sub": user.id, "role": user.role.value},
        expires_delta=timedelta(hours=24),
    )

    print("\nTOKEN CREATED")
    print("User ID:", user.id)
    print("Username:", user.username)
    print("Role:", user.role.value)
    print("JTI:", jti)
    print("Token length:", len(token))

    session = ActiveSession(
        user_id=user.id,
        token_jti=jti,
        ip_address=ip,
        user_agent=ua,
    )
    db.add(session)

    print("\nSESSION RECORD CREATED")
    print("Session user:", user.username)
    print("Session IP:", ip)

    user.last_login = datetime.utcnow()
    await db.commit()

    # FIX 3: Set token as an HttpOnly cookie so JS cannot read or steal it.
    # The browser will send this cookie automatically on every request.
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,    # not accessible via JS — prevents XSS token theft
        samesite="lax",   # sent on same-site navigations, blocks CSRF
        secure=False,     # set True in production when using HTTPS
        max_age=86400,    # 24 hours — matches token expiry
        path="/",
    )

    # FIX 2: Return redirect_to so the frontend knows where to send the user.
    # FIX 1: return is now at the end — the print statements above actually run.
    redirect_to = "/admin" if user.role == UserRole.ADMIN else "/dashboard"

    print("\nLOGIN SUCCESSFUL")
    print("Redirecting to:", redirect_to)
    print("=" * 50)

    return TokenOut(
        access_token=token,   # still returned for API / Swagger clients
        token_type="bearer",
        role=user.role.value,
        redirect_to=redirect_to,  # FIX 2
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,  # FIX 5: needed to clear the cookie
    db: AsyncSession = Depends(get_db),
):
    """
    FIX 5: Reads token from cookie (not just the Authorization header),
    invalidates the session in the DB, and clears the cookie.
    """
    token = _extract_token(request)

    if token:
        payload = decode_access_token(token)
        if payload:
            jti = payload.get("jti")
            if jti:
                sess_q = await db.execute(
                    select(ActiveSession).where(ActiveSession.token_jti == jti)
                )
                sess = sess_q.scalar_one_or_none()
                if sess:
                    sess.is_valid = False
                    await db.commit()

    # Clear the HttpOnly cookie regardless of whether the token was valid
    response.delete_cookie(key="access_token", path="/")
    return {"detail": "Logged out successfully"}


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    print("\n" + "=" * 50)
    print("ME ENDPOINT CALLED")
    print("Authenticated user:", user.username)
    print("User ID:", user.id)
    print("=" * 50)

    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.value,
        created_at=user.created_at,
    )