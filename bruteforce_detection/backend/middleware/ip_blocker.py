"""
IP Blocking Middleware
─────────────────────
Checks every inbound request against the BlockedIP table.
Returns HTTP 403 immediately if the source IP is on the blocklist.

Also houses the rule-based attack classifier that runs after
every failed login attempt.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from backend.models.models import BlockedIP, LoginLog, LoginStatus, AttackType
from backend.models.database import AsyncSessionLocal
from config import settings

log = logging.getLogger(__name__)


# ── Middleware ────────────────────────────────────────────────────────────────

class IPBlockMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests from IPs present in the blocked_ips table.
    Auth endpoints (/api/auth/*) are checked; static assets are skipped.
    """
    EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json", "/health"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip non-auth static paths for performance
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return await call_next(request)

        client_ip = _get_client_ip(request)

        async with AsyncSessionLocal() as db:
            blocked = await _is_ip_blocked(db, client_ip)

        if blocked:
            log.warning("BLOCKED request from %s to %s", client_ip, path)
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Access forbidden. Your IP has been blocked due to suspicious activity.",
                    "ip": client_ip,
                },
            )

        return await call_next(request)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_client_ip(request: Request) -> str:
    """Extracts real IP, respecting X-Forwarded-For from trusted proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


async def _is_ip_blocked(db: AsyncSession, ip: str) -> bool:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(BlockedIP).where(
            BlockedIP.ip_address == ip,
            BlockedIP.is_active == True,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        return False
    # Honour expiry
    if record.expires_at and record.expires_at < now:
        record.is_active = False
        await db.commit()
        return False
    return True


# ── Rule-Based Classifier ─────────────────────────────────────────────────────

async def classify_and_block(db: AsyncSession, ip: str, username: str) -> AttackType:
    """
    Analyses recent login_logs for the given IP/username and:
    1. Labels the attack type (BRUTE_FORCE | SPRAY | STUFFING | NONE).
    2. Automatically blocks the IP if thresholds are exceeded.
    Returns the detected AttackType.
    """
    window_start = datetime.utcnow() - timedelta(seconds=settings.MAX_FAILED_WINDOW_SECONDS)

    # ── Fetch recent failures from this IP ───────────────────────────────────
    ip_failures_q = await db.execute(
        select(LoginLog).where(
            LoginLog.ip_address == ip,
            LoginLog.status == LoginStatus.FAILURE,
            LoginLog.timestamp >= window_start,
        )
    )
    ip_failures = ip_failures_q.scalars().all()

    # ── Fetch recent failures targeting this username (many IPs) ─────────────
    username_failures_q = await db.execute(
        select(LoginLog).where(
            LoginLog.attempted_username == username,
            LoginLog.status == LoginStatus.FAILURE,
            LoginLog.timestamp >= window_start,
        )
    )
    username_failures = username_failures_q.scalars().all()

    unique_users_from_ip = len({r.attempted_username for r in ip_failures})
    unique_ips_for_user  = len({r.ip_address for r in username_failures})
    total_ip_attempts    = len(ip_failures)

    attack_type = AttackType.NONE

    # ── Classification logic ──────────────────────────────────────────────────
    if (unique_ips_for_user >= settings.STUFFING_UNIQUE_IPS_THRESHOLD and
            unique_users_from_ip >= settings.SPRAY_UNIQUE_USERS_THRESHOLD):
        # Distributed IPs each hitting different accounts → Credential Stuffing
        attack_type = AttackType.STUFFING

    elif unique_users_from_ip >= settings.SPRAY_UNIQUE_USERS_THRESHOLD:
        # Single IP → many accounts → Password Spraying
        attack_type = AttackType.SPRAY

    elif total_ip_attempts >= settings.MAX_FAILED_ATTEMPTS_PER_IP:
        # Single IP → single account → Brute Force
        attack_type = AttackType.BRUTE_FORCE

    # ── Auto-block if an attack was detected ─────────────────────────────────
    if attack_type != AttackType.NONE:
        await block_ip(
            db=db,
            ip=ip,
            reason=f"Auto-blocked: {attack_type.value}",
            attack_type=attack_type,
            blocked_by="system",
            duration_seconds=settings.BLOCK_DURATION_SECONDS,
        )

    return attack_type


async def block_ip(
    db: AsyncSession,
    ip: str,
    reason: str = "",
    attack_type: AttackType = AttackType.NONE,
    blocked_by: str = "system",
    duration_seconds: Optional[int] = None,
) -> BlockedIP:
    """
    Inserts or updates a BlockedIP record.
    If duration_seconds is None the block is permanent.
    """
    now = datetime.utcnow()
    expires = (now + timedelta(seconds=duration_seconds)) if duration_seconds else None

    # Upsert: deactivate old, insert fresh
    existing_q = await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == ip)
    )
    existing = existing_q.scalar_one_or_none()

    if existing:
        existing.is_active   = True
        existing.reason      = reason
        existing.attack_type = attack_type
        existing.blocked_at  = now
        existing.expires_at  = expires
        existing.blocked_by  = blocked_by
        record = existing
    else:
        record = BlockedIP(
            ip_address=ip,
            reason=reason,
            attack_type=attack_type,
            blocked_at=now,
            expires_at=expires,
            blocked_by=blocked_by,
            is_active=True,
        )
        db.add(record)

    await db.commit()
    await db.refresh(record)
    log.warning("IP %s blocked. Reason: %s | Type: %s", ip, reason, attack_type.value)
    return record


async def unblock_ip(db: AsyncSession, ip: str) -> bool:
    """Deactivates a block. Returns True if a record was found."""
    result = await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == ip, BlockedIP.is_active == True)
    )
    record = result.scalar_one_or_none()
    if not record:
        return False
    record.is_active = False
    await db.commit()
    return True
