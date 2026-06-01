"""
Admin Routes
────────────
GET  /api/admin/users/active      – live active sessions
GET  /api/admin/logs              – paginated login log table
GET  /api/admin/logs/stats        – attack type breakdown
GET  /api/admin/blocked-ips       – all blocked IPs
POST /api/admin/blocked-ips       – manually block an IP
DELETE /api/admin/blocked-ips/{ip} – unblock an IP
POST /api/admin/ml/train          – trigger model retraining
GET  /api/admin/ml/anomalies      – ML flagged events
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.auth import require_admin
from backend.middleware.ip_blocker import block_ip, unblock_ip
from backend.ml.pipeline import train_model, ThreatDetector
from backend.models.database import get_db
from backend.models.models import (
    ActiveSession, BlockedIP, LoginLog, LoginStatus, AttackType,
    MLAnomaly, User,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class BlockIPIn(BaseModel):
    ip_address: str
    reason: Optional[str] = "Manually blocked by admin"
    duration_seconds: Optional[int] = None  # None = permanent


class ActiveUserOut(BaseModel):
    username: str
    email: str
    role: str
    ip_address: Optional[str]
    logged_in_at: datetime
    last_active: datetime


class LogOut(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    attempted_username: str
    status: str
    attack_type: str
    ml_score: Optional[float]
    user_agent: Optional[str]


class BlockedIPOut(BaseModel):
    id: int
    ip_address: str
    reason: Optional[str]
    attack_type: str
    blocked_at: datetime
    expires_at: Optional[datetime]
    blocked_by: Optional[str]


# ── Active Sessions ───────────────────────────────────────────────────────────

@router.get("/users/active", response_model=list[ActiveUserOut])
async def active_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(
        select(ActiveSession, User)
        .join(User, ActiveSession.user_id == User.id)
        .where(ActiveSession.is_valid == True)
        .order_by(desc(ActiveSession.last_active))
    )
    rows = result.all()
    return [
        ActiveUserOut(
            username=u.username,
            email=u.email,
            role=u.role.value,
            ip_address=s.ip_address,
            logged_in_at=s.logged_in_at,
            last_active=s.last_active,
        )
        for s, u in rows
    ]


# ── Log Table ─────────────────────────────────────────────────────────────────

@router.get("/logs", response_model=list[LogOut])
async def get_logs(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None),
    attack_filter: Optional[str] = Query(None),
    ip_filter: Optional[str] = Query(None),
):
    q = select(LoginLog).order_by(desc(LoginLog.timestamp))
    if status_filter:
        q = q.where(LoginLog.status == status_filter)
    if attack_filter:
        q = q.where(LoginLog.attack_type == attack_filter)
    if ip_filter:
        q = q.where(LoginLog.ip_address.ilike(f"%{ip_filter}%"))
    q = q.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(q)
    logs = result.scalars().all()
    return [
        LogOut(
            id=l.id,
            timestamp=l.timestamp,
            ip_address=l.ip_address,
            attempted_username=l.attempted_username,
            status=l.status.value,
            attack_type=l.attack_type.value,
            ml_score=l.ml_score,
            user_agent=l.user_agent,
        )
        for l in logs
    ]


@router.get("/logs/stats")
async def log_stats(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Returns counts broken down by status and attack_type."""
    # Status counts
    status_q = await db.execute(
        select(LoginLog.status, func.count(LoginLog.id))
        .group_by(LoginLog.status)
    )
    status_counts = {row[0].value: row[1] for row in status_q.all()}

    # Attack type counts
    attack_q = await db.execute(
        select(LoginLog.attack_type, func.count(LoginLog.id))
        .group_by(LoginLog.attack_type)
    )
    attack_counts = {row[0].value: row[1] for row in attack_q.all()}

    # Total log count
    total_q = await db.execute(select(func.count(LoginLog.id)))
    total = total_q.scalar_one()

    # Blocked IP count
    blocked_q = await db.execute(
        select(func.count(BlockedIP.id)).where(BlockedIP.is_active == True)
    )
    blocked_total = blocked_q.scalar_one()

    return {
        "total_logs": total,
        "active_blocks": blocked_total,
        "by_status": status_counts,
        "by_attack_type": attack_counts,
    }


# ── Blocked IPs ───────────────────────────────────────────────────────────────

@router.get("/blocked-ips", response_model=list[BlockedIPOut])
async def list_blocked_ips(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
    active_only: bool = Query(True),
):
    q = select(BlockedIP).order_by(desc(BlockedIP.blocked_at))
    if active_only:
        q = q.where(BlockedIP.is_active == True)
    result = await db.execute(q)
    ips = result.scalars().all()
    return [
        BlockedIPOut(
            id=b.id,
            ip_address=b.ip_address,
            reason=b.reason,
            attack_type=b.attack_type.value,
            blocked_at=b.blocked_at,
            expires_at=b.expires_at,
            blocked_by=b.blocked_by,
        )
        for b in ips
    ]


@router.post("/blocked-ips", status_code=201)
async def add_blocked_ip(
    body: BlockIPIn,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    record = await block_ip(
        db=db,
        ip=body.ip_address,
        reason=body.reason or "Manually blocked",
        blocked_by=admin.username,
        duration_seconds=body.duration_seconds,
    )
    return {"detail": f"IP {body.ip_address} blocked", "id": record.id}


@router.delete("/blocked-ips/{ip}")
async def remove_blocked_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    success = await unblock_ip(db, ip)
    if not success:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")
    return {"detail": f"IP {ip} unblocked"}


# ── ML Admin ──────────────────────────────────────────────────────────────────

@router.post("/ml/train")
async def trigger_training(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Pulls logs from the DB, engineers features, retrains the model.
    Returns evaluation metrics.
    """
    import pandas as pd
    from backend.ml.pipeline import engineer_features, FEATURE_COLS

    result = await db.execute(select(LoginLog).order_by(LoginLog.timestamp))
    logs = result.scalars().all()

    metrics = {}
    if len(logs) >= 50:
        data = pd.DataFrame([{
            "timestamp":          r.timestamp,
            "ip_address":         r.ip_address,
            "attempted_username": r.attempted_username,
            "status":             r.status.value,
        } for r in logs])
        features_df = engineer_features(data)
        # Label: any IP with BRUTE_FORCE/SPRAY/STUFFING logs → attack
        attack_ips_q = await db.execute(
            select(LoginLog.ip_address).where(
                LoginLog.attack_type != AttackType.NONE
            ).distinct()
        )
        attack_ips = {r[0] for r in attack_ips_q.all()}
        features_df["label"] = features_df["ip_address"].apply(
            lambda ip: 1 if ip in attack_ips else 0
        )
        metrics = train_model(features_df)
    else:
        metrics = train_model(None)   # synthetic data fallback

    ThreatDetector.get().reload()
    return {"detail": "Model retrained", "metrics": metrics}


@router.get("/ml/anomalies")
async def ml_anomalies(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
    limit: int = Query(100, ge=1, le=500),
):
    result = await db.execute(
        select(MLAnomaly).order_by(desc(MLAnomaly.detected_at)).limit(limit)
    )
    anomalies = result.scalars().all()
    return [
        {
            "id":           a.id,
            "detected_at":  a.detected_at,
            "ip_address":   a.ip_address,
            "ml_score":     a.ml_score,
            "features":     a.features,
            "action_taken": a.action_taken,
        }
        for a in anomalies
    ]
