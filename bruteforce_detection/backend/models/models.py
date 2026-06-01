"""
SQLAlchemy ORM Models
Covers: Users, LoginLog, BlockedIP, ActiveSession, MLAnomaly
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Text, Float, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class LoginStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"


class AttackType(str, enum.Enum):
    NONE         = "NONE"
    BRUTE_FORCE  = "BRUTE_FORCE"       # One IP → One Account
    SPRAY        = "SPRAY"             # One IP → Many Accounts
    STUFFING     = "CREDENTIAL_STUFFING"  # Many IPs → Many Accounts
    ANOMALY      = "ML_ANOMALY"        # Flagged by ML model


class UserRole(str, enum.Enum):
    USER  = "user"
    ADMIN = "admin"


# ── Tables ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(64),  unique=True, nullable=False, index=True)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role          = Column(SAEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active     = Column(Boolean, default=True, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login    = Column(DateTime, nullable=True)

    sessions      = relationship("ActiveSession", back_populates="user",
                                 cascade="all, delete-orphan")
    login_logs    = relationship("LoginLog", back_populates="user")


class LoginLog(Base):
    __tablename__ = "login_logs"

    id               = Column(Integer, primary_key=True, index=True)
    timestamp        = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address       = Column(String(45), nullable=False, index=True)
    attempted_username = Column(String(64), nullable=False, index=True)
    status           = Column(SAEnum(LoginStatus), nullable=False, index=True)
    attack_type      = Column(SAEnum(AttackType), default=AttackType.NONE, nullable=False)
    user_agent       = Column(Text, nullable=True)
    ml_score         = Column(Float, nullable=True)   # anomaly score from model
    user_id          = Column(Integer, ForeignKey("users.id"), nullable=True)

    user             = relationship("User", back_populates="login_logs")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id           = Column(Integer, primary_key=True, index=True)
    ip_address   = Column(String(45), unique=True, nullable=False, index=True)
    reason       = Column(Text, nullable=True)
    attack_type  = Column(SAEnum(AttackType), default=AttackType.NONE)
    blocked_at   = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at   = Column(DateTime, nullable=True)   # None = permanent
    blocked_by   = Column(String(64), nullable=True) # "system" or admin username
    is_active    = Column(Boolean, default=True, nullable=False)


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_jti  = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    logged_in_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_active   = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_valid      = Column(Boolean, default=True, nullable=False)

    user = relationship("User", back_populates="sessions")


class MLAnomaly(Base):
    """Records every anomaly flagged by the ML pipeline for audit trail."""
    __tablename__ = "ml_anomalies"

    id           = Column(Integer, primary_key=True, index=True)
    detected_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address   = Column(String(45), nullable=False, index=True)
    ml_score     = Column(Float, nullable=False)
    features     = Column(Text, nullable=True)   # JSON blob of feature vector
    action_taken = Column(String(64), nullable=True)  # "blocked" | "flagged"
