"""
scripts/seed.py
───────────────
Run once to create:
  • An admin user (admin / Admin1234!)
  • A regular test user (testuser / Test1234!)
  • 200 synthetic login log entries (mix of normal + attack traffic)
  • Pre-train the ML model

Usage:
    cd bruteforce_detection
    python scripts/seed.py
"""
import asyncio
import random
import sys
import os
from datetime import datetime, timedelta

# Make sure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.database import AsyncSessionLocal, init_db
from backend.models.models import User, UserRole, LoginLog, LoginStatus, AttackType
from backend.utils.security import hash_password
from backend.ml.pipeline import train_model
from sqlalchemy import select


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin1234!"
ADMIN_EMAIL    = "admin@bruteshield.local"

TEST_USERNAME  = "testuser"
TEST_PASSWORD  = "Test1234!"
TEST_EMAIL     = "testuser@bruteshield.local"


async def seed():
    print("Initialising database tables…")
    await init_db()

    async with AsyncSessionLocal() as db:
        # ── Users ──────────────────────────────────────────────────────────
        for uname, email, pwd, role in [
            (ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD, UserRole.ADMIN),
            (TEST_USERNAME,  TEST_EMAIL,  TEST_PASSWORD,  UserRole.USER),
        ]:
            existing = await db.execute(select(User).where(User.username == uname))
            if existing.scalar_one_or_none():
                print(f"  User '{uname}' already exists, skipping.")
                continue
            user = User(
                username=uname,
                email=email,
                hashed_password=hash_password(pwd),
                role=role,
            )
            db.add(user)
            print(f"  Created {role.value} user: {uname}")

        await db.commit()

        # ── Synthetic login logs ────────────────────────────────────────────
        print("Generating synthetic login logs…")
        now = datetime.utcnow()
        logs_created = 0

        # Normal traffic: 120 scattered successes/failures
        normal_users = ["alice","bob","charlie","diana","edward","fiona","george"]
        normal_ips   = [f"10.0.{i}.{j}" for i in range(1,4) for j in range(1,10)]

        for _ in range(120):
            ts = now - timedelta(hours=random.uniform(0,48))
            status = random.choice([LoginStatus.SUCCESS]*3 + [LoginStatus.FAILURE])
            log = LoginLog(
                timestamp=ts,
                ip_address=random.choice(normal_ips),
                attempted_username=random.choice(normal_users),
                status=status,
                attack_type=AttackType.NONE,
                user_agent="Mozilla/5.0 (Normal Traffic)",
            )
            db.add(log)
            logs_created += 1

        # Brute force: one IP hammering one account
        bf_ip = "192.168.99.100"
        for i in range(30):
            ts = now - timedelta(minutes=random.uniform(0,10))
            log = LoginLog(
                timestamp=ts,
                ip_address=bf_ip,
                attempted_username="admin",
                status=LoginStatus.FAILURE,
                attack_type=AttackType.BRUTE_FORCE,
                user_agent="python-requests/2.28.0",
            )
            db.add(log)
            logs_created += 1

        # Password spray: one IP trying many accounts
        spray_ip = "203.0.113.50"
        spray_users = [f"user{i:03d}" for i in range(20)]
        for uname in spray_users:
            ts = now - timedelta(minutes=random.uniform(0,5))
            log = LoginLog(
                timestamp=ts,
                ip_address=spray_ip,
                attempted_username=uname,
                status=LoginStatus.FAILURE,
                attack_type=AttackType.SPRAY,
                user_agent="Go-http-client/1.1",
            )
            db.add(log)
            logs_created += 1

        # Credential stuffing: many IPs, many accounts
        stuffing_ips = [f"198.51.{i}.{j}" for i in range(100,106) for j in range(1,6)]
        stuffing_targets = [f"victim{i}" for i in range(25)]
        for ip, uname in zip(stuffing_ips, stuffing_targets*2):
            ts = now - timedelta(hours=random.uniform(0,2))
            log = LoginLog(
                timestamp=ts,
                ip_address=ip,
                attempted_username=uname,
                status=LoginStatus.FAILURE,
                attack_type=AttackType.STUFFING,
                user_agent="curl/7.85.0",
            )
            db.add(log)
            logs_created += 1

        await db.commit()
        print(f"  Created {logs_created} log entries.")

    # ── Pre-train model ────────────────────────────────────────────────────
    print("Pre-training ML model with synthetic data…")
    metrics = train_model()
    print(f"  Training complete: accuracy={metrics['accuracy']:.3f} | F1={metrics['f1']:.3f}")

    print("\n✓ Seed complete!")
    print(f"  Admin  → username: {ADMIN_USERNAME}  password: {ADMIN_PASSWORD}")
    print(f"  User   → username: {TEST_USERNAME}   password: {TEST_PASSWORD}")
    print("  Run: uvicorn main:app --reload")


if __name__ == "__main__":
    asyncio.run(seed())
