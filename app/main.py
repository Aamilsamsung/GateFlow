"""GateFlow development-only pilot API. NEVER expose demo authentication publicly."""
import os
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gateflow.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(engine)

class Base(DeclarativeBase):
    pass

class Leave(Base):
    __tablename__ = "leaves"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant: Mapped[str] = mapped_column(String(80), index=True)
    student: Mapped[str] = mapped_column(String(80))
    guardian: Mapped[str] = mapped_column(String(80))
    destination: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(300))
    departure: Mapped[datetime] = mapped_column(DateTime())
    expected_return: Mapped[datetime] = mapped_column(DateTime())
    status: Mapped[str] = mapped_column(String(40), default="pending_parent")
    pass_token: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant: Mapped[str] = mapped_column(String(80), index=True)
    leave_id: Mapped[int] = mapped_column(ForeignKey("leaves.id"))
    actor: Mapped[str] = mapped_column(String(80))
    event: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(), default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )

Base.metadata.create_all(engine)
app = FastAPI(title="GateFlow Prototype API — DO NOT DEPLOY PUBLICLY", version="0.1.0")
DEMO_SECRET = os.getenv("GATEFLOW_DEMO_SECRET", "")

class Principal(BaseModel):
    tenant: str
    role: Literal["student", "parent", "warden", "security", "admin"]
    identity: str

def auth(x_demo_auth: str = Header(default="")):
    if not DEMO_SECRET or not x_demo_auth:
        raise HTTPException(401, "Set GATEFLOW_DEMO_SECRET and provide X-Demo-Auth")
    parts = x_demo_auth.split(":")
    if len(parts) != 4 or not secrets.compare_digest(parts[3], DEMO_SECRET):
        raise HTTPException(401, "Invalid credentials")
    try:
        return Principal(tenant=parts[0], role=parts[1], identity=parts[2])
    except ValueError as exc:
        raise HTTPException(401, "Invalid identity") from exc

def db():
    with SessionLocal() as session:
        yield session

class RequestLeave(BaseModel):
    guardian: str = Field(min_length=1, max_length=80)
    destination: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=300)
    departure: datetime
    expected_return: datetime

class Decision(BaseModel):
    approve: bool

class Policy(BaseModel):
    requires_warden: bool = True

POLICIES = {}  # demo-only process-local setting; not suitable for deployments

def require(principal, *roles):
    if principal.role not in roles:
        raise HTTPException(403, "Role not permitted")

def get_leave(session, tenant, leave_id):
    item = session.scalar(select(Leave).where(Leave.id == leave_id, Leave.tenant == tenant))
    if not item:
        raise HTTPException(404, "Leave not found")
    return item

def log(session, principal, leave, event):
    session.add(Audit(tenant=principal.tenant, leave_id=leave.id,
                      actor=f"{principal.role}:{principal.identity}", event=event))

def view(leave):
    return {key: getattr(leave, key) for key in (
        "id", "tenant", "student", "guardian", "destination", "reason",
        "departure", "expected_return", "status",
    )}

@app.get("/health")
def health():
    return {"ok": True, "mode": "development-only"}

@app.post("/leaves", status_code=201)
def create(payload: RequestLeave, p: Principal = Depends(auth), s: Session = Depends(db)):
    require(p, "student")
    if payload.expected_return <= payload.departure:
        raise HTTPException(422, "Return must be after departure")
    leave = Leave(tenant=p.tenant, student=p.identity, guardian=payload.guardian,
                  destination=payload.destination, reason=payload.reason,
                  departure=payload.departure.replace(tzinfo=None),
                  expected_return=payload.expected_return.replace(tzinfo=None),
                  status="pending_parent")
    s.add(leave)
    s.flush()
    log(s, p, leave, "requested")
    s.commit()
    s.refresh(leave)
    return view(leave)

@app.get("/leaves")
def list_leaves(p: Principal = Depends(auth), s: Session = Depends(db)):
    q = select(Leave).where(Leave.tenant == p.tenant)
    if p.role == "student":
        q = q.where(Leave.student == p.identity)
    if p.role == "parent":
        q = q.where(Leave.guardian == p.identity)
    return [view(leave) for leave in s.scalars(q.order_by(Leave.id.desc())).all()]

@app.post("/leaves/{leave_id}/parent-decision")
def parent_decision(leave_id: int, decision: Decision,
                    p: Principal = Depends(auth), s: Session = Depends(db)):
    require(p, "parent")
    leave = get_leave(s, p.tenant, leave_id)
    if leave.guardian != p.identity:
        raise HTTPException(403, "Not assigned guardian")
    if leave.status != "pending_parent":
        raise HTTPException(409, "Invalid state")
    leave.status = ("pending_warden" if POLICIES.get(p.tenant, True) else "approved") if decision.approve else "rejected"
    if leave.status == "approved":
        leave.pass_token = secrets.token_urlsafe(32)
    log(s, p, leave, "parent_approved" if decision.approve else "parent_rejected")
    s.commit()
    return view(leave)

@app.post("/leaves/{leave_id}/warden-decision")
def warden_decision(leave_id: int, decision: Decision,
                    p: Principal = Depends(auth), s: Session = Depends(db)):
    require(p, "warden")
    leave = get_leave(s, p.tenant, leave_id)
    if leave.status != "pending_warden":
        raise HTTPException(409, "Invalid state")
    leave.status = "approved" if decision.approve else "rejected"
    if decision.approve:
        leave.pass_token = secrets.token_urlsafe(32)
    log(s, p, leave, "warden_approved" if decision.approve else "warden_rejected")
    s.commit()
    return view(leave)

@app.get("/leaves/{leave_id}/pass")
def pass_info(leave_id: int, p: Principal = Depends(auth), s: Session = Depends(db)):
    leave = get_leave(s, p.tenant, leave_id)
    if p.role != "student" or leave.student != p.identity:
        raise HTTPException(403, "Not your pass")
    if leave.status != "approved":
        raise HTTPException(409, "Pass not available")
    return {"leave_id": leave.id, "token": leave.pass_token,
            "note": "DEMO ONLY: token is not an expiring QR credential"}

class Scan(BaseModel):
    token: str
    action: Literal["exit", "return"]

@app.post("/gate/scan")
def scan(payload: Scan, p: Principal = Depends(auth), s: Session = Depends(db)):
    require(p, "security")
    leave = s.scalar(select(Leave).where(
        Leave.tenant == p.tenant, Leave.pass_token == payload.token
    ))
    if not leave:
        raise HTTPException(404, "Invalid pass")
    expected = "approved" if payload.action == "exit" else "outside"
    if leave.status != expected:
        raise HTTPException(409, "Pass cannot be used in current state")
    leave.status = "outside" if payload.action == "exit" else "returned"
    log(s, p, leave, payload.action)
    s.commit()
    return view(leave)

@app.get("/audit")
def audit(p: Principal = Depends(auth), s: Session = Depends(db)):
    require(p, "warden", "admin")
    entries = s.scalars(select(Audit).where(
        Audit.tenant == p.tenant
    ).order_by(Audit.id.desc())).all()
    return [{"leave_id": a.leave_id, "actor": a.actor,
             "event": a.event, "created_at": a.created_at} for a in entries]

@app.put("/policy")
def set_policy(payload: Policy, p: Principal = Depends(auth)):
    require(p, "admin")
    POLICIES[p.tenant] = payload.requires_warden
    return {"tenant": p.tenant, "requires_warden": payload.requires_warden}
