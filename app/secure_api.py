"""GateFlow API: authenticated, tenant-scoped pilot. Set DATABASE_URL, AUTH_SECRET and BOOTSTRAP_ADMIN_PASSWORD."""
import os, hashlib, hmac, secrets
from datetime import datetime, timezone
from typing import Literal
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, DateTime, ForeignKey, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./gateflow.db").replace("postgres://","postgresql://",1)
AUTH_SECRET=os.getenv("AUTH_SECRET","")
BOOTSTRAP_PASSWORD=os.getenv("BOOTSTRAP_ADMIN_PASSWORD","")
if not AUTH_SECRET or len(AUTH_SECRET)<32: raise RuntimeError("AUTH_SECRET must be at least 32 characters")
engine=create_engine(DATABASE_URL,connect_args={"check_same_thread":False} if DATABASE_URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal=sessionmaker(engine)
class Base(DeclarativeBase): pass
class Account(Base):
    __tablename__="accounts"
    id:Mapped[int]=mapped_column(primary_key=True)
    tenant:Mapped[str]=mapped_column(String(80),index=True)
    username:Mapped[str]=mapped_column(String(100))
    role:Mapped[str]=mapped_column(String(30))
    password_hash:Mapped[str]=mapped_column(String(250))
    student_id:Mapped[str|None]=mapped_column(String(100),nullable=True)
class Leave(Base):
    __tablename__="leaves"
    id:Mapped[int]=mapped_column(primary_key=True)
    tenant:Mapped[str]=mapped_column(String(80),index=True)
    student:Mapped[str]=mapped_column(String(100))
    guardian:Mapped[str]=mapped_column(String(100))
    destination:Mapped[str]=mapped_column(String(200))
    reason:Mapped[str]=mapped_column(String(300))
    departure:Mapped[datetime]=mapped_column(DateTime)
    expected_return:Mapped[datetime]=mapped_column(DateTime)
    status:Mapped[str]=mapped_column(String(40),default="pending_parent")
    pass_token:Mapped[str|None]=mapped_column(String(128),unique=True,nullable=True)
class Audit(Base):
    __tablename__="audit"
    id:Mapped[int]=mapped_column(primary_key=True)
    tenant:Mapped[str]=mapped_column(String(80),index=True)
    leave_id:Mapped[int]=mapped_column(ForeignKey("leaves.id"))
    actor:Mapped[str]=mapped_column(String(120))
    event:Mapped[str]=mapped_column(String(80))
    created_at:Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.utcnow())
Base.metadata.create_all(engine)
def pwd_hash(password):
    salt=secrets.token_bytes(16)
    return salt.hex()+":"+hashlib.pbkdf2_hmac("sha256",password.encode(),salt,260000).hex()
def pwd_check(password,stored):
    try:
        salt,digest=stored.split(":")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),260000),bytes.fromhex(digest))
    except (ValueError,TypeError): return False
if BOOTSTRAP_PASSWORD:
    with SessionLocal() as db:
        if not db.scalar(select(Account).where(Account.tenant=="pilot",Account.username=="admin")):
            db.add(Account(tenant="pilot",username="admin",role="admin",password_hash=pwd_hash(BOOTSTRAP_PASSWORD)))
            db.commit()
signer=URLSafeTimedSerializer(AUTH_SECRET,salt="gateflow-session-v1")
app=FastAPI(title="GateFlow Pilot API",version="0.2.0")
origins=[s.strip() for s in os.getenv("CORS_ORIGINS","https://gateflow-ui-preview.onrender.com").split(",") if s.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=False,allow_methods=["GET","POST","PUT"],allow_headers=["Authorization","Content-Type"])
def db():
    with SessionLocal() as session: yield session
def require(account,*roles):
    if account.role not in roles: raise HTTPException(403,"Role not permitted")
def auth(authorization:str=Header(default=""),s:Session=Depends(db)):
    if not authorization.startswith("Bearer "): raise HTTPException(401,"Sign in required")
    try: ident=signer.loads(authorization[7:],max_age=3600*8)
    except (BadSignature,SignatureExpired): raise HTTPException(401,"Session expired or invalid")
    account=s.get(Account,ident.get("id"))
    if not account or account.tenant!=ident.get("tenant"): raise HTTPException(401,"Invalid account")
    return account
def get_leave(s,p,id):
    leave=s.scalar(select(Leave).where(Leave.id==id,Leave.tenant==p.tenant))
    if not leave: raise HTTPException(404,"Leave not found")
    return leave
def view(l):
    return {k:getattr(l,k) for k in ("id","tenant","student","guardian","destination","reason","departure","expected_return","status")}
def log(s,p,l,event):
    s.add(Audit(tenant=p.tenant,leave_id=l.id,actor=p.role+":"+p.username,event=event))
class Login(BaseModel):
    tenant:str="pilot"
    username:str
    password:str
class NewAccount(BaseModel):
    username:str=Field(min_length=3,max_length=100)
    password:str=Field(min_length=12,max_length=128)
    role:Literal["student","parent","warden","security","admin"]
    student_id:str|None=None
class RequestLeave(BaseModel):
    guardian:str
    destination:str=Field(min_length=1,max_length=200)
    reason:str=Field(min_length=1,max_length=300)
    departure:datetime
    expected_return:datetime
class Decision(BaseModel): approve:bool
class Scan(BaseModel):
    token:str
    action:Literal["exit","return"]
@app.get("/health")
def health():return {"ok":True,"mode":"authenticated-pilot"}
@app.post("/auth/login")
def login(body:Login,s:Session=Depends(db)):
    account=s.scalar(select(Account).where(Account.tenant==body.tenant,Account.username==body.username))
    if not account or not pwd_check(body.password,account.password_hash): raise HTTPException(401,"Invalid credentials")
    return {"token":signer.dumps({"id":account.id,"tenant":account.tenant}),"role":account.role,"username":account.username,"tenant":account.tenant}
@app.get("/auth/me")
def me(p:Account=Depends(auth)):return {"role":p.role,"username":p.username,"tenant":p.tenant}
@app.post("/accounts",status_code=201)
def new_account(body:NewAccount,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"admin")
    if s.scalar(select(Account).where(Account.tenant==p.tenant,Account.username==body.username)):raise HTTPException(409,"Username exists")
    if body.role=="parent" and not body.student_id:raise HTTPException(422,"Parent requires assigned student_id")
    if body.role=="parent" and not s.scalar(select(Account).where(Account.tenant==p.tenant,Account.username==body.student_id,Account.role=="student")):raise HTTPException(422,"Assigned student does not exist")
    s.add(Account(tenant=p.tenant,username=body.username,role=body.role,password_hash=pwd_hash(body.password),student_id=body.student_id))
    s.commit()
    return {"created":True,"username":body.username,"role":body.role}
@app.get("/leaves")
def list_leaves(p:Account=Depends(auth),s:Session=Depends(db)):
    q=select(Leave).where(Leave.tenant==p.tenant)
    if p.role=="student":q=q.where(Leave.student==p.username)
    if p.role=="parent":q=q.where(Leave.guardian==p.username,Leave.student==p.student_id)
    return [view(l) for l in s.scalars(q.order_by(Leave.id.desc())).all()]
@app.post("/leaves",status_code=201)
def create_leave(body:RequestLeave,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"student")
    if body.expected_return<=body.departure:raise HTTPException(422,"Return must be after departure")
    guardian=s.scalar(select(Account).where(Account.tenant==p.tenant,Account.username==body.guardian,Account.role=="parent",Account.student_id==p.username))
    if not guardian:raise HTTPException(422,"Guardian must be assigned by an administrator")
    l=Leave(tenant=p.tenant,student=p.username,guardian=body.guardian,destination=body.destination,reason=body.reason,departure=body.departure.replace(tzinfo=None),expected_return=body.expected_return.replace(tzinfo=None),status="pending_parent")
    s.add(l);s.flush();log(s,p,l,"requested");s.commit();s.refresh(l)
    return view(l)
@app.post("/leaves/{leave_id}/parent-decision")
def parent_decision(leave_id:int,body:Decision,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"parent");l=get_leave(s,p,leave_id)
    if l.guardian!=p.username or l.student!=p.student_id:raise HTTPException(403,"Not assigned guardian")
    if l.status!="pending_parent":raise HTTPException(409,"Invalid state")
    l.status="pending_warden" if body.approve else "rejected"
    log(s,p,l,"parent_approved" if body.approve else "parent_rejected");s.commit();return view(l)
@app.post("/leaves/{leave_id}/warden-decision")
def warden_decision(leave_id:int,body:Decision,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"warden");l=get_leave(s,p,leave_id)
    if l.status!="pending_warden":raise HTTPException(409,"Invalid state")
    l.status="approved" if body.approve else "rejected"
    if body.approve:l.pass_token=secrets.token_urlsafe(32)
    log(s,p,l,"warden_approved" if body.approve else "warden_rejected");s.commit();return view(l)
@app.get("/leaves/{leave_id}/pass")
def pass_info(leave_id:int,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"student");l=get_leave(s,p,leave_id)
    if l.student!=p.username:raise HTTPException(403,"Not your pass")
    if l.status!="approved":raise HTTPException(409,"Pass unavailable")
    return {"leave_id":l.id,"token":l.pass_token,"note":"Pilot credential. Present to authorized security staff."}
@app.post("/gate/scan")
def scan(body:Scan,p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"security")
    l=s.scalar(select(Leave).where(Leave.tenant==p.tenant,Leave.pass_token==body.token))
    if not l:raise HTTPException(404,"Invalid pass")
    if l.status!=("approved" if body.action=="exit" else "outside"):raise HTTPException(409,"Pass not valid for this action")
    l.status="outside" if body.action=="exit" else "returned"
    log(s,p,l,body.action);s.commit();return view(l)
@app.get("/audit")
def audit(p:Account=Depends(auth),s:Session=Depends(db)):
    require(p,"warden","admin")
    return [{"leave_id":a.leave_id,"actor":a.actor,"event":a.event,"created_at":a.created_at} for a in s.scalars(select(Audit).where(Audit.tenant==p.tenant).order_by(Audit.id.desc())).all()]
@app.put("/policy")
def policy(p:Account=Depends(auth)):
    require(p,"admin")
    raise HTTPException(501,"Institution policy management is not implemented yet")
