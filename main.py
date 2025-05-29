from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt, JWTError
from sqlalchemy import (
    Column, Integer, String, create_engine, ForeignKey, DateTime as SA_DateTime
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.context import CryptContext
from typing import Optional, List, Dict
import random

# --- Configurações JWT ---
SECRET_KEY = "ChaveSuperSeguraComMaisDe64CaracteresParaJWTFuncionarCorretamenteComHS512"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# --- Setup SQLAlchemy ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# --- Modelos ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    regions = relationship(
        "Region", back_populates="user", cascade="all, delete-orphan"
    )
    events = relationship(
        "OutageEvent", back_populates="user", cascade="all, delete-orphan"
    )

class Region(Base):
    __tablename__ = "regions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    region = Column(String, nullable=False)
    created_at = Column(SA_DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="regions")

class OutageEvent(Base):
    __tablename__ = "outage_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    region_id = Column(Integer, ForeignKey("regions.id"), nullable=False)
    start_time = Column(SA_DateTime, default=datetime.utcnow)
    estimated_duration = Column(String, nullable=False)
    actual_duration = Column(String, nullable=True)
    damages = Column(String, nullable=True)
    created_at = Column(SA_DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="events")
    region = relationship("Region")

Base.metadata.create_all(bind=engine)

# --- Segurança Senha ---
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# --- Schemas Pydantic ---
class LoginRequest(BaseModel):
    email: str
    password: str

class CreateUserRequest(BaseModel):
    email: str
    password: str

class UpdateUserRequest(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True

class RegionCreate(BaseModel):
    region: str

class RegionResponse(BaseModel):
    id: int
    region: str
    created_at: datetime
    class Config:
        from_attributes = True

class OutageEventCreate(BaseModel):
    region_id: int
    estimated_duration: str
    actual_duration: Optional[str] = None
    damages: Optional[str] = None

class OutageEventUpdate(BaseModel):
    estimated_duration: Optional[str] = None
    actual_duration: Optional[str] = None
    damages: Optional[str] = None

class OutageEventResponse(BaseModel):
    id: int
    region_id: int
    estimated_duration: str
    actual_duration: Optional[str]
    damages: Optional[str]
    start_time: datetime
    created_at: datetime
    class Config:
        from_attributes = True

# --- Dependência DB ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Autenticação JWT ---
def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- FastAPI App ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Endpoints Usuário ---
@app.post("/create-user", response_model=UserResponse)
def create_user(request: CreateUserRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")
    new_user = User(
        email=request.email,
        hashed_password=get_password_hash(request.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def get_my_user(current_user: User = Depends(get_current_user)):
    return current_user

# --- Endpoints Regiões ---
@app.post("/regions", response_model=RegionResponse)
def create_region(
    payload: RegionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    new = Region(user_id=current_user.id, region=payload.region)
    db.add(new)
    db.commit()
    db.refresh(new)
    return new

@app.get("/regions", response_model=List[RegionResponse])
def list_regions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(Region) \
        .filter(Region.user_id == current_user.id) \
        .order_by(Region.created_at.desc()) \
        .all()

# --- Endpoints Eventos de Falta de Energia ---
@app.post("/events", response_model=OutageEventResponse)
def create_event(
    payload: OutageEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = OutageEvent(
        user_id=current_user.id,
        region_id=payload.region_id,
        estimated_duration=payload.estimated_duration,
        actual_duration=payload.actual_duration,
        damages=payload.damages
    )
    db.add(ev); db.commit(); db.refresh(ev)
    return ev

@app.get("/events", response_model=List[OutageEventResponse])
def list_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(OutageEvent) \
        .filter(OutageEvent.user_id == current_user.id) \
        .order_by(OutageEvent.created_at.desc()) \
        .all()

@app.get("/events/{event_id}", response_model=OutageEventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = db.query(OutageEvent).filter_by(id=event_id, user_id=current_user.id).first()
    if not ev:
        raise HTTPException(404, "Evento não encontrado")
    return ev

@app.put("/events/{event_id}", response_model=OutageEventResponse)
def update_event(
    event_id: int,
    payload: OutageEventUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = db.query(OutageEvent).filter_by(id=event_id, user_id=current_user.id).first()
    if not ev:
        raise HTTPException(404, "Evento não encontrado")
    for attr, val in payload.dict(exclude_unset=True).items():
        setattr(ev, attr, val)
    db.commit(); db.refresh(ev)
    return ev

@app.delete("/events/{event_id}")
def delete_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = db.query(OutageEvent).filter_by(id=event_id, user_id=current_user.id).first()
    if not ev:
        raise HTTPException(404, "Evento não encontrado")
    db.delete(ev); db.commit()
    return {"detail": "Evento removido com sucesso"}

# --- Endpoints Recomendações ---
@app.get("/recommendations", response_model=List[str])
def get_recommendations():
    return [
        'Mantenha lanternas e pilhas à mão.',
        'Estoque água potável.',
        'Desligue equipamentos sensíveis antes do restabelecimento.',
        'Siga instruções das autoridades locais.'
    ]

# --- Health Check ---
@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
