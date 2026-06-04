from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import asyncpg
import bcrypt
import jwt
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

# --- KONFIGURACJA BAZY DANYCH I SSL ---
if os.getenv('RENDER') is None:
    load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

# Poprawa protokołu i wymuszenie SSL dla Rendera
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL and "ssl" not in DATABASE_URL:
    if "?" in DATABASE_URL:
        DATABASE_URL += "&ssl=require"
    else:
        DATABASE_URL += "?ssl=require"

JWT_SECRET = os.getenv('JWT_SECRET', 'awaryjny_klucz_jesli_brak_env')
ALGORITHM = "HS256"

security = HTTPBearer()
pool = None

# Zarządzanie cyklem życia aplikacji
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    # Jawne przekazanie ssl="require" przy tworzeniu puli
    pool = await asyncpg.create_pool(dsn=DATABASE_URL, ssl="require")
    yield
    await pool.close()

app = FastAPI(lifespan=lifespan)

# --- MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# --- MODELE Pydantic ---
class UserAuth(BaseModel):
    email: str
    password: str

class InquiryCreate(BaseModel):
    watch_id: Optional[int] = None
    message: str

class WatchCreate(BaseModel):
    brand: str
    model: str
    price_pln: float
    status: str = "dostępny"
    image_url: str
    description: Optional[str] = "Brak opisu"

class WatchUpdate(BaseModel):
    brand: str
    model: str
    price_pln: float
    status: str
    image_url: str
    description: Optional[str] = "Brak opisu"

class UserRoleUpdate(BaseModel):
    role_id: int

class WatchPriceUpdate(BaseModel):
    price_pln: float

class InquiryReply(BaseModel):
    reply: str

class WatchStatusUpdate(BaseModel):
    status: str

# --- FUNKCJE POMOCNICZE ---
def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=403, detail="Token wygasł lub jest nieprawidłowy")

# --- ENDPOINTY ---
@app.post("/auth/register", status_code=201)
async def register(user_data: UserAuth):
    async with pool.acquire() as conn:
        user_exists = await conn.fetchval('SELECT id FROM "User" WHERE email = $1', user_data.email)
        if user_exists:
            raise HTTPException(status_code=409, detail="Użytkownik już istnieje")
        
        client_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Client')
        hashed_password = get_password_hash(user_data.password)
        
        new_user = await conn.fetchrow(
            'INSERT INTO "User" (email, password_hash, role_id) VALUES ($1, $2, $3) RETURNING id, email, role_id',
            user_data.email, hashed_password, client_role_id
        )
        return {"message": "Rejestracja udana", "user": dict(new_user)}

@app.post("/auth/login")
async def login(user_data: UserAuth):
    async with pool.acquire() as conn:
        user = await conn.fetchrow('SELECT * FROM "User" WHERE email = $1', user_data.email)
        if not user or not verify_password(user_data.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="Nieprawidłowy e-mail lub hasło")

        expire = datetime.now(timezone.utc) + timedelta(hours=24)
        token = jwt.encode({"userId": user['id'], "roleId": user['role_id'], "email": user['email'], "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)
        return {"message": "Zalogowano", "token": token, "roleId": user['role_id']}

@app.get("/watches")
async def get_watches():
    async with pool.acquire() as conn:
        watches = await conn.fetch('SELECT * FROM "Watch" ORDER BY id ASC')
        return [dict(w) for w in watches]

# ... (reszta Twoich endpointów zostaje bez zmian)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=3001, reload=True)