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

# 1. Ładowanie zmiennych środowiskowych
if os.getenv('RENDER') is None:
    load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("Brak zmiennej środowiskowej DATABASE_URL!")

# Wymuszenie SSL dla bezpiecznego połączenia z bazą na Renderze
if "sslmode=require" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL += f"{separator}sslmode=require"

JWT_SECRET = os.getenv('JWT_SECRET', 'awaryjny_klucz_jesli_brak_env')
ALGORITHM = "HS256"

security = HTTPBearer()
pool = None

# Zarządzanie cyklem życia aplikacji (Połączenie z bazą przez URL z SSL)
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(dsn=DATABASE_URL, ssl='require')
    yield
    await pool.close()

app = FastAPI(lifespan=lifespan)

# NAPRAWA CORS: Zezwalamy na ruch lokalny ORAZ z chmury (dowolnej domeny) na Renderze
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# --- MODELE PANDANTIC ---
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

class InquiryReply(BaseModel):
    reply: str

class WatchPriceUpdate(BaseModel):
    price_pln: float

class WatchStatusUpdate(BaseModel):
    status: str

# --- FUNKCJE POMOCNICZE (SZYFROWANIE) ---
def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise HTTPException(status_code=403, detail="Token wygasł lub jest nieprawidłowy")

# --- ENDPOINTY AUTORYZACJI ---

@app.post("/auth/register", status_code=201)
async def register(user_data: UserAuth):
    async with pool.acquire() as conn:
        user_exists = await conn.fetchval('SELECT id FROM "User" WHERE email = $1', user_data.email)
        if user_exists:
            raise HTTPException(status_code=409, detail="Użytkownik o tym e-mailu już istnieje")

        client_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Client')
        if not client_role_id:
            # Awaryjne tworzenie roli, jeśli baza jest zupełnie nowa
            await conn.execute('INSERT INTO "Role" (name) VALUES ($1) ON CONFLICT DO NOTHING', 'Client')
            client_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Client')

        hashed_password = get_password_hash(user_data.password)

        try:
            new_user = await conn.fetchrow(
                'INSERT INTO "User" (email, password_hash, role_id) VALUES ($1, $2, $3) RETURNING id, email, role_id',
                user_data.email, hashed_password, client_role_id
            )
            return {"message": "Rejestracja zakończona sukcesem", "user": dict(new_user)}
        except Exception as e:
            print(f"Błąd rejestracji: {e}")
            raise HTTPException(status_code=500, detail="Błąd serwera podczas rejestracji")

@app.post("/auth/login")
async def login(user_data: UserAuth):
    async with pool.acquire() as conn:
        try:
            user = await conn.fetchrow('SELECT * FROM "User" WHERE email = $1', user_data.email)
            
            if not user or not verify_password(user_data.password, user['password_hash']):
                raise HTTPException(status_code=401, detail="Nieprawidłowy e-mail lub hasło")

            expire = datetime.now(timezone.utc) + timedelta(hours=24)
            to_encode = {"userId": user['id'], "roleId": user['role_id'], "email": user['email'], "exp": expire}
            token = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

            return {"message": "Zalogowano pomyślnie", "token": token, "roleId": user['role_id']}
        except HTTPException:
            raise
        except Exception as e:
            print(f"Błąd logowania: {e}")
            raise HTTPException(status_code=500, detail="Błąd serwera podczas logowania")

# --- POZOSTAŁE ENDPOINTY APLIKACJI ---

@app.get("/")
async def root():
    return {"message": "Backend działa!"}

@app.get("/watches")
async def get_watches(request: Request):
    # Próbujemy ręcznie odczytać nagłówek Authorization, aby nie blokować niezalogowanych
    auth_header = request.headers.get("Authorization")
    is_logged_in = False
    
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
            is_logged_in = True
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            is_logged_in = False # Token niepoprawny lub wygasł -> traktujemy jako niezalogowanego

    async with pool.acquire() as conn:
        try:
            watches = await conn.fetch('SELECT * FROM "Watch" ORDER BY id ASC')
            
            result = []
            for w in watches:
                watch_dict = dict(w)
                if is_logged_in:
                    # Zalogowany widzi pełną strukturę (razem z nowymi parametrami)
                    result.append(watch_dict)
                else:
                    # Niezalogowany widzi TYLKO bezpieczne minimum
                    result.append({
                        "id": watch_dict["id"],
                        "brand": watch_dict["brand"],
                        "model": watch_dict["model"],
                        "image_url": watch_dict["image_url"],
                        "status": watch_dict["status"],
                        # Ukryte bezpieczne wartości domyślne, by frontend się nie wysypał:
                        "price_pln": 0, 
                        "description": watch_dict["description"],
                        "year": None,
                        "mileage": None,
                        "power_hp": None,
                        "fuel_type": None
                    })
            return result
        except Exception as e:
            print(f"Błąd bazy danych: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")
@app.get("/watches/{id}")
async def get_watch(id: int):
    async with pool.acquire() as conn:
        try:
            watch = await conn.fetchrow('SELECT * FROM "Watch" WHERE id = $1', id)
            if not watch:
                raise HTTPException(status_code=404, detail="Zegarek nie znaleziony")
            return dict(watch)
        except HTTPException:
            raise
        except Exception as e:
            print(f"Błąd bazy danych: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

@app.post("/inquiries")
async def create_inquiry(inquiry: InquiryCreate, current_user: dict = Depends(get_current_user)):
    user_id = current_user['userId']
    async with pool.acquire() as conn:
        try:
            new_inquiry = await conn.fetchrow(
                'INSERT INTO "Inquiry" (user_id, watch_id, message) VALUES ($1, $2, $3) RETURNING *',
                user_id, inquiry.watch_id, inquiry.message
            )
            try:
                await conn.execute(
                    'INSERT INTO "AuditLog" (user_id, action_type, timestamp, ip_address) VALUES ($1, $2, NOW(), $3)',
                    user_id, 'create_inquiry', '127.0.0.1'
                )
            except Exception as auditErr:
                print(f"Błąd zapisu AuditLog: {auditErr}")
            return dict(new_inquiry)
        except Exception as e:
            print(f"Błąd przy dodawaniu zapytania: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

@app.get("/inquiries")
async def get_inquiries(current_user: dict = Depends(get_current_user)):
    user_id = current_user['userId']
    role_id = current_user['roleId']
    async with pool.acquire() as conn:
        try:
            if role_id == 2:
                inquiries = await conn.fetch(
                    'SELECT i.*, w.brand AS watch_brand, w.model AS watch_model FROM "Inquiry" i LEFT JOIN "Watch" w ON i.watch_id = w.id WHERE i.user_id = $1 ORDER BY i.created_at DESC',
                    user_id
                )
                return [dict(i) for i in inquiries]
            inquiries = await conn.fetch('SELECT * FROM "Inquiry" ORDER BY created_at DESC')
            return [dict(i) for i in inquiries]
        except Exception as e:
            print(f"Błąd pobierania zapytań: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

@app.post("/watches", status_code=201)
async def create_watch(watch: WatchCreate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień. Tylko moderator.")
    async with pool.acquire() as conn:
        try:
            new_watch = await conn.fetchrow(
                'INSERT INTO "Watch" (brand, model, description, price_pln, status, image_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
                watch.brand, watch.model, watch.description, watch.price_pln, watch.status, watch.image_url
            )
            return dict(new_watch)
        except Exception as e:
            raise HTTPException(status_code=500, detail="Błąd dodawania zegarka do bazy")

@app.delete("/watches/{id}")
async def delete_watch(id: int, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM "Watch" WHERE id = $1', id)
        return {"message": "Zegarek usunięty"}

@app.put("/watches/{id}")
async def update_watch_full(id: int, watch_data: WatchUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    async with pool.acquire() as conn:
        try:
            updated = await conn.fetchrow(
                '''UPDATE "Watch" 
                   SET brand = $1, model = $2, description = $3, price_pln = $4, status = $5, image_url = $6 
                   WHERE id = $7 RETURNING *''',
                watch_data.brand, watch_data.model, watch_data.description, watch_data.price_pln, watch_data.status, watch_data.image_url, id
            )
            if not updated:
                raise HTTPException(status_code=404, detail="Zegarek nie znaleziony")
            return dict(updated)
        except Exception as e:
            print(f"Błąd edycji zegarka: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

@app.patch("/watches/{id}/price")
async def update_watch_price(id: int, price_data: WatchPriceUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    async with pool.acquire() as conn:
        updated = await conn.fetchrow(
            'UPDATE "Watch" SET price_pln = $1 WHERE id = $2 RETURNING *',
            price_data.price_pln, id
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Zegarek nie znaleziony")
        return dict(updated)

@app.patch("/watches/{id}/status")
async def update_watch_status(id: int, status_data: WatchStatusUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    async with pool.acquire() as conn:
        updated = await conn.fetchrow(
            'UPDATE "Watch" SET status = $1 WHERE id = $2 RETURNING *',
            status_data.status, id
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Zegarek nie znaleziony")
        return dict(updated)

@app.patch("/inquiries/{id}/reply")
async def reply_to_inquiry(id: int, reply_data: InquiryReply, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    async with pool.acquire() as conn:
        updated = await conn.fetchrow(
            'UPDATE "Inquiry" SET admin_reply = $1 WHERE id = $2 RETURNING *',
            reply_data.reply, id
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Zapytanie nie znalezione")
        return dict(updated)

@app.get("/users")
async def get_users(current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 4:
        raise HTTPException(status_code=403, detail="Tylko Admin może przeglądać użytkowników")
    async with pool.acquire() as conn:
        try:
            users = await conn.fetch(
                'SELECT u.id, u.email, u.role_id, r.name as role_name FROM "User" u JOIN "Role" r ON u.role_id = r.id ORDER BY u.id ASC'
            )
            return [dict(u) for u in users]
        except Exception as e:
            print(f"Błąd pobierania użytkowników: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

@app.patch("/users/{id}/role")
async def update_user_role(id: int, role_data: UserRoleUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 4:
        raise HTTPException(status_code=403, detail="Tylko Admin może zarządzać uprawnieniami")
    if id == current_user['userId']:
        raise HTTPException(status_code=400, detail="Nie możesz zmienić uprawnień swojemu własnemu kontu")

    async with pool.acquire() as conn:
        try:
            target_user = await conn.fetchrow('SELECT role_id FROM "User" WHERE id = $1', id)
            if not target_user:
                raise HTTPException(status_code=404, detail="Użytkownik nie znaleziony")
            if target_user['role_id'] == 4:
                raise HTTPException(status_code=403, detail="Brak uprawnień. Nie możesz degradować innych administratorów!")

            updated = await conn.fetchrow(
                'UPDATE "User" SET role_id = $1 WHERE id = $2 RETURNING id, email, role_id',
                role_data.role_id, id
            )
            return dict(updated)
        except HTTPException:
            raise
        except Exception as e:
            print(f"Błąd zmiany roli: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych przy zmianie roli")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3001))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)