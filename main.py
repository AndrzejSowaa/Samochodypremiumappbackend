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

# DB_CONFIG = {
#    'user': 'postgres',
#    'password': 'puchatek123',
#     'database': 'dbwatch',
#     'host': 'localhost',
#     'port': 5432
# }

# JWT_SECRET = os.getenv('JWT_SECRET', 'tajny_klucz_do_zegarkow_123')
# ALGORITHM = "HS256"

security = HTTPBearer()
pool = None

load_dotenv()

# TYMCZASOWO - wklejamy dane bezpośrednio z panelu bazy
DB_CONFIG = {
    'user': 'moje_auto_db_user',
    'password': 'w8Ae5ozeNj04ym8Y09aJKCBi5Z05ZS8R',
    'database': 'moje_auto_db',
    'host': 'dpg-d8glcsek1jcs73d4mfp0-a.frankfurt-postgres.render.com',
    'port': 5432,
    'ssl': 'require'
}

JWT_SECRET = os.getenv('JWT_SECRET', 'awaryjny_klucz_jesli_brak_env')
ALGORITHM = "HS256"

# Zarządzanie cyklem życia aplikacji 
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(**DB_CONFIG)
    yield
    await pool.close()

app = FastAPI(lifespan=lifespan)

# NAPRAWA 1: Dokładny adres Reacta zamiast gwiazdki "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NAPRAWA 3: Dodanie brakujących nagłówków bezpieczeństwa
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

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

class WatchPriceUpdate(BaseModel):
    price_pln: float

class WatchStatusUpdate(BaseModel):
    status: str

# NAPRAWA 2: Bezpieczne funkcje szyfrujące (bez passlib)
def get_password_hash(password: str) -> str:
    # Generujemy sól i szyfrujemy hasło
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  # Zwracamy jako tekst do bazy

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except ValueError:
        return False

# Middleware do sprawdzania tokenów
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Token wygasł lub jest nieprawidłowy")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Token wygasł lub jest nieprawidłowy")

# Rejestracja
@app.post("/auth/register", status_code=201)
async def register(user_data: UserAuth):
    async with pool.acquire() as conn:
        # 1. Sprawdź, czy użytkownik już istnieje
        user_exists = await conn.fetchval('SELECT id FROM "User" WHERE email = $1', user_data.email)
        if user_exists:
            raise HTTPException(status_code=409, detail="Użytkownik o tym e-mailu już istnieje")

        # 2. Znajdź ID dla roli "Client"
        client_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Client')
        if not client_role_id:
            raise HTTPException(status_code=500, detail="Błąd serwera: Brak roli Client")

        # 3. Zaszyfruj hasło
        hashed_password = get_password_hash(user_data.password)

        # 4. Zapisz użytkownika w bazie
        try:
            new_user = await conn.fetchrow(
                'INSERT INTO "User" (email, password_hash, role_id) VALUES ($1, $2, $3) RETURNING id, email, role_id',
                user_data.email, hashed_password, client_role_id
            )
            return {"message": "Rejestracja zakończona sukcesem", "user": dict(new_user)}
        except Exception as e:
            print(f"Błąd rejestracji: {e}")
            raise HTTPException(status_code=500, detail="Błąd serwera podczas rejestracji")

# Logowanie
@app.post("/auth/login")
async def login(user_data: UserAuth):
    async with pool.acquire() as conn:
        try:
            # 1. Znajdź użytkownika
            user = await conn.fetchrow('SELECT * FROM "User" WHERE email = $1', user_data.email)
            
            # 2. Porównaj hasła
            if not user or not verify_password(user_data.password, user['password_hash']):
                raise HTTPException(status_code=401, detail="Nieprawidłowy e-mail lub hasło")

            # 3. Generuj token
            expire = datetime.now(timezone.utc) + timedelta(hours=24)
            to_encode = {"userId": user['id'], "roleId": user['role_id'], "email": user['email'], "exp": expire}
            token = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

            return {"message": "Zalogowano pomyślnie", "token": token, "roleId": user['role_id']}
        except HTTPException:
            raise
        except Exception as e:
            print(f"Błąd logowania: {e}")
            raise HTTPException(status_code=500, detail="Błąd serwera podczas logowania")

# Pobierz wszystkie zegarki
@app.get("/watches")
async def get_watches():
    async with pool.acquire() as conn:
        try:
            watches = await conn.fetch('SELECT * FROM "Watch" ORDER BY id ASC')
            return [dict(w) for w in watches]
        except Exception as e:
            print(f"Błąd bazy danych: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

# Pobierz jeden zegarek po ID
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

# Dodaj nowe zapytanie
@app.post("/inquiries")
async def create_inquiry(inquiry: InquiryCreate, current_user: dict = Depends(get_current_user)):
    user_id = current_user['userId']
    
    async with pool.acquire() as conn:
        try:
            new_inquiry = await conn.fetchrow(
                'INSERT INTO "Inquiry" (user_id, watch_id, message) VALUES ($1, $2, $3) RETURNING *',
                user_id, inquiry.watch_id, inquiry.message
            )

            # AuditLog
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

# Pobierz zapytania
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

# Dodaj nowy zegarek
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

# Usuń zegarek
@app.delete("/watches/{id}")
async def delete_watch(id: int, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 3:
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM "Watch" WHERE id = $1', id)
        return {"message": "Zegarek usunięty"}

# Pełna edycja zegarka
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

# Zmień cenę zegarka
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

# Zmień status zegarka
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

# Odpowiedz na zapytanie klienta
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

# Pobierz listę wszystkich użytkowników
@app.get("/users")
async def get_users(current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 4:
        raise HTTPException(status_code=403, detail="Tylko Admin może przeglądać użytkowników")
    
    async with pool.acquire() as conn:
        try:
            # Łączymy tabele User i Role, żeby od razu wiedzieć, jak nazywa się rola
            users = await conn.fetch(
                'SELECT u.id, u.email, u.role_id, r.name as role_name FROM "User" u JOIN "Role" r ON u.role_id = r.id ORDER BY u.id ASC'
            )
            return [dict(u) for u in users]
        except Exception as e:
            print(f"Błąd pobierania użytkowników: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych")

# Zmień rolę użytkownika
@app.patch("/users/{id}/role")
async def update_user_role(id: int, role_data: UserRoleUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['roleId'] < 4:
        raise HTTPException(status_code=403, detail="Tylko Admin może zarządzać uprawnieniami")
    
    # Blokada 1: Nie można zmienić uprawnień samemu sobie
    if id == current_user['userId']:
        raise HTTPException(status_code=400, detail="Nie możesz zmienić uprawnień swojemu własnemu kontu")

    async with pool.acquire() as conn:
        try:
            # Pobieramy obecne dane użytkownika, którego próbujemy zmienić
            target_user = await conn.fetchrow('SELECT role_id FROM "User" WHERE id = $1', id)
            
            if not target_user:
                raise HTTPException(status_code=404, detail="Użytkownik nie znaleziony")
            
            # Blokada 2: Admin nie może zdegradować INNEGO Admina
            if target_user['role_id'] == 4:
                raise HTTPException(status_code=403, detail="Brak uprawnień. Nie możesz degradować innych administratorów!")

            updated = await conn.fetchrow(
                'UPDATE "User" SET role_id = $1 WHERE id = $2 RETURNING id, email, role_id',
                role_data.role_id, id
            )
            return dict(updated)
        except HTTPException:
            raise # Pozwala błędom HTTP przejść dalej
        except Exception as e:
            print(f"Błąd zmiany roli: {e}")
            raise HTTPException(status_code=500, detail="Błąd bazy danych przy zmianie roli")

if __name__ == "__main__":
    import uvicorn
    print("✓ Serwer gotowy do uruchomienia na porcie 3001")
    uvicorn.run("main:app", host="127.0.0.1", port=3001, reload=True)