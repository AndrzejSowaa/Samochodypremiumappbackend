from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncpg
import bcrypt
import os
from dotenv import load_dotenv
import uvicorn
from contextlib import asynccontextmanager

# 1. Ładowanie zmiennych
if os.getenv('RENDER') is None:
    load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("Brak zmiennej środowiskowej DATABASE_URL!")

if "sslmode=require" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL += f"{separator}sslmode=require"

pool = None

# --- FUNKCJA INICJALIZUJĄCA BAZĘ (Seedowanie) ---
async def init_db():
    global pool
    pool = await asyncpg.create_pool(dsn=DATABASE_URL, ssl='require')
    
    async with pool.acquire() as conn:
        # A. Role
        roles = ['Guest', 'Client', 'Manager', 'Admin']
        for role in roles:
            await conn.execute('INSERT INTO "Role" (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', role)
        
        # B. Admin z .env
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if admin_email and admin_password:
            admin_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Admin')
            exists = await conn.fetchval('SELECT id FROM "User" WHERE email = $1', admin_email)
            
            if not exists:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(admin_password.encode('utf-8'), salt).decode('utf-8')
                await conn.execute(
                    'INSERT INTO "User" (email, password_hash, role_id) VALUES ($1, $2, $3)',
                    admin_email, hashed, admin_role_id
                )
                print("✓ Administrator utworzony pomyślnie.")
    print("✓ Baza danych gotowa.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await pool.close()

app = FastAPI(lifespan=lifespan)

# --- MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ENDPOINTY ---
@app.get("/watches")
async def get_watches():
    async with pool.acquire() as conn:
        watches = await conn.fetch('SELECT * FROM "Watch" ORDER BY id ASC')
        return [dict(w) for w in watches]

@app.get("/")
async def root():
    return {"message": "Backend działa!"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)