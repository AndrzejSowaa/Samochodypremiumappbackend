from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta, timezone
import asyncpg
import bcrypt
import jwt
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

if os.getenv('RENDER') is None:
    load_dotenv()

# Pobieramy pełny adres bazy danych
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("Brak zmiennej środowiskowej DATABASE_URL!")

# UWAGA: asyncpg w nowszych wersjach bardzo dobrze radzi sobie z formatem postgres://
# Nie musimy ręcznie zmieniać "postgres://" na "postgresql://"
# Render wymaga ssl=require w parametrach połączenia

# Dodajemy sslmode=require tylko jeśli go nie ma
if "sslmode=require" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL += f"{separator}sslmode=require"

# Zarządzanie pulą
pool = None

async def init_db_pool():
    global pool
    # Kluczowe: przekazujemy dsn oraz jawne ssl='require' dla asyncpg
    pool = await asyncpg.create_pool(dsn=DATABASE_URL, ssl='require')

# W main.py w lifespan:
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db_pool()
    yield
    await pool.close()
app = FastAPI(lifespan=lifespan)

# --- MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Zmień na konkretne domeny w produkcji
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- FUNKCJE POMOCNICZE ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# --- ENDPOINTY (ZACHOWANE) ---
# (Tutaj wstawiasz swoje pozostałe funkcje register/login/watches tak jak miałeś)

if __name__ == "__main__":
    import uvicorn
    # Port 8080 jest preferowany przez Render, 3001 zostaw tylko dla lokalnego testu
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)