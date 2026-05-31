import asyncio
import os
import asyncpg
import bcrypt
from dotenv import load_dotenv

# Wczytujemy zmienne z pliku .env
load_dotenv()

async def seed_database():
    print("Rozpoczynam seedowanie bazy danych...")
    
    # Nawiązanie połączenia
    conn = await asyncpg.connect(
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT')
    )

    try:
        # 1. Upewniamy się, że podstawowe role istnieją w bazie
        roles = ['Guest', 'Client', 'Manager', 'Admin']
        for role in roles:
            await conn.execute(
                'INSERT INTO "Role" (name) VALUES ($1) ON CONFLICT (name) DO NOTHING',
                role
            )
        print("✓ Role sprawdzone/utworzone.")

        # 2. Pobieramy ID roli Admin
        admin_role_id = await conn.fetchval('SELECT id FROM "Role" WHERE name = $1', 'Admin')

        # 3. Sprawdzamy, czy admin z pliku .env już istnieje
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')

        exists = await conn.fetchval('SELECT id FROM "User" WHERE email = $1', admin_email)

        if exists:
            print(f"✓ Główny administrator ({admin_email}) już istnieje w bazie. Pomijam.")
        else:
            # Szyfrujemy hasło z pliku .env i tworzymy admina
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), salt).decode('utf-8')

            await conn.execute(
                'INSERT INTO "User" (email, password_hash, role_id) VALUES ($1, $2, $3)',
                admin_email, hashed_password, admin_role_id
            )
            print(f"✓ Główny administrator ({admin_email}) został pomyślnie utworzony!")

    except Exception as e:
        print(f" Wystąpił błąd podczas seedowania: {e}")
    finally:
        await conn.close()
        print("Seedowanie zakończone.")

if __name__ == "__main__":
    asyncio.run(seed_database())