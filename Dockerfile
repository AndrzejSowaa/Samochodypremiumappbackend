FROM python:3.12-slim

WORKDIR /app

# Kopiujemy i instalujemy zależności
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy resztę kodu źródłowego aplikacji
COPY . .

# Uruchamiamy FastAPI na porcie 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]