# Wybieramy lekki obraz Pythona
FROM python:3.12-slim

# Ustawiamy katalog roboczy
WORKDIR /app

# Instalujemy zależności (kopiujemy tylko requirements.txt, żeby przyspieszyć budowanie)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy resztę kodu
COPY . .

# Informujemy Render, na jakim porcie działa aplikacja
EXPOSE 8080

# Uruchamiamy aplikację
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]