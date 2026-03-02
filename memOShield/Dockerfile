FROM python:3.13-slim

LABEL maintainer="memOShield" \
      description="memOShield — Otonom Ağ Güvenlik Sistemi"

WORKDIR /app

# Bağımlılıkları önce kopyala (layer cache)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY app.py ./
COPY memoshield/ ./memoshield/
COPY static/ ./static/
COPY templates/ ./templates/
COPY tools/ ./tools/
COPY reports/ ./reports/

# Ortam değişkenleri
ENV FLASK_ENV=production \
    ENABLE_MOCK_STREAM=1 \
    MOCK_STREAM_INTERVAL=4 \
    ADMIN_PASSWORD=admin

# Demo verisi oluştur
RUN python -m tools.seed_mock_events

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/events')" || exit 1

CMD ["python", "app.py"]