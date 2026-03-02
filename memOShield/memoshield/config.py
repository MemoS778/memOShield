from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / 'memoshield.db'

# IDS thresholds
IDS = {
    'threshold': 100,
    'window_seconds': 10,
    'ban_duration_seconds': 3600
}

# Honeypot (geliştirme ortamı için yüksek portlar)
HONEYPOT_PORTS = [2121, 2323, 3307]

# GeoIP service (ipapi.co returns country, ISP, org, hostname)
GEOIP_URL = 'https://ipapi.co/{ip}/json/'
