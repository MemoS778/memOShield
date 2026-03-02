import random
import datetime
from memoshield.db import log_event, get_events, add_ban

ATTACK_TYPES = [
    'Honeypot Trigger', 'Port Scan', 'DoS/DDoS', 'Brute Force', 'SQL Injection', 'XSS'
]

ATTACK_DETAILS = {
    'Honeypot Trigger': [
        'FTP honeypot (port 2121) bağlantı denemesi',
        'SSH honeypot (port 2222) kimlik doğrulama denemesi',
        'Telnet honeypot (port 2323) erişim girişimi',
        'MySQL honeypot (port 3307) sorgu denemesi',
    ],
    'Port Scan': [
        'TCP SYN taraması — port 22,80,443,8080',
        'Nmap agresif tarama tespit edildi — 1024 port',
        'UDP port taraması — DNS, SNMP, NTP',
        'Stealth FIN taraması — port 21-1024',
    ],
    'DoS/DDoS': [
        'SYN flood saldırısı — 15.000 paket/sn',
        'HTTP GET flood — 8.400 istek/dk',
        'UDP amplification saldırısı tespit edildi',
        'Slowloris bağlantı tükenmesi — 500 yarı-açık bağlantı',
    ],
    'Brute Force': [
        'SSH brute force — 120 başarısız deneme',
        'FTP brute force — wordlist saldırısı',
        'HTTP Basic Auth brute force — admin panel',
        'RDP brute force denemesi — 50 deneme/dk',
    ],
    'SQL Injection': [
        "Payload: ' OR 1=1 -- ",
        "Payload: UNION SELECT username,password FROM users",
        "Blind SQL injection — time-based: SLEEP(5)",
        "Payload: '; DROP TABLE users; --",
    ],
    'XSS': [
        'Reflected XSS: <script>alert(document.cookie)</script>',
        'Stored XSS denemesi — yorum alanında payload',
        'DOM-based XSS — URL hash manipülasyonu',
        'SVG onload XSS: <svg onload=alert(1)>',
    ],
}

SAMPLE_COUNTRIES = [
    ('ABD', 37.7749, -122.4194),
    ('ABD', 40.7128, -74.0060),
    ('Türkiye', 39.9255, 32.8663),
    ('Türkiye', 41.0082, 28.9784),
    ('Almanya', 52.52, 13.405),
    ('Almanya', 48.1351, 11.582),
    ('Rusya', 55.7558, 37.6173),
    ('Rusya', 59.9343, 30.3351),
    ('Çin', 39.9042, 116.4074),
    ('Çin', 31.2304, 121.4737),
    ('Brezilya', -23.5505, -46.6333),
    ('Hindistan', 28.6139, 77.2090),
    ('Hindistan', 19.076, 72.8777),
    ('Hollanda', 52.3676, 4.9041),
    ('Japonya', 35.6762, 139.6503),
    ('Güney Kore', 37.5665, 126.978),
    ('İngiltere', 51.5074, -0.1278),
    ('Fransa', 48.8566, 2.3522),
    ('Avustralya', -33.8688, 151.2093),
    ('Kanada', 43.6532, -79.3832),
    ('İran', 35.6892, 51.3890),
    ('Ukrayna', 50.4501, 30.5234),
]

KNOWN_IPS = [
    '185.220.101.42', '203.0.113.5', '198.51.100.77', '45.33.32.156',
    '103.21.244.0', '91.219.236.18', '77.247.181.163', '176.10.99.200',
    '85.214.132.117', '162.247.74.7', '23.129.64.100', '51.15.43.205',
    '104.244.76.13', '209.141.58.146', '178.20.55.16', '185.107.47.215',
]


def random_ip():
    if random.random() < 0.3 and KNOWN_IPS:
        return random.choice(KNOWN_IPS)
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))


def seed(n=80):
    """n adet gerçekçi demo olay oluştur."""
    now = datetime.datetime.utcnow()
    print(f"Seeding {n} mock events...")

    for i in range(n):
        ip = random_ip()
        country, lat, lon = random.choice(SAMPLE_COUNTRIES)
        attack = random.choice(ATTACK_TYPES)
        details = random.choice(ATTACK_DETAILS[attack])
        # Olayları son 30 dakikaya yay
        offset = random.randint(0, 1800)
        timestamp = (now - datetime.timedelta(seconds=offset)).isoformat()

        log_event(
            ip, country, attack, details,
            lat=lat + random.uniform(-0.5, 0.5),
            lon=lon + random.uniform(-0.5, 0.5)
        )

    # Birkaç ban ekle
    ban_ips = random.sample(KNOWN_IPS, min(5, len(KNOWN_IPS)))
    ban_reasons = ['Port Scan saldırısı', 'DDoS tespit edildi', 'Honeypot tetiklendi', 'Brute force', 'SQL Injection']
    for ip, reason in zip(ban_ips, ban_reasons):
        add_ban(ip, reason)

    print(f"Seeded {n} events + {len(ban_ips)} bans.")


if __name__ == '__main__':
    seed(80)
    events = get_events(10)
    print('\nLatest 10 events:')
    for e in events[:10]:
        print(f"  {e['timestamp']}  {e['src_ip']:16s}  {e['country']:12s}  {e['attack_type']}")

