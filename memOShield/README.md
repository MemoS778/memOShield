# memOShield — Otonom Ağ Güvenlik Katmanı

**memOShield**, basit bir güvenlik duvarı olmanın ötesinde, hem savunma hem de analiz yeteneklerini birleştiren **Otonom bir Ağ Güvenlik Katmanı**'dır.

Temel felsefesi: **Saldırganı sadece engellemek değil, onu tanımak, tuzağa düşürmek ve hakkında istihbarat toplamak.**

Geleneksel firewall'lar statiktir — sadece senin tanımladığın kuralları uygular. memOShield ise **dinamiktir**; saldırganın hareketlerini analiz eder ve kendi kararını vererek savunma hattını günceller. Golang (paket motoru) + Python (dashboard & IDS) hibrit mimarisiyle yazılmış, **50ms tepki süresi** ile DoS/DDoS, port taraması ve brute-force saldırılarını yakalar.

---

## Temel Özellikler

| Özellik | Açıklama |
|---------|----------|
| **IDS (Saldırı Algılama)** | DoS/DDoS, port tarama, kötü User-Agent tespiti |
| **Honeypot** | Sahte FTP/SSH/MySQL servisleri ile saldırganları tuzağa düşürme |
| **Tehdit İstihbaratı (GeoIP)** | Saldırganın ülkesi, ISP'si (Türk Telekom, AWS vb.) ve hostname'ini belirler |
| **Whitelist** | Güvenilir IP'lerin banlanmasını önler |
| **Real-Time Dashboard** | SSE ile canlı güncellenen olay tablosu, grafikler, harita |
| **Bildirimler** | Telegram ve Slack'e otomatik alert gönderimi |
| **Forensics** | PCAP kaydı + PDF raporlama |
| **Token Auth + TLS** | Hizmetler arası güvenli iletişim |

---

## Mimari

```
İnternet / Dış Ağ
       │
┌──────▼──────────────┐
│  Go Core Engine     │  ← Paket yakalama (gopacket/pcap)
│  (port 9000)        │  ← DoS + Port-scan tespiti
└──────┬──────────────┘
       │ HTTP POST /ingest
┌──────▼──────────────┐
│  Go Engine (SSE)    │  ← Real-time olay yayınlama
│  (port 8081)        │  ← Token auth + TLS
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│  Flask App (5000)   │  ← Dashboard, API, Honeypot, IDS
│  + Leaflet Harita   │  ← Chart.js grafikleri
│  + Dark Theme UI    │  ← SSE canlı akış
└─────────────────────┘
```

---

## Kullanım Senaryosu — Bir Saldırı Nasıl Yakalanır?

```
1. KEŞIF      Saldırgan, sunucundaki açık portları taramaya başlar.
2. TUZAK      memOShield'ın Honeypot'una (sahte FTP/MySQL portu) dokunur.
3. İSTİHBARAT  Go Core anında IP'yi yakalar → GeoIP ile ülke, ISP, hostname bulunur.
4. İMHA       Sistem <50ms içinde iptables kuralı ekler → IP "kapıda" engellenir.
5. KAYIT      Tüm süreç DB'ye yazılır, Dashboard'da alarm grafiği belirir,
              Telegram/Slack'e alert gönderilir, PCAP kaydı forensics'e hazır.
```

Saldırgan daha sistemi keşfedemeden banlanmıştır. Gerçek servislere hiç ulaşamamıştır.

---

## memOShield'ın Farkı

Piyasadaki birçok firewall sadece trafiği izler ve sabit kurallar uygular. memOShield ise:

| Klasik Firewall | memOShield |
|----------------|------------|
| Statik kurallar | **Dinamik karar verme** — davranış analizi ile otomatik ban |
| Sadece engelleme | **Aldatma** — Honeypot ile saldırganı tuzağa düşürür |
| IP log'u tutar | **İstihbarat** — ISP, hostname, ülke bilgisi çıkarır |
| Manuel raporlama | **Otomatik raporlama** — PDF + canlı dashboard + alert |
| Tek dil | **Hibrit mimari** — Go (performans) + Python (esneklik) |

---

## Nasıl Çalışır

memOShield üç katmanlı bir güvenlik hattı oluşturur. Her katman bağımsız çalışabilir, birlikte kullanıldığında tam koruma sağlar.

### 1. Paket Yakalama (Go Core — `core/main.go`)

```
Ağ trafiği → gopacket/pcap ile dinleme → Her paketin kaynak IP'si çıkarılır
```

- Linux kernel seviyesinde `AF_PACKET` / `pcap` ile **ham paketleri** yakalar
- Her paket için kaynak IP, hedef port ve protokol bilgisini çıkarır
- **Kayan pencere** (sliding window) algoritması ile her IP'nin davranışını izler:
  - Saniyede 200+ paket → **DoS/DDoS** olarak işaretler
  - 10 saniyede 20+ farklı port → **Port taraması** olarak işaretler
- Tehdit tespit edildiğinde Go Engine'e HTTP POST ile bildirir

### 2. Olay Dağıtımı (Go Engine — `go-engine/`)

```
Core Engine → POST /ingest → Go Engine → SSE broadcast → Dashboard
```

- Gelen olayları alır, **Bearer token** ile doğrulama yapar
- **SSE (Server-Sent Events)** ile tüm bağlı dashboard'lara anında yayınlar
- `/ban` endpoint'i ile IP engelleme komutları alır
- Binlerce eşzamanlı SSE istemcisini düşük bellek kullanımıyla destekler

### 3. Dashboard & Koruma (Flask App — `app.py` + `memoshield/`)

Flask uygulaması hem kullanıcı arayüzünü hem de arka plan koruma servislerini çalıştırır:

#### IDS Modülü (`ids.py`)
```
Gelen paket → IP kuyruğuna ekle → Eşik aşıldı mı? → Evet: Ban + Log + Alert
```
- Her IP için zaman damgalı kuyruk tutar
- Eşik aşılınca: Firewall kuralı ekler, veritabanına yazar, bildirimi tetikler
- **Whitelist** kontrolü: Güvenilir IP'ler IDS'den muaf tutulur

#### Honeypot Modülü (`honeypot.py`)
```
Sahte portlar (2121, 2323, 3307) dinleniyor → Bağlantı geldi → IP anında banlandı
```
- Sahte FTP (2121), Telnet (2323) ve MySQL (3307) servisleri açar
- Bağlanan IP anında kaydedilir, GeoIP ile ülkesi belirlenir ve **kalıcı olarak engellenir**
- Gerçek servislere hiç ulaşılamaz — saldırgan tuzağa düşer

#### Firewall Modülü (`firewall.py`)
```
Ban komutu → SQLite'a kaydet → Linux'ta iptables kuralı uygula
```
- Windows'ta simülasyon (yalnızca DB kaydı)
- Linux'ta `iptables -A INPUT -s <IP> -j DROP` ile gerçek engelleme
- Tüm kurallar veritabanında tutulur → restart sonrası kaybolmaz

#### Bildirim Akışı
```
Kritik olay → Notifier → Telegram Bot API / Slack Webhook
```

#### Forensics
```
Paketler → PCAP dosyasına kayıt → Sonradan Wireshark ile analiz
Olaylar → PDF raporu üretimi → Yönetim sunumu
```

### Tüm Akış (Uçtan Uca)

```
Saldırgan IP → Ağ trafiği
       │
       ▼
  Go Core Engine           ← pcap ile paket yakalama
  (saniyede 200+ paket?)
       │ Evet
       ▼
  Go Engine /ingest        ← Olay kaydı + SSE yayını
       │
       ├──▶ Dashboard      ← Harita + grafikler anında güncellenir
       ├──▶ Firewall       ← iptables DROP kuralı eklenir
       ├──▶ Notifier       ← Telegram/Slack alert gönderilir
       ├──▶ SQLite DB      ← Olay kalıcı olarak kaydedilir
       └──▶ PCAP Recorder  ← Paketler dosyaya yazılır

Tüm süre: ~50ms (algılama → engelleme)
```

---

## Proje Yapısı

```
memOShield/
├── app.py                  # Flask ana uygulama (port 5000)
├── requirements.txt        # Python bağımlılıkları
├── Dockerfile              # Flask container
├── memoshield/             # Python çekirdek modüller
│   ├── db.py               #   SQLite event logging
│   ├── firewall.py         #   iptables/nftables arayüzü
│   ├── ids.py              #   IDS kuralları (DoS, port-scan, UA)
│   ├── honeypot.py         #   Honeypot yöneticisi
│   ├── geoip.py            #   GeoIP lookup
│   ├── whitelist.py        #   IP whitelist
│   ├── notifier.py         #   Telegram/Slack alerts
│   ├── pcap_recorder.py    #   PCAP kaydı
│   ├── broadcaster.py      #   SSE broadcast
│   └── mock_stream.py      #   Demo mock data
├── go-engine/              # Go SSE broker servisi
│   ├── main.go             #   HTTP sunucu + /ban, /ingest
│   ├── engine.go           #   SSE broker implementasyonu
│   └── Dockerfile          #   Go engine container
├── core/                   # Go paket yakalama motoru
│   └── main.go             #   gopacket/pcap ile trafik dinleme
├── templates/              # Jinja2 HTML şablonları
│   ├── index.html          #   Landing page
│   ├── dashboard.html      #   Real-time dashboard
│   ├── login.html          #   Admin giriş
│   └── base.html           #   Temel layout
├── static/                 # Statik dosyalar
│   ├── css/style.css       #   Dark theme
│   ├── js/app.js           #   SSE client + Chart.js + Leaflet
│   └── img/                #   Logo, favicon
├── reports/
│   └── pdf_report.py       # PDF raporlama
├── tools/
│   └── seed_mock_events.py # Mock veri üretici
├── docs/
│   └── deployment.md       # Ubuntu/systemd kurulum
├── test.ps1                # Windows test scripti
├── test.sh                 # Linux test scripti
└── test_docker.sh          # Docker test scripti
```

---

## Hızlı Başlangıç

### Windows

```powershell
cd memOShield
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

### Linux / Ubuntu

```bash
sudo apt install python3-venv libpcap-dev
cd memOShield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Docker

```bash
docker build -t memoshield:latest .
docker run -e ADMIN_PASSWORD=changeme -p 5000:5000 memoshield:latest
```

Tarayıcıda aç:
- `http://127.0.0.1:5000` → Landing page
- `http://127.0.0.1:5000/demo` → Demo dashboard (şifresiz)
- `http://127.0.0.1:5000/login` → Admin giriş (varsayılan şifre: `admin`)

---

## Test

### Otomatik Test Scriptleri

```powershell
# Windows
.\test.ps1

# Linux
bash test.sh

# Docker
bash test_docker.sh
```

Test scriptleri şunları kontrol eder:
1. Python / venv kurulumu
2. Bağımlılık yükleme
3. Database başlatma
4. Tüm modül testleri (firewall, geoip, ids, whitelist, honeypot)
5. Flask app yükleme
6. API endpoint testleri (test.sh)

### Manuel API Testi

```bash
# Olayları listele
curl http://127.0.0.1:5000/api/events

# Admin girişi
curl -c cookies.txt -X POST http://127.0.0.1:5000/login -d "password=admin"

# IP banla
curl -b cookies.txt -X POST http://127.0.0.1:5000/api/ban \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.1","reason":"test"}'
```

---

## Go Engine (Opsiyonel)

Go engine, yüksek performanslı paket işleme ve SSE yayını sağlar.

### SSE Broker (go-engine/)

```bash
cd go-engine
go build -o memoengine .
export AUTH_TOKEN="s3cr3t"
./memoengine    # → :8081 portunda dinler
```

### Paket Yakalama Motoru (core/)

```bash
cd core
go build -o core .
export ENGINE_TOKEN="s3cr3t"
sudo ./core -iface eth0 -engine http://127.0.0.1:8081/ingest -rate 200
```

---

## Production Deployment (Ubuntu)

Detaylı kurulum: [docs/deployment.md](docs/deployment.md)

```bash
# Kısa özet
sudo apt install python3-venv libpcap-dev golang-go
cd /opt/memOShield
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Go engine
cd go-engine && go build -o memoengine .
sudo cp memoengine /usr/local/bin/

# systemd ile başlat
sudo systemctl enable memoshield-go memoshield-python
sudo systemctl start memoshield-go memoshield-python
```

---

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `ADMIN_PASSWORD` | `admin` | Dashboard admin şifresi |
| `FLASK_SECRET` | `change-this-secret` | Flask session key |
| `AUTH_TOKEN` | _(boş)_ | Go engine hizmet arası token |
| `ENGINE_TOKEN` | _(boş)_ | Core → Go engine token |
| `TLS_CERT` / `TLS_KEY` | _(boş)_ | TLS sertifika yolları |
| `ENABLE_MOCK_STREAM` | `0` | Demo mock data akışı |
| `TELEGRAM_BOT_TOKEN` | _(boş)_ | Telegram bildirim token'ı |
| `SLACK_WEBHOOK_URL` | _(boş)_ | Slack webhook URL'i |

---

## Teknoloji Stack

| Katman | Teknoloji |
|--------|-----------|
| Backend | Python 3.10+, Flask |
| Paket Motoru | Go, gopacket/pcap |
| SSE Broker | Go (go-engine) |
| Veritabanı | SQLite |
| Frontend | HTML5, CSS3, Vanilla JS |
| Görselleştirme | Chart.js, Leaflet.js |
| Bildirim | Telegram Bot API, Slack Webhooks |
| Deployment | Docker, systemd, gunicorn |
| Güvenlik | Bearer Token, TLS/mTLS |

---

## Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| `Python not found` | Python 3.10+ kur: https://www.python.org |
| Port 5000 meşgul | `lsof -i :5000` ile kontrol et |
| PCAP hatası (Windows) | Npcap kur: https://npcap.com |
| Go engine permission denied | `sudo setcap cap_net_raw=ep ./memoengine` |
| Sayfa boş/çirkin | Ctrl+F5 ile hard refresh |

---

**memOShield** — Saldırganı engelleyen, aldatan, fişleyen ve raporlayan otonom ağ güvenlik sistemi.

