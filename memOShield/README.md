# memOShield — Otonom Ağ Güvenlik Katmanı

**memOShield**, saldırı algılama, honeypot tuzakları ve gerçek zamanlı tehdit görselleştirmesi sunan **Go ile yazılmış otonom bir ağ güvenlik sistemidir**.

Tek bir Go binary, SQLite veritabanı ve modern web dashboard ile **<50ms tepki süresinde** DoS/DDoS, port taraması ve brute-force saldırılarını tespit edip engeller.

---

## Temel Özellikler

| Özellik | Açıklama |
|---------|----------|
| **IDS (Saldırı Algılama)** | DoS/DDoS, port tarama, kötü User-Agent tespiti |
| **Honeypot** | Sahte FTP/Telnet/MySQL servisleri ile saldırganları tuzağa düşürme |
| **GeoIP İstihbaratı** | Saldırganın ülkesi, ISP'si ve hostname bilgisi |
| **Whitelist** | Güvenilir IP'lerin banlanmasını önler |
| **Real-Time Dashboard** | SSE ile canlı güncellenen tablo, grafikler, harita |
| **Bildirimler** | Telegram ve Slack'e otomatik alert gönderimi |
| **Dinamik Firewall** | Linux iptables ile otomatik IP engelleme |
| **PCAP Kaydı** | Paket yakalama desteği (gopacket/pcap) |

---

## Mimari

```
İnternet / Dış Ağ
       │
┌──────▼──────────────────────┐
│  Go HTTP Sunucu (net/http)  │
│  Port 5000                  │
│                             │
│  ┌─────────────────────┐    │
│  │ IDS Engine          │    │  ← Rate-limit + port scan tespiti
│  │ Honeypot Listeners  │    │  ← Sahte servisler (2121, 2323, 3307)
│  │ Firewall Manager    │    │  ← iptables kural yönetimi
│  │ GeoIP Client        │    │  ← ipapi.co entegrasyonu
│  │ SSE Broadcaster     │    │  ← Gerçek zamanlı olay yayını
│  │ Notifier            │    │  ← Telegram + Slack alertleri
│  └─────────────────────┘    │
│                             │
│  ┌─────────────────────┐    │
│  │ REST API Endpoints  │    │
│  │ Dashboard (HTML)    │    │
│  │ Chart.js + Leaflet  │    │
│  │ SQLite Veritabanı   │    │
│  └─────────────────────┘    │
└─────────────────────────────┘
```

---

## Hızlı Başlangıç

### Gereksinimler

- Go 1.22+
- Git

### Kurulum ve Çalıştırma

```bash
# Klonla
git clone https://github.com/MemoS778/memOShield.git
cd memOShield

# Bağımlılıkları indir
go mod tidy

# Demo verisi oluştur
go run ./cmd/seed

# Sunucuyu başlat
go run .
```

Tarayıcıda: **http://localhost:5000**

### Mock Stream ile Demo

```bash
ENABLE_MOCK_STREAM=1 go run .
```

### Docker

```bash
docker build -t memoshield .
docker run -p 5000:5000 memoshield
```

---

## Proje Yapısı

```
memOShield/
├── main.go                         # Giriş noktası
├── go.mod                          # Go modül tanımı
├── Dockerfile                      # Multi-stage Docker build
├── cmd/
│   └── seed/
│       └── main.go                 # Demo veri oluşturucu
├── internal/
│   ├── broadcaster/broadcaster.go  # SSE fan-out yayıncı
│   ├── config/config.go            # Yapılandırma (env vars)
│   ├── db/db.go                    # SQLite veritabanı
│   ├── firewall/firewall.go        # Firewall kural yönetimi
│   ├── geoip/geoip.go              # GeoIP istemcisi
│   ├── honeypot/honeypot.go        # Honeypot sunucuları
│   ├── ids/ids.go                  # Saldırı tespit motoru
│   ├── mockstream/mockstream.go    # Mock olay üreticisi
│   ├── notifier/notifier.go        # Telegram/Slack bildirim
│   ├── pcap/pcap.go                # PCAP kaydedici
│   ├── web/handlers.go             # HTTP handler'lar + API
│   └── whitelist/whitelist.go      # IP whitelist
├── static/
│   ├── css/style.css               # Dashboard tema
│   ├── js/app.js                   # SIEM dashboard JS
│   ├── js/landing.js               # Landing page JS
│   └── img/                        # Logo ve favicon
├── templates/
│   ├── base.html                   # Temel layout
│   ├── dashboard.html              # SIEM dashboard
│   ├── index.html                  # Landing sayfası
│   └── login.html                  # Giriş sayfası
└── docs/
    └── deployment.md               # Dağıtım rehberi
```

---

## API Endpoints

| Endpoint | Metot | Açıklama |
|----------|-------|----------|
| `/api/events` | GET | Son 200 güvenlik olayı |
| `/api/events/clear` | POST | Olay geçmişini temizle `{days}` (0 = hepsi) |
| `/api/bans` | GET | Engellenen IP listesi |
| `/api/rules` | GET | Firewall kuralları |
| `/api/ban` | POST | IP engelle `{ip, reason}` |
| `/api/unban` | POST | IP ban kaldır `{ip}` |
| `/api/lookup/:ip` | GET | IP istihbarat sorgulama |
| `/api/record` | POST | Paket kaydet `{ip}` |
| `/api/stats` | GET | Toplu istatistikler (saldırı türleri, ülkeler, saatlik dağılım) |
| `/api/health` | GET | Sistem sağlık durumu ve uptime |
| `/api/whitelist` | GET | Whitelist listesi |
| `/api/whitelist/add` | POST | Whitelist'e IP ekle `{ip}` |
| `/api/whitelist/remove` | POST | Whitelist'ten IP kaldır `{ip}` |
| `/api/honeypot-status` | GET | Honeypot durumu |
| `/stream` | GET | SSE gerçek zamanlı akış |

---

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `PORT` | `5000` | HTTP sunucu portu |
| `ADMIN_PASSWORD` | `admin` | Yönetici şifresi |
| `FLASK_SECRET` | `change-this-secret` | Cookie imzalama anahtarı |
| `ENABLE_MOCK_STREAM` | `0` | Mock olay akışı (`1` = aktif) |
| `MOCK_STREAM_INTERVAL` | `3` | Mock akış aralığı (saniye) |
| `MOCK_STREAM_MODE` | `steady` | `steady` / `burst` / `random` |
| `TELEGRAM_BOT_TOKEN` | - | Telegram bot token |
| `TELEGRAM_CHAT_ID` | - | Telegram chat ID |
| `SLACK_WEBHOOK` | - | Slack webhook URL |
| `GEOIP_URL` | `https://ipapi.co/%s/json/` | GeoIP API URL |
| `IDS_THRESHOLD` | `300` | IDS rate-limit eşiği (paket/pencere) |
| `IDS_WINDOW_SECONDS` | `10` | IDS pencere süresi (saniye) |
| `IDS_BAN_DURATION_SECONDS` | `600` | IDS ban süresi (saniye) |
| `IDS_PORT_THRESHOLD` | `80` | Port tarama eşiği |
| `IDS_UA_RULES` | `sqlmap,nikto,nmap,...` | Kötü User-Agent kuralları (virgülle ayrılmış) |
| `WAF_ENABLED` | `false` | WAF middleware'i aktif/pasif yapar |
| `UA_BLOCK_ENABLED` | `false` | Saldırı aracı User-Agent bloklamasını aktif/pasif yapar |
| `IP_REPUTATION_AUTOBAN` | `false` | IP reputation skoruna göre otomatik ban |
| `MAX_ADMIN_SESSIONS` | `10` | Eşzamanlı admin oturum limiti |
| `SESSION_MAX_AGE` | `86400` | Oturum çerezi ömrü (saniye) |
| `LOGIN_RATE_LIMIT_ENABLED` | `false` | Login denemelerinde rate limit kontrolü |
| `LOGIN_LOCKOUT_ENABLED` | `false` | Çoklu hatalı girişte IP lockout |
| `LOGIN_CSRF_ENABLED` | `false` | Login formunda CSRF token zorunluluğu |
| `LOGIN_HONEYPOT_ENABLED` | `false` | Login honeypot bot tespiti |

---

## Teknolojiler

- **Go 1.22+** — Backend, HTTP sunucu, tüm iş mantığı
- **SQLite** — Veritabanı (modernc.org/sqlite, pure Go, CGO gerektirmez)
- **HTML/CSS/JS** — Dashboard (Chart.js, Leaflet.js)
- **SSE** — Gerçek zamanlı olay akışı
- **iptables** — Linux firewall entegrasyonu

---

## Lisans

MIT License — 2026 memOShield

