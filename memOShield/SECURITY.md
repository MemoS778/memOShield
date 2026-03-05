# memOShield — Güvenlik Protokolleri Dokümantasyonu

> **Versiyon:** 2.0  
> **Son Güncelleme:** Mart 2026  
> **Toplam Güvenlik Bileşeni:** 28

---

## İçindekiler

1. [Genel Bakış](#1-genel-bakış)
2. [Ağ Katmanı Güvenliği](#2-ağ-katmanı-güvenliği)
3. [Web Application Firewall (WAF)](#3-web-application-firewall-waf)
4. [Kimlik Doğrulama & Yetkilendirme](#4-kimlik-doğrulama--yetkilendirme)
5. [Oturum Güvenliği](#5-oturum-güvenliği)
6. [Saldırı Tespit & Engelleme](#6-saldırı-tespit--engelleme)
7. [HTTP Güvenlik Katmanı](#7-http-güvenlik-katmanı)
8. [Veri Güvenliği & Doğrulama](#8-veri-güvenliği--doğrulama)
9. [İzleme & Denetim](#9-izleme--denetim)
10. [Yapılandırma Referansı](#10-yapılandırma-referansı)
11. [Güvenlik Mimarisi Diyagramı](#11-güvenlik-mimarisi-diyagramı)
12. [Güvenlik Skoru](#12-güvenlik-skoru)
13. [Sertleştirme Rehberi](#13-sertleştirme-rehberi)

---

## 1. Genel Bakış

memOShield, **28 farklı güvenlik bileşeni** içeren kapsamlı bir ağ güvenlik sistemidir. Tüm bileşenler saf Go ile yazılmış olup harici bağımlılık gerektirmez.

### Güvenlik Katmanları

```
İstek Akışı (Request Pipeline):

İnternet → [Panic Recovery] → [Request ID] → [Request Logger]
         → [Secure Headers] → [Content-Type Check] → [Body Limiter]
         → [UA Blocker] → [WAF] → [Rate Limiter] → [Uygulama]
```

Her gelen HTTP isteği bu 9 katmanlı middleware zincirinden sırasıyla geçer. Herhangi bir katmanda tehdit algılanırsa istek anında reddedilir.

---

## 2. Ağ Katmanı Güvenliği

### 2.1 Rate Limiting (Hız Sınırlama)

**Dosya:** `internal/security/security.go` — Bileşen #1

IP başına kayan pencere (sliding window) algoritması ile istek sayısı sınırlandırılır.

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| Login limiti | 5 istek / 1 dk | Giriş sayfası için |
| API limiti | 60 istek / 1 dk | API endpointleri için |
| SSE Stream limiti | 5 bağlantı / 1 dk | Canlı akış bağlantıları |

**Çalışma Prensibi:**
- Her IP için son pencere süresi içindeki istek zaman damgaları saklanır
- Pencere dışına çıkan eski kayıtlar otomatik temizlenir (60 sn döngü)
- Limit aşılırsa `429 Too Many Requests` döner
- `X-RateLimit-Remaining` başlığı kalan istek hakkını belirtir

```
Örnek: 60 saniye pencerede 5 istek limiti

[t=0s] İstek 1 ✓   [t=15s] İstek 2 ✓   [t=30s] İstek 3 ✓
[t=40s] İstek 4 ✓   [t=50s] İstek 5 ✓   [t=55s] İstek 6 ✗ (429)
[t=61s] İstek 7 ✓ ← t=0'daki istek pencereden çıktı
```

### 2.2 Slow Loris / Bağlantı Tüketme Koruması

**Dosya:** `main.go`

HTTP sunucu zaman aşımları ile yavaş bağlantı saldırıları engellenir:

| Zaman Aşımı | Değer | Amaç |
|-------------|-------|------|
| `ReadHeaderTimeout` | 10 sn | Header okuma süresi — Slow Loris koruması |
| `ReadTimeout` | 30 sn | Tam istek okuma süresi |
| `WriteTimeout` | 60 sn | Yanıt yazma süresi |
| `IdleTimeout` | 120 sn | Keep-alive boşta bekleme süresi |
| `MaxHeaderBytes` | 1 MB | Maksimum header boyutu |

### 2.3 Body Size Limiter (Gövde Boyutu Sınırı)

**Dosya:** `internal/security/security.go` — Bileşen #15

`http.MaxBytesReader` ile istek gövdesi boyutu sınırlandırılır. Aşırı büyük payload'lar ile yapılan DoS saldırılarını engeller.

- Varsayılan limit: **10 MB**
- Limit aşılırsa bağlantı otomatik kapatılır

### 2.4 Geo-Blocking (Ülke Bazlı Engelleme)

**Dosya:** `internal/security/security.go` — Bileşen #10

Belirli ülkelerden gelen tüm trafik engellenebilir.

| Özellik | Açıklama |
|---------|----------|
| Env değişkeni | `GEO_BLOCK_COUNTRIES=CN,RU,KP` |
| Dinamik yönetim | Dashboard'dan ekleme/kaldırma |
| API endpointleri | `/api/security/geoblock`, `/add`, `/remove` |

**Kullanım senaryosu:** Sadece Türkiye'den erişim beklenen bir sistemde diğer tüm ülkeleri engelleyerek saldırı yüzeyini daraltma.

---

## 3. Web Application Firewall (WAF)

**Dosya:** `internal/security/security.go` — Bileşen #5

memOShield WAF'ı **40+ regex kuralı** ile web saldırılarını tespit edip engeller.

### 3.1 Kural Kategorileri

| Kategori | Kural Sayısı | Şiddet | Aksiyon |
|----------|-------------|--------|---------|
| **SQL Injection** | 6 | Critical | Block |
| **XSS (Cross-Site Scripting)** | 5 | High | Block |
| **Path Traversal** | 3 | Critical | Block |
| **Command Injection** | 3 | Critical/High | Block |
| **LFI / RFI** | 3 | Critical | Block |
| **LDAP Injection** | 1 | High | Block |
| **XXE (XML External Entity)** | 1 | Critical | Block |
| **SSTI (Server-Side Template Injection)** | 1 | High | Log |
| **Log4Shell / JNDI** | 1 | Critical | Block |
| **Scanner/Araç Yolları** | 4 | Medium/High | Block/Log |
| **Null Byte Injection** | 1 | High | Block |
| **Header Injection** | 1 | Critical | Block |

### 3.2 SQL Injection Koruması

Tespit edilen SQL enjeksiyon kalıpları:

```
✗ UNION SELECT, INSERT INTO, UPDATE SET, DELETE FROM
✗ ' OR 1=1 --, " AND "x"="x
✗ Stacked queries: ; DROP TABLE; ALTER TABLE
✗ Tehlikeli fonksiyonlar: BENCHMARK(), SLEEP(), LOAD_FILE()
✗ Bilgi şeması erişimi: information_schema, sqlite_master, pg_catalog
```

### 3.3 XSS (Cross-Site Scripting) Koruması

```
✗ <script> etiketleri
✗ Olay işleyicileri: onclick=, onerror=, onload=
✗ Protokol enjeksiyonu: javascript:, vbscript:, data:text/html
✗ <img onerror=>, <svg onload=>
✗ <iframe>, <object>, <embed> etiketleri
```

### 3.4 Path Traversal Koruması

```
✗ ../../etc/passwd, ..\..\windows\system32
✗ URL kodlu: %2e%2e%2f, %252e%252e%2f
✗ Hassas dosyalar: .env, .git/, .htaccess, web.config
```

### 3.5 Command Injection Koruması

```
✗ Pipe/chain: | cat, ; whoami, `id`
✗ Shell substitution: $(command)
✗ Komut zincirleme: && cat /etc/passwd
```

### 3.6 WAF Çalışma Prensibi

1. **Payload Birleştirme:** URL + Query String + POST Form Değerleri + Referer + User-Agent birleştirilir
2. **Kural Taraması:** 40+ regex deseni sırasıyla kontrol edilir
3. **Aksiyon:** `block` kuralı eşleşirse → 403 Forbidden, `log` kuralı → yalnızca kayıt
4. **Olay Kaydı:** Her tespit WAF olay loguna yazılır (max 2000 kayıt)
5. **Statik Bypass:** `/static/` altındaki dosyalar WAF kontrolünden muaftır (performans)

### 3.7 WAF API

| Endpoint | Açıklama |
|----------|----------|
| `GET /api/security/waf` | WAF istatistikleri (toplam tespit, engellenen, kural sayısı) |
| `GET /api/security/waf/events` | Son WAF olayları listesi |

---

## 4. Kimlik Doğrulama & Yetkilendirme

### 4.1 Parola Güvenliği

**Dosya:** `internal/security/security.go` — Bileşen #23

Parolalar **10.000 iterasyon SHA-512** ile hash'lenir:

```
Algoritma:  SHA-512 × 10.000 iterasyon
Salt:       32 byte kriptografik rastgele
Format:     sha512:<salt_hex>:<hash_hex>
```

**Geriye Uyumluluk:** Eski format (SHA-256 tek iterasyon) ve düz metin parolalar da desteklenir. Doğrulama sırasında format otomatik algılanır.

| Format | Güvenlik | Destek |
|--------|----------|--------|
| `sha512:salt:hash` | Yüksek — 10K iterasyon | ✓ Aktif |
| `salt:hash` (SHA-256) | Orta — tek iterasyon | ✓ Geriye uyumlu |
| Düz metin | Düşük | ✓ Env değişkeni |

**Sabit Zamanlı Karşılaştırma:** Tüm parola ve token karşılaştırmaları `crypto/subtle.ConstantTimeCompare` ile yapılır — timing saldırılarına karşı bağışık.

### 4.2 Brute Force Koruması (Login Protector)

**Dosya:** `internal/security/security.go` — Bileşen #2

Başarısız giriş denemeleri izlenir ve hesap otomatik kilitlenir:

| Parametre | Değer |
|-----------|-------|
| Maks. başarısız deneme | 5 |
| Pencere süresi | 5 dakika |
| Kilitleme süresi | 15 dakika |

**Çalışma Prensibi:**
1. Her başarısız giriş IP bazlı kaydedilir
2. 5 dakika içinde 5 hatalı deneme → IP 15 dk kilitlenir
3. Kilitli IP'ye özel hata mesajı + kalan süre gösterilir
4. Başarılı giriş sonrası sayaç sıfırlanır
5. Her kilitleme olayı loglanır

### 4.3 TOTP İki Faktörlü Doğrulama (2FA)

**Dosya:** `internal/security/security.go` — Bileşen #12

RFC 6238 uyumlu TOTP (Time-based One-Time Password) implementasyonu:

| Parametre | Değer |
|-----------|-------|
| Algoritma | HMAC-SHA256 |
| Basamak | 6 |
| Periyot | 30 saniye |
| Skew toleransı | ±1 pencere (toplam 90 sn) |
| Encoding | Base32 (RFC 4648) |

**Özellikler:**
- 🔑 Saf Go implementasyonu — harici kütüphane yok
- 📱 Google Authenticator, Authy, Microsoft Authenticator uyumlu
- 🔗 `otpauth://` URI oluşturma desteği (QR kod için)
- ⚡ Dashboard'dan tek tıkla kurulum/kapatma

**API Endpointleri:**

| Endpoint | Metot | Açıklama |
|----------|-------|----------|
| `/api/security/2fa/status` | GET | 2FA durumu |
| `/api/security/2fa/setup` | POST | Yeni TOTP sırrı oluştur |
| `/api/security/2fa/verify` | POST | TOTP kodu doğrula |
| `/api/security/2fa/disable` | POST | 2FA devre dışı bırak |

### 4.4 Admin IP Allowlist (IP Kısıtlaması)

**Dosya:** `internal/security/security.go` — Bileşen #11

Admin paneline erişimi belirli IP'lerle sınırlandırır:

```bash
ADMIN_ALLOWED_IPS=192.168.1.100,10.0.0.50
```

- Boşsa devre dışıdır (herkes erişebilir)
- `127.0.0.1` ve `::1` (localhost) her zaman izinlidir
- İzinsiz IP'ler giriş sayfasında bile 403 alır

### 4.5 CSRF Koruması (Cross-Site Request Forgery)

**Dosya:** `internal/security/security.go` — Bileşen #3

Tek kullanımlık CSRF tokenları ile form manipülasyonu engellenir:

| Parametre | Değer |
|-----------|-------|
| Token uzunluğu | 32 byte (64 hex karakter) |
| Geçerlilik süresi | 1 saat |
| Token tipi | Tek kullanımlık (use-once) |
| Temizleme | 5 dk döngü ile süresi dolan tokenlar silinir |

**Akış:**
1. Login sayfası yüklenirken sunucu CSRF token üretir
2. Token gizli form alanına yerleştirilir
3. Form gönderildiğinde token doğrulanır ve silinir
4. Geçersiz/eksik token → 403 Forbidden + audit kaydı

---

## 5. Oturum Güvenliği

### 5.1 Oturum Fingerprinting

**Dosya:** `internal/security/security.go` — Bileşen #8

Her oturum, kullanıcının tarayıcı parmak izi ile ilişkilendirilir:

```
Fingerprint = SHA-256(User-Agent + Accept-Language)[:16]
```

- Oturum çalınsa bile farklı bir tarayıcıdan kullanılamaz
- Fingerprint uyumsuzluğu → oturum anında imha edilir + log
- Session hijacking saldırılarını tespit eder

### 5.2 Eşzamanlı Oturum Yönetimi

**Dosya:** `internal/security/security.go` — Bileşen #9

| Parametre | Varsayılan |
|-----------|-----------|
| Maks. eşzamanlı oturum | 3 |
| Otomatik temizleme | 2 saat inaktiflik |
| Çıkarma politikası | En eski oturum çıkarılır |

**Koruma Mekanizması:**
- Limit aşılırsa en eski oturum otomatik sonlandırılır
- Her oturum ID, IP, UA, fingerprint ve son aktivite zamanı ile izlenir
- Dashboard'dan aktif oturumlar görüntülenebilir

### 5.3 Güvenli Cookie Yönetimi

**Dosya:** `internal/security/security.go` — Bileşen #25

Tüm oturum cookie'leri güvenlik bayraklarıyla ayarlanır:

| Bayrak | Değer | Amaç |
|--------|-------|------|
| `HttpOnly` | true | JavaScript erişimini engeller (XSS koruması) |
| `SameSite` | Strict | Cross-site isteklerde cookie gönderilmez (CSRF koruması) |
| `Secure` | Production'da true | Yalnızca HTTPS üzerinden gönderilir |
| `Path` | `/` | Tüm yollarda geçerli |
| `MaxAge` | Yapılandırılabilir | Oturum süresi sınırlı |

### 5.4 Çift Cookie Doğrulama

Oturum sistemi iki ayrı cookie kullanır:

| Cookie | İçerik | Amaç |
|--------|--------|------|
| `session` | HMAC imzalı değer | Kimlik doğrulama kanıtı |
| `sid` | Session Manager ID | Fingerprint doğrulama |

Her istek için **her iki cookie** da doğrulanır. Biri geçersizse oturum reddedilir.

---

## 6. Saldırı Tespit & Engelleme

### 6.1 IP Reputation System (IP İtibar Sistemi)

**Dosya:** `internal/security/security.go` — Bileşen #6

Her IP adresi için tehdit skoru hesaplanır ve belirli eşikte otomatik engelleme yapılır.

**Skor Tablosu:**

| Risk Seviyesi | Skor Aralığı | Aksiyon |
|--------------|-------------|---------|
| 🟢 Clean | 0–14 | Normal erişim |
| 🟡 Low | 15–39 | İzleme altında |
| 🟠 Medium | 40–69 | Artırılmış izleme |
| 🔴 High | 70–99 | Yüksek risk — yakın takip |
| ⛔ Critical | 100+ | **Otomatik engelleme** |

**Puan Kazandıran Olaylar:**

| Olay | Puan |
|------|------|
| WAF kuralı tetikleme | Şiddete göre 10–30 |
| Brute force deneme | 20 |
| Engellenen User-Agent | 15 |
| 404 probe (tarama) | 5 |
| Port tarama | 25 |

**Özellikler:**
- Maksimum skor: 200 (overflow koruması)
- Otomatik temizleme: 24 saat görmezden gelme + skor < 50 → kayıt silinir
- Kategori bazlı olay takibi
- `IP_REPUTATION_AUTOBAN=true` ile otomatik engelleme

**API:**

| Endpoint | Açıklama |
|----------|----------|
| `GET /api/security/reputation` | En tehditli IP'ler |
| `GET /api/security/reputation/lookup/{ip}` | Tekil IP raporu |

### 6.2 User-Agent Analizi & Bot Tespiti

**Dosya:** `internal/security/security.go` — Bileşen #7

Gelen isteklerin User-Agent başlığı 30+ regex deseni ile analiz edilir.

**Engellenen Araçlar (Block):**

| Kategori | Araçlar |
|----------|--------|
| Saldırı Araçları | sqlmap, nikto, nmap, masscan, hydra, metasploit, burpsuite |
| Tarayıcılar | zgrab, gobuster, dirbuster, wpscan, acunetix, nessus, openvas, havij, commix, w3af |
| Bot Kütüphaneleri | python-requests, python-urllib, go-http-client, java/, perl, libwww-perl |
| HTTP İstemcileri | wget, curl, okhttp, aiohttp, scrapy, httpclient |
| Boş UA | `^$` (User-Agent başlığı boş) |

**Şüpheli (Suspicious) — Yalnızca İzleme:**

| Araç | Açıklama |
|------|----------|
| bot, crawler, spider | Arama motoru botları |
| phantomjs, headless | Headless tarayıcılar |
| selenium, webdriver | Otomasyon araçları |
| puppeteer | Chrome otomasyon |

Engellenen UA'lar → 403 Forbidden + IP Reputation puanı artırılır.

### 6.3 Honeypot Form Alanı

**Dosya:** `internal/security/security.go` — Bileşen #20

Login formuna CSS ile gizlenmiş bir alan eklenir:

```html
<input name="website_url_hp" style="position:absolute;left:-9999px;opacity:0" tabindex="-1">
```

- Normal kullanıcılar bu alanı göremez ve doldurmaz
- Botlar formu otomatik doldurarak alanı tetikler
- Tetiklenirse → giriş reddedilir + IP reputation puanı artırılır + audit kaydı

### 6.4 Entropi Algılama

**Dosya:** `internal/security/security.go` — Bileşen #13

Shannon entropi hesaplaması ile rastgele/kodlanmış payload'lar tespit edilir:

```
Entropi = -Σ(pᵢ × log₂(pᵢ))

Normal metin:  ~3.5-4.5 bit
Şüpheli:       ~5.0+ bit
Kodlanmış:     ~6.0+ bit
```

Yüksek entropili parametreler potansiyel şifrelenmiş payload veya obfuscation girişimi olarak işaretlenir.

---

## 7. HTTP Güvenlik Katmanı

### 7.1 Güvenlik Başlıkları (Security Headers)

**Dosya:** `internal/security/security.go` — Bileşen #14

Her HTTP yanıtına eklenen güvenlik başlıkları:

| Başlık | Değer | Amaç |
|--------|-------|------|
| `X-Frame-Options` | `DENY` | Clickjacking koruması |
| `X-Content-Type-Options` | `nosniff` | MIME type sniffing engelleme |
| `X-XSS-Protection` | `1; mode=block` | Tarayıcı XSS filtresi |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referer bilgisi sızıntısı |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()...` | Cihaz API kısıtlama |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Cross-origin kaynak izolasyonu |
| `Cross-Origin-Opener-Policy` | `same-origin` | Cross-origin pencere izolasyonu |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cross-origin kaynak politikası |
| `X-Permitted-Cross-Domain-Policies` | `none` | Flash/PDF cross-domain engeli |
| `X-Download-Options` | `noopen` | IE indirme güvenliği |
| `Content-Security-Policy` | (aşağıda ayrıntılı) | İçerik kaynağı kısıtlama |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | HSTS (yalnızca HTTPS) |

### 7.2 Content Security Policy (CSP)

```
default-src 'self';
script-src  'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com;
style-src   'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com;
img-src     'self' data: https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org;
connect-src 'self';
font-src    'self' https://cdn.jsdelivr.net;
frame-ancestors 'none';
form-action 'self';
base-uri    'self';
object-src  'none';
```

- `frame-ancestors 'none'` → iframe ile gömme engeli
- `form-action 'self'` → form verisi yalnızca aynı origin'e gönderilebilir
- `object-src 'none'` → Flash/Java plugin'leri engellenmiş
- `base-uri 'self'` → base tag manipulation koruması

### 7.3 Cache Kontrolü

API, dashboard ve login sayfaları için:

```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
```

Hassas verilerin tarayıcı önbelleğinde saklanması engellenir.

### 7.4 Sunucu Bilgisi Gizleme

`Server` ve `X-Powered-By` başlıkları yanıtlardan kaldırılır. Saldırganların sunucu teknolojisini tespit etmesi engellenir.

### 7.5 Content-Type Doğrulama

**Dosya:** `internal/security/security.go` — Bileşen #19

POST/PUT/PATCH isteklerinde Content-Type başlığı doğrulanır:

| İzin Verilen | Reddedilen |
|-------------|-----------|
| `application/json` | `text/xml` |
| `application/x-www-form-urlencoded` | `application/octet-stream` |
| `multipart/form-data` | Bilinmeyen tipler |

Geçersiz Content-Type → `415 Unsupported Media Type`

---

## 8. Veri Güvenliği & Doğrulama

### 8.1 IP Doğrulama & Sanitizasyon

**Dosya:** `internal/security/security.go` — Bileşen #4

| Fonksiyon | Amaç |
|-----------|------|
| `ValidateIP()` | IP formatının geçerliliğini kontrol eder |
| `SanitizeIP()` | IP adresini temizler, port bilgisini ayırır |
| `IsPrivateIP()` | Özel/dahili ağ IP'lerini tespit eder |

**Desteklenen Özel Ağ Aralıkları:**

```
IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
IPv6: ::1/128, fc00::/7, fe80::/10
```

### 8.2 Input Sanitizasyonu

**Dosya:** `internal/security/security.go` — Bileşen #26

```go
SanitizeInput(input string, maxLen int) string
```

- Maksimum uzunluk kısıtı
- Null byte (`\x00`) temizleme
- HTML etiket kaldırma (`<script>`, `<img>` vb.)
- Baş/son boşluk temizleme

### 8.3 Open Redirect Engelleme

Login başarılı olduktan sonra yönlendirme yalnızca `/dashboard`'a yapılır. Harici URL'ye yönlendirme mümkün değildir.

### 8.4 Güvenli Token Üretimi

**Dosya:** `internal/security/security.go` — Bileşen #28

Tüm security token'lar `crypto/rand` kullanılarak kriptografik olarak güvenli rastgele sayı üreteci ile oluşturulur:

- CSRF tokenları: 32 byte (256 bit)
- Session ID'ler: 32 byte (256 bit)
- Request ID'ler: 8 byte (64 bit)
- TOTP secret: 20 byte (160 bit)
- Parola salt: 32 byte (256 bit)

---

## 9. İzleme & Denetim

### 9.1 Request ID Tracking

**Dosya:** `internal/security/security.go` — Bileşen #18

Her isteğe benzersiz bir ID atanır:

- Header: `X-Request-ID: <16 hex karakter>`
- Hem yanıt başlığında hem istek header'ında ayarlanır
- Loglar ve hatalar bu ID ile ilişkilendirilebilir

### 9.2 İstek Loglama

**Dosya:** `internal/security/security.go` — Bileşen #16

Tüm HTTP istekleri (statik dosyalar hariç) yapılandırılmış formatta loglanır:

```
HTTP 200 POST /login 192.168.1.100 [45.2ms] UA="Mozilla/5.0..."
HTTP 403 GET /api/events 45.33.32.156 [1.2ms] UA="sqlmap/1.7"
```

Kaydedilen bilgiler: HTTP durum kodu, metot, yol, istemci IP, süre, User-Agent.

### 9.3 Audit Log (Denetim Kaydı)

**Dosya:** `internal/security/security.go` — Bileşen #24

Güvenlik açısından kritik tüm işlemler denetim loguna kaydedilir:

| Aksiyon | Şiddet | Açıklama |
|---------|--------|----------|
| `LOGIN_SUCCESS` | info | Başarılı giriş |
| `LOGIN_FAIL` | high | Başarısız giriş denemesi |
| `LOGIN_LOCKED` | high | IP kilitleme |
| `CSRF_FAIL` | high | CSRF token hatası |
| `WAF_BLOCK` | critical | WAF engelleme |
| `UA_BLOCKED` | critical | User-Agent engelleme |
| `GEOBLOCK` | critical | Ülke bazlı engelleme |
| `TOTP_FAIL` | critical | 2FA doğrulama hatası |
| `BAN` / `UNBAN` | medium | IP ban/unban |
| `EVENTS_CLEAR_ALL` | medium | Olay temizleme |
| `LOGOUT` | info | Çıkış |

**Audit Log Kapasitesi:** 10.000 kayıt (FIFO — en eski kayıtlar silinir).

### 9.4 Panic Recovery

**Dosya:** `internal/security/security.go` — Bileşen #17

Beklenmeyen runtime panic'leri yakalanır ve:

1. Panic detayı güvenli şekilde loglanır (IP, metot, yol dahil)
2. İstemciye genel bir 500 hatası döndürülür (iç detay sızmaz)
3. Sunucu çökmeden çalışmaya devam eder

```
PANIC RECOVERED: runtime error: index out of range [POST /api/ban from 192.168.1.1]
```

### 9.5 Güvenlik Skoru Hesaplama

**Dosya:** `internal/security/security.go` — Bileşen #27

Sistemin güvenlik duruşunu puanlayan otomatik denetim:

| Kontrol | Maks. Puan |
|---------|-----------|
| Parola gücü | 15 |
| TOTP 2FA | 20 |
| WAF durumu | 15 |
| Geo-engelleme | 10 |
| Admin IP kısıtlama | 15 |
| Rate limiting | 10 |
| Güvenlik başlıkları | 10 |
| CSRF koruması | 5 |
| **Toplam** | **100** |

**Derecelendirme:**

| Puan | Not | Anlam |
|------|-----|-------|
| 95–100 | A+ | Mükemmel güvenlik |
| 85–94 | A | Çok iyi güvenlik |
| 75–84 | B | İyi güvenlik |
| 60–74 | C | Orta — iyileştirme gerekli |
| 40–59 | D | Zayıf — acil aksiyon |
| 0–39 | F | Kritik — güvensiz |

---

## 10. Yapılandırma Referansı

### Güvenlik Ortam Değişkenleri

| Değişken | Varsayılan | Tip | Açıklama |
|----------|-----------|-----|----------|
| `ADMIN_PASSWORD` | `admin` | string | Yönetici parolası (min 12 karakter önerilir) |
| `FLASK_SECRET` | `change-this-secret` | string | Cookie HMAC imzalama anahtarı |
| `WAF_ENABLED` | `true` | bool | Web Application Firewall |
| `UA_BLOCK_ENABLED` | `true` | bool | User-Agent engelleme |
| `GEO_BLOCK_COUNTRIES` | *(boş)* | string | Engellenen ülkeler (virgülle ayrılmış: `CN,RU,KP`) |
| `ADMIN_ALLOWED_IPS` | *(boş)* | string | Yetkili admin IP'leri (virgülle ayrılmış) |
| `TOTP_SECRET` | *(boş)* | string | 2FA TOTP sırrı (boş = devre dışı) |
| `MAX_ADMIN_SESSIONS` | `3` | int | Maks. eşzamanlı oturum |
| `IP_REPUTATION_AUTOBAN` | `true` | bool | Otomatik IP engelleme (skor ≥ 100) |
| `SESSION_MAX_AGE` | `3600` | int | Oturum süresi (saniye) |

### Üretim (Production) Önerisi

```bash
export ADMIN_PASSWORD="guclu-ve-uzun-bir-sifre-buraya"
export FLASK_SECRET="$(openssl rand -hex 32)"
export WAF_ENABLED=true
export UA_BLOCK_ENABLED=true
export GEO_BLOCK_COUNTRIES="CN,RU,KP,IR"
export ADMIN_ALLOWED_IPS="192.168.1.100,10.0.0.50"
export TOTP_SECRET="$(openssl rand -base64 20 | tr -d '=/+' | head -c 32)"
export MAX_ADMIN_SESSIONS=2
export IP_REPUTATION_AUTOBAN=true
export SESSION_MAX_AGE=1800
```

---

## 11. Güvenlik Mimarisi Diyagramı

```
                          ┌───────────────────────────────────┐
                          │         İNTERNET / DIŞ AĞ          │
                          └────────────────┬──────────────────┘
                                           │
                    ┌──────────────────────▼──────────────────────┐
                    │            HTTP SERVER (net/http)            │
                    │   ReadTimeout=30s, MaxHeaderBytes=1MB       │
                    └──────────────────────┬──────────────────────┘
                                           │
        ┌──────────────────────────────────▼──────────────────────────────────┐
        │                    MİDDLEWARE ZİNCİRİ (9 KATMAN)                   │
        │                                                                     │
        │  ① Panic Recovery ─── Çökme yakalama, 500 döndürme                 │
        │  ② Request ID ─────── Benzersiz istek kimliği (X-Request-ID)       │
        │  ③ Request Logger ─── HTTP log (durum, süre, IP, UA)               │
        │  ④ Secure Headers ─── 12+ güvenlik başlığı (CSP, HSTS, X-Frame)   │
        │  ⑤ Content-Type ───── POST/PUT Content-Type doğrulama              │
        │  ⑥ Body Limiter ───── 10MB maks. istek gövdesi                    │
        │  ⑦ UA Blocker ─────── 30+ saldırı aracı User-Agent engeli         │
        │  ⑧ WAF ────────────── 40+ regex, SQLi/XSS/Traversal/CMDi/XXE     │
        │  ⑨ Rate Limiter ───── IP bazlı hız sınırlama                      │
        │                                                                     │
        └──────────────────────────────────┬──────────────────────────────────┘
                                           │
        ┌──────────────────────────────────▼──────────────────────────────────┐
        │                        UYGULAMA KATMANI                             │
        │                                                                     │
        │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────────┐ │
        │  │ Login        │  │ Dashboard    │  │ API Endpoints              │ │
        │  │ ▸ CSRF       │  │ ▸ Auth Check │  │ ▸ /api/security/*          │ │
        │  │ ▸ Brute Force│  │ ▸ Session FP │  │ ▸ /api/events, /api/bans   │ │
        │  │ ▸ Honeypot   │  │ ▸ Rate Limit │  │ ▸ /api/whitelist           │ │
        │  │ ▸ TOTP 2FA   │  │              │  │ ▸ /stream (SSE)            │ │
        │  │ ▸ IP Allowlist│ │              │  │                            │ │
        │  └─────────────┘  └──────────────┘  └────────────────────────────┘ │
        │                                                                     │
        │  ┌───────────────────────────────────────────────────────────────┐  │
        │  │               ARTıŞ / TEHDİT SİSTEMLERİ                      │  │
        │  │  IP Reputation │ Geo-Blocker │ Session Manager │ Audit Log   │  │
        │  └───────────────────────────────────────────────────────────────┘  │
        └─────────────────────────────────────────────────────────────────────┘
```

---

## 12. Güvenlik Skoru

Dashboard'taki **Güvenlik** sekmesinden sisteminizin anlık güvenlik durumunu görüntüleyebilirsiniz.

`GET /api/security/score` endpoint'i ile programatik olarak da erişilebilir.

**Skor artırmak için:**

| Aksiyon | Puan Kazanımı |
|---------|--------------|
| Güçlü parola ayarlama (12+ karakter) | +15 |
| TOTP 2FA aktifleştirme | +20 |
| WAF'ı açık tutma | +15 |
| Admin IP kısıtlama | +15 |
| Geo-engelleme yapılandırma | +10 |
| *(Rate limiting + headers + CSRF otomatik)* | +25 |

---

## 13. Sertleştirme Rehberi

### Minimum Güvenlik (Varsayılan)

Hiçbir yapılandırma gerekmeden aktif olan korumalar:

- ✅ Rate Limiting (login + API + stream)
- ✅ WAF (40+ kural)
- ✅ Güvenlik başlıkları (12+ header)
- ✅ CSRF koruması
- ✅ Brute force koruması (5 deneme / 15 dk kilit)
- ✅ UA blocker (30+ araç)
- ✅ Body size limiter (10 MB)
- ✅ Panic recovery
- ✅ Request ID tracking
- ✅ Request logging
- ✅ Audit logging
- ✅ Content-Type doğrulama
- ✅ IP reputation (auto-ban)
- ✅ Honeypot form alanı
- ✅ Session fingerprinting
- ✅ Eşzamanlı oturum limiti (3)
- ✅ Güvenli cookie bayrakları
- ✅ Çift cookie doğrulama
- ✅ HTTP server zaman aşımları
- ✅ Open redirect engelleme
- ✅ Sunucu bilgisi gizleme

### Tam Sertleştirme (A+ Skor)

Ek yapılandırma ile maksimum güvenlik:

```bash
# 1. Güçlü parola
export ADMIN_PASSWORD="EnAz12KarakterUzunVeKarmasik!"

# 2. Cookie imzalama anahtarı
export FLASK_SECRET="$(openssl rand -hex 32)"

# 3. 2FA etkinleştirme
export TOTP_SECRET="JBSWY3DPEHPK3PXP"  # 32 karakterlik Base32

# 4. Admin IP kısıtlama
export ADMIN_ALLOWED_IPS="192.168.1.100"

# 5. Ülke engelleme
export GEO_BLOCK_COUNTRIES="CN,RU,KP,IR,VN"

# 6. Eşzamanlı oturum limiti
export MAX_ADMIN_SESSIONS=1

# 7. Kısa oturum süresi
export SESSION_MAX_AGE=900  # 15 dakika
```

### HTTPS (Üretim)

Güvenli cookie bayrakları ve HSTS başlığı yalnızca HTTPS ile tam etkili olur. Üretim ortamında Let's Encrypt veya reverse proxy (nginx/Caddy) ile HTTPS zorunlu yapın.

---

## Bileşen Özet Tablosu

| # | Bileşen | Kategori | Koruma |
|---|---------|----------|--------|
| 1 | Rate Limiter | Ağ | DDoS, brute force |
| 2 | Login Protector | Kimlik | Brute force saldırıları |
| 3 | CSRF Manager | Web | Cross-site request forgery |
| 4 | IP Validation | Veri | IP spoofing, injection |
| 5 | WAF | Web | SQLi, XSS, LFI, RFI, CMDi, XXE |
| 6 | IP Reputation | Saldırı Tespit | Tekrarlayan tehditler |
| 7 | UA Analyzer | Saldırı Tespit | Saldırı araçları, botlar |
| 8 | Session Fingerprint | Oturum | Session hijacking |
| 9 | Session Manager | Oturum | Eşzamanlı oturum kötüye kullanımı |
| 10 | Geo-Blocker | Ağ | Ülke bazlı saldırılar |
| 11 | Admin Allowlist | Kimlik | Yetkisiz admin erişimi |
| 12 | TOTP 2FA | Kimlik | Parola hırsızlığı |
| 13 | Entropy Detector | Veri | Obfuscated payload'lar |
| 14 | Security Headers | HTTP | Clickjacking, XSS, MIME sniffing |
| 15 | Body Limiter | Ağ | Payload DoS |
| 16 | Request Logger | İzleme | Adli inceleme |
| 17 | Panic Recovery | Sistem | Sunucu çökmesi |
| 18 | Request ID | İzleme | İstek korelasyonu |
| 19 | Content-Type Check | HTTP | Beklenmeyen veri tipleri |
| 20 | Honeypot Field | Saldırı Tespit | Bot tespiti |
| 21 | Client IP | Ağ | Proxy arkasında gerçek IP |
| 22 | Secure Compare | Kripto | Timing saldırıları |
| 23 | Password Hashing | Kripto | Parola kırma (SHA-512 × 10K) |
| 24 | Audit Log | İzleme | Güvenlik denetimi |
| 25 | Secure Cookies | Oturum | Cookie hırsızlığı |
| 26 | Input Sanitization | Veri | HTML/null byte injection |
| 27 | Security Score | İzleme | Güvenlik duruş değerlendirmesi |
| 28 | Helper Functions | Sistem | Güvenli token üretimi, string truncation |

---

## API Güvenlik Endpointleri

| Endpoint | Metot | Açıklama |
|----------|-------|----------|
| `/api/security/score` | GET | Güvenlik skoru raporu |
| `/api/security/waf` | GET | WAF istatistikleri |
| `/api/security/waf/events` | GET | WAF olay listesi |
| `/api/security/reputation` | GET | En tehditli IP'ler |
| `/api/security/reputation/lookup/{ip}` | GET | Tekil IP raporu |
| `/api/security/sessions` | GET | Aktif oturumlar |
| `/api/security/geoblock` | GET | Engellenen ülkeler |
| `/api/security/geoblock/add` | POST | Ülke engelle `{country}` |
| `/api/security/geoblock/remove` | POST | Engeli kaldır `{country}` |
| `/api/security/2fa/status` | GET | 2FA durumu |
| `/api/security/2fa/setup` | POST | TOTP sırrı oluştur |
| `/api/security/2fa/verify` | POST | TOTP kodu doğrula `{code}` |
| `/api/security/2fa/disable` | POST | 2FA kapat |

---

*Bu dokümantasyon memOShield v2.0 güvenlik protokollerini kapsamaktadır.*  
*Tüm güvenlik bileşenleri saf Go ile yazılmış olup harici bağımlılık gerektirmez.*
