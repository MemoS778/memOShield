# Kişisel sürüm mimarisi ve sınırlar

```text
root-owned SSH journal ─┐
                       ├─ parser → dedup + SQLite → SSE → yerel panel
Suricata EVE alerts ────┘                  │
                     fresh SSH rule / manual decision
                                         ↓
                             persistent desired bans
                                         ↓
                           protected Unix socket helper
                                         ↓
                           private nftables INPUT sets
```

## Güven sınırları

- HTTP yalnızca literal loopback bind, doğrulanmış Host, 256 bit token ve HttpOnly/SameSite oturumla kullanılır. Mutasyonlar exact Origin + JSON gerektirir. Proxy başlıkları kullanılmaz.
- Tarayıcıya verilen metinler `textContent` ile oluşturulur. CDN/inline script yoktur. Yönetim uçları kimlik doğrulaması ister; kayıt üretme veya tüm olayları silme API'si yoktur.
- Suricata dosyası bir sensör girdisidir; alert algılanması başarılı saldırı anlamına gelmez. Kaynak IP'ye dayanarak kişilik/kimlik atfedilmez. EVE otomatik IPS'ye bağlanmaz.
- SSH otomatik politika root journald metadata, zaman penceresi ve kalıcı deduplikasyon gerektirir. Başarılı oturumlar ayrı gösterilir.
- Engelleme transaction başarısından önce başarı bildirilmez. İşlem başarısızsa istenen durum kalır ve yeniden denenir; UI `unconfirmed` gösterir. Yapılandırılmış modda hiçbir örtük sudo çağrısı yoktur.
- Unix socket kullanıcısının o bilgisayara süreli INPUT IP engeli koyma yetkisi vardır. Aynı kullanıcı hesabı ele geçirilirse bu yetki ve panel token'ı da ele geçirilmiş sayılır.

## Mevcut sınırlar / sıradaki işler

1. SSH dışı servislerin (RDP, Samba, kamera/NVR) günlük adaptörleri henüz yok.
2. Port taraması görünürlüğü için çalışan Suricata + uygun kurallar gerekir. EVE okuyucusu paket yakalama motoru değildir.
3. Güvenilir liste/engel yönetim işlemleri için ayrı değiştirilemez audit izi ve kullanıcı ayrımı sonraki sürümdür; şu an tek kullanıcı ve son durum kaydı vardır.
4. Journal vacuum sonucu kayıp cursor otomatik sıfırlanmaz; sensör görünür hata verir. Rotation/cursor kurtarma arayüzü eklenecek.
5. Suricata heartbeat/stats ile gerçek sensör canlılığı henüz doğrulanmaz; UI sadece dosya okuma ve son alert durumunu açıklar.
6. Wi-Fi ağ değişiminde otomatik profil/CIDR politikası ve DHCP cihaz geçmişi henüz yok. Helper yerel adres/gateway korumasını her transaction'da yeniler.
7. Nftables entegrasyonu test ortamında doğrulanmalıdır; sadece testleri geçmek gerçek host üzerinde IPS'nin aktif olduğunu göstermez.
8. Yönetim için loopback HTTP paneli ve aynı API'ye bağlanan GNOME Shell 51 panel eklentisi vardır. Eklenti 15 saniyelik snapshot alır; tarayıcı panelindeki SSE, tüm filtreler ve JSON dışa aktarımı eklentide yoktur. Tarayıcı eklentisi, KDE Plasma eklentisi ve bağımsız masaüstü penceresi henüz yoktur.

## Doğrulama

Testler gerçek SQLite kullanır: olay tekrarları, zaman penceresi, eksik JSON/Origin/Host/auth, gerçek HTTP SSE akışı, EVE partial-write/rename rotation, engel süresi ve yardımcı süreç hataları. Fake firewall gerçek bilgisayarın kurallarını değiştirmez. Rootless network namespace desteklenirse ek nft smoke testi yalnızca o ayrı namespace içinde çalışır.
