# memOShield Personal — Güvenlik modeli

Bu belge mevcut Linux kişisel sürümünü açıklar. Kurulum için [deployment.md](docs/deployment.md), görünürlük sınırları için [mimari belgesi](docs/personal-design.md).

## Yerel yönetim

- Sunucu yalnızca literal loopback adresine bağlanır. İstemci adresi ve HTTP Host doğrulanır; uzaktan erişim ve reverse proxy desteklenmez.
- İlk çalıştırmada kriptografik rastgele 256 bit erişim anahtarı üretilir. Anahtar dosyası `0600`, veri dizini `0700` izinlidir.
- Oturum cookie'si `HttpOnly` ve `SameSite=Strict` kullanır. Sunucu loopback HTTP kullandığından `Secure` bayrağı yoktur. Oturumlar 8 saat geçerlidir; çıkış veya sunucunun yeniden başlamasıyla geçersizleşir.
- Giriş uç noktasında toplam 10 deneme/dakika sınırı, en fazla 10 oturum ve aynı anda en fazla 8 SSE bağlantısı vardır. Bunlar genel DDoS koruması değildir.
- Değişiklik yapan istekler aynı origin ve `application/json` gerektirir. Gövde 4096 baytla sınırlıdır; bilinmeyen JSON alanları ve birden fazla JSON nesnesi reddedilir.
- Panel dış CDN kullanmaz; CSP inline script ve stillere izin vermez. Olay metinleri HTML olarak çalıştırılmadan gösterilir. Yanıtlar `Cache-Control: no-store` kullanır.

## Sensörler ve engelleme

GNOME panel eklentisi de aynı yerel API ve oturum modelini kullanır. Erişim anahtarını kullanıcı dosyasından okur; GSettings'e yazmaz. Cookie yalnızca bellekte tutulur, HTTP yönlendirmeleri izlenmez ve sistem HTTP proxy'si kullanılmaz. Eklentiyi kapatmak servisi durdurmaz. Eklentinin bellekteki oturumu sunucu tarafında süre dolumuna kadar kalabilir.

- SSH sensörü root-owned `sshd` / `sshd-session` journal metadata'sını doğrular. Otomatik engelleme yalnızca taze yerel SSH parola hatalarından üretilir.
- Suricata ayrı kurulur; EVE okuyucusu sadece üretilen uyarıları alır. Bu uyarılar otomatik engel üretmez.
- Varsayılan `monitor` modu engel uygulamaz. `manual` ve `auto` modlarında normal kullanıcıyla çalışan uygulama ayrı firewall yardımcı sürecine bağlanır.
- Yardımcı süreç root-owned, diğer kullanıcıların yazamadığı bir dizinde seçilen kullanıcıya ait `0600` Unix socket oluşturur; erişim dosya sistemi izinleriyle sınırlandırılır. Yalnızca kendi `inet memoshield_personal` nftables tablosundaki gelen trafik kaynak IP engellerini yönetir.
- Süreler 1–60 dakika, aktif hedef sayısı en fazla 256 IP'dir. Kernel timeout süre dolumunu uygular. Yerel adresler, ağ geçitleri ve yardımcı sürecin görebildiği DNS adresleri engellemeye karşı korunur.
- Başarısız firewall işlemleri başarı gibi gösterilmez; istenen durum ve son doğrulanan sonuç ayrı saklanır. `applied` son başarılı uzlaştırmayı ifade eder, sürekli bağımsız doğrulama değildir.

## Sınırlar ve veri

- Bu sürüm antivirüs, web siteleri için WAF, tarayıcı eklentisi veya ağın tamamına yönelik koruma ürünü değildir. 2FA, ülke engelleme ve güvenlik puanı özelliği yoktur.
- Aynı kullanıcı hesabını ele geçiren bir süreç erişim anahtarını ve yerel verileri okuyabilir. Root ele geçirilmesine karşı koruma sağlanmaz.
- SQLite olayları, IP adresleri ve günlük kanıtları yerel diskte tutulur; uygulama veritabanını şifrelemez. JSON dışa aktarımları da bu bilgileri içerebilir.
- Ayrı değiştirilemez işlem denetim izi ve çok kullanıcılı yetkilendirme yoktur. Normal bir Wi-Fi istemcisi diğer iki cihaz arasındaki trafiği genellikle göremez.
- Testlerde sahte firewall kullanılması gerçek cihazda IPS'nin etkin olduğunu kanıtlamaz. Gerçek nftables entegrasyonu ayrı ortamda doğrulanmalıdır.

## Sorun bildirimi

Hata raporlarında erişim anahtarını, oturum cookie'sini veya kişisel günlük/veritabanı dosyalarını paylaşmayın. Raporun yeniden üretme adımlarını ve ilgili sürümü belirtin; özel güvenlik bildirimi kanalı henüz tanımlanmamıştır.
