# memOShield Personal — Güvenlik modeli

## Yerel masaüstü iletişimi

- Go servisi yalnızca Unix socket dinler. Üretimde TCP dinleyicisi, HTML paneli veya web varlıkları sunulmaz.
- Varsayılan yol `$XDG_RUNTIME_DIR/memoshield/control.sock`. Runtime dizini yoksa `$XDG_STATE_HOME/memoshield/memoshield/control.sock`; state varsayılanı `~/.local/state`.
- Socket dizini bu kullanıcıya ait `0700`, socket `0600` olmalıdır. Özel `MEMOSHIELD_SOCKET` mutlak yol gerektirir. Çalışan socket'in üzerine yazılmaz; socket olmayan dosya silinmez.
- İlk açılışta 256 bit rastgele token oluşturulur. Token dosyası `0600`, state dizini `0700`; token loglanmaz. GTK ve GNOME istemcileri token'ı otomatik okur.
- HTTP/JSON, yalnızca Unix socket üzerinde bir IPC protokolü olarak kullanılır. Host, Origin ve JSON gövdeleri doğrulanır; istemci proxy veya redirect kullanmaz.
- Oturum cookie'si bellekte saklanır. Oturumlar 8 saat geçerli; çıkış veya servis yeniden başlatmasıyla geçersizleşir. `HttpOnly` ve `SameSite=Strict` korunur; bu taşıma TLS kullanmaz.
- Giriş 10 deneme/dakika, en fazla 10 oturum ve 8 SSE bağlantısıyla sınırlıdır. Mutasyon gövdeleri 4096 baytla sınırlı; bilinmeyen alanlar ve çoklu JSON nesneleri reddedilir.
- Aynı kullanıcı hesabındaki kötü amaçlı süreçlere veya root ele geçirilmesine karşı izolasyon sağlamaz.

## Sensörler ve firewall

- SSH sensörü root-owned `sshd` / `sshd-session` journal metadata'sını doğrular. Yalnızca taze yerel parola hataları otomatik karar üretebilir.
- Suricata ayrı kurulur. EVE okuyucusu sadece `alert` kayıtlarını alır; otomatik engel üretmez. Dosyanın okunması sensörün paket yakaladığını kanıtlamaz.
- `monitor` varsayılandır ve helper çağırmaz. GTK uygulaması ve Go servisi root çalışmaz.
- Ayrı yetkili helper, seçilen kullanıcıya ait `0600` Unix socket üzerinden yalnızca `inet memoshield_personal` tablosunu yönetir.
- Sadece gelen INPUT kaynak IP engelleri: 1–60 dakika, en fazla 256 aktif IP. Yerel adresler, gateway'ler ve görülebilen DNS adresleri korunur. Kernel timeout uygulama kapansa da süreyi bitirir.
- `applied` son başarılı transaction'ı ifade eder; bağımsız sürekli ruleset/gerçek trafik doğrulaması değildir. Başarısız işlem `unconfirmed` olarak gösterilir ve yeniden denenebilir.
- Pencere/eklenti kapatılması Go servisini durdurmaz. Monitor moduna geçmek mevcut kernel engellerini hemen kaldırmaz.

## Veri ve sınırlar

- SQLite olayları ve JSON dışa aktarımları IP, kullanıcı ve journal kanıtı içerebilir. Veritabanı uygulama tarafından şifrelenmez.
- Ayrı değiştirilemez audit izi ve çok kullanıcılı yetkilendirme yoktur.
- Değişiklik izleme/enventer henüz uygulanmadı; ilgili sayfa hazırlık durumunu gösterir.
- Testler geçici veri ve izole ortam kullanır. Test başarısı gerçek host üzerinde IPS etkinliğinin kanıtı değildir.

## Sorun bildirimi

Anahtar, cookie veya kişisel günlük/veritabanı paylaşmayın. Yeniden üretme adımlarını ve sürümü belirtin. Özel güvenlik bildirimi kanalı henüz tanımlanmamıştır.
