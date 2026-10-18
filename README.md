# memOShield Personal

Linux bilgisayarınız için **kişisel güvenlik olayları izleme ve kontrollü IP engelleme** aracı. Go + SQLite, yerel web paneli, SSH günlük sensörü ve isteğe bağlı Suricata EVE entegrasyonu.

## Ne yapar?

- Root-owned `sshd` / `sshd-session` journald kayıtlarından başarılı ve başarısız SSH girişlerini gösterir.
- İki dakikada en az 10 başarısız SSH parola girişini ilişkilendirir.
- Suricata'nın ürettiği ağ uyarılarını kaynak, hedef, port ve imza bilgisiyle gösterir.
- `monitor` modunda sadece izler; `manual` modunda kullanıcı kararıyla, `auto` modunda ayrıca **taze yerel SSH parola hataları** için süreli engel uygular.
- Engelleri ayrı bir Unix-socket yardımcı süreciyle, yalnızca `inet memoshield_personal` nftables tablosunda yönetir. Web uygulaması root çalışmaz.
- Kalıcı IP/CIDR güvenilir listesi, olay tekrarlarını önleme, SSE cursor replay ve sensör durumları sağlar.

**Görünürlük sınırı:** Normal bir Wi-Fi istemcisi başka iki cihaz arasındaki trafiği çoğunlukla göremez. Kafe kameralarını veya bütün ağı izlemek için ağ sahibinin yetkilendirdiği router/AP/SPAN sensörü gerekir. IP bir kişinin kimliği değildir; port bağlantısı başarılı oturum açma kanıtı değildir. Bu araç genel DDoS koruması veya antivirüs iddiasında bulunmaz.

## Başlangıç

Gereksinimler: Linux, Go **1.26+** (güncel yamalı sürüm önerilir), SSH izlemek için okunabilir systemd journal.

```sh
git clone https://github.com/MemoS778/memOShield.git
cd memOShield/memOShield
go build -o memoshield-personal .
./memoshield-personal
```

Panel: **http://127.0.0.1:5000**. İlk çalıştırmada 256 bit rastgele erişim anahtarı oluşturulur:

```sh
cat "${XDG_STATE_HOME:-$HOME/.local/state}/memoshield/access-token"
```

Anahtarı yerel giriş formuna girin. Anahtar loglara yazılmaz; dosya `0600`, veri dizini `0700` izinlidir. Başka bir cihazdan/proxy üzerinden yönetim desteklenmez. Oturumlar 8 saat geçerlidir ve yeniden başlatmada sonlanır.

**Varsayılan kurulum ağ paketi yakalamaz, port açan honeypot başlatmaz ve hiçbir IP engellemez.** SSH kaydı yoksa boş panel normaldir. “watching”, sensörün veri kaynağını beklediğini söyler; sistemin saldırıya karşı test edildiğini söylemez.

## Kontrol merkezi

- **Genel bakış:** Görünen olay sayısı, yüksek önem uyarıları, kaynak IP dağılımı, doğrulanmış engeller ve saatlik aktivite.
- **Olay akışı:** IP/kullanıcı/kanıt araması, önem/kaynak/zaman filtreleri, sayfalama ve olay detayları. `/` tuşu aramayı açar.
- **Akışı duraklat:** Görünümü sabitler; arka planda olay toplama devam eder. Canlıya dönünce yeni kayıtlar görünür.
- **JSON indir:** Etkin filtrelere uyan en yeni 200 kayıt içindeki olayları dışa aktarır; tam veritabanı yedeği değildir.
- **Koruma:** Süreli engelleme kararlarını ve güvenilir IP/CIDR adreslerini yönetir. İzleme modunda engelleme düğmesi kapalıdır.
- **Sensörler:** Veri kaynağı durumlarını, kurulum rehberlerini ve masaüstü bildirim iznini gösterir.

Panel masaüstü ve dar ekranlara uyarlanır. Boş durumda gerçek kayıt bekler; örnek saldırı verisi üretmez.

## Çalışma modları

| Mod | Davranış |
|---|---|
| `monitor` (varsayılan) | Gerçek olayları kaydeder; firewall yardımcı sürecini çağırmaz. |
| `manual` | Panelden 1–60 dakikalık engeller; yardımcı süreç gerekir. |
| `auto` | Manuel işlevlere ek olarak son 30 saniye içinde alınan SSH kayıtlarından 2 dakikada 10 parola hatasında 10 dakikalık engel. |

Suricata uyarıları **otomatik engel üretmez**. Tarihsel SSH kayıtları yeniden okunduğunda otomatik engel uygulanmaz. Aynı IP için tekrarlanan karar engelin süresini sonsuza uzatmaz. Yardımcı süreç yoksa API başarı bildirmez: talep `unconfirmed` olarak kalır ve manual/auto modunda süresi dolana kadar yeniden denenir. İptal etmek için “Kaldır / iptal et” kullanın.

## Yapılandırma

| Değişken | Varsayılan |
|---|---|
| `MEMOSHIELD_LISTEN` | `127.0.0.1:5000` (yalnızca literal loopback) |
| `MEMOSHIELD_DATA_DIR` | `$XDG_STATE_HOME/memoshield` veya `~/.local/state/memoshield` |
| `MEMOSHIELD_MODE` | `monitor` |
| `MEMOSHIELD_JOURNAL` | `1`; devre dışı bırakmak için `0` |
| `MEMOSHIELD_EVE_PATH` | boş; örn. `/var/log/suricata/eve.json` |
| `MEMOSHIELD_FIREWALL_SOCKET` | `/run/memoshield/firewall.sock` |

Olaylar 30 gün ve yaklaşık 100.000 kayıt sınırıyla, dakikalık temizlikle tutulur. Panel son 200 olayı gösterir. Masaüstü bildirimleri kullanıcı izin verirse panel açıkken yeni yüksek önem olaylarında çalışır.

## Kurulum ve test

- [Linux, systemd, Suricata ve firewall kurulumu](memOShield/docs/deployment.md)
- [Tasarım ve sonraki işler](memOShield/docs/personal-design.md)

```sh
cd memOShield  # repo kökünden
go test -race ./...
go vet ./...
```

Tarayıcı akış testi (Node.js 22.13+, Go ve Playwright Chromium):

```sh
cd memOShield/tests/ui  # repo kökünden
npm ci
npx playwright install chromium
npm test
```

Test geçici bir veri dizininde, yalnızca izleme modunda kendi sunucusunu başlatır. Giriş, filtreleme, sayfalama, güvenilir liste, JSON indirme ve mobil görünümü doğrular. Mevcut Chromium tabanlı tarayıcı için `BROWSER_PATH`, farklı Go kurulumu için `GO_BIN` kullanılabilir.

## Proje yapısı ve geçiş

- `memOShield/main.go`: normal kullanıcıyla çalışan kişisel servis.
- `memOShield/internal/personal/`: sensörler, SQLite, API ve gömülü panel.
- `memOShield/cmd/memoshield-fw/`, `internal/firewallctl/`: ayrı nftables yardımcı süreci ve protokolü.
- `memOShield/deploy/`: systemd servis örnekleri ve isteğe bağlı Suricata kuralı.
- `memOShield/desktop/gnome/`: GNOME Shell 51 panel eklentisi.
- `memOShield/tests/ui/`: izole tarayıcı akış testi.

Önceki demo paketleri, örnek olay üreticisi, eski web şablonları ve Windows binary'leri kaldırıldı; geçmiş sürümler Git geçmişinde bulunur. Eski `memoshield.db` otomatik taşınmaz; kişisel sürüm ayrı `personal.db` kullanır. Mevcut kullanıcı veri dosyaları bu kaynak temizliğinin parçası değildir.

Linux üzerinde arka plan servisi, yerel tarayıcı paneli ve **GNOME Shell 51 panel eklentisi** sunulur. Eklentiyle durumları ve son olayları tarayıcı açmadan görebilir, güvenilir listeye ekleyebilir ve manual/auto modunda süreli engelleri yönetebilirsiniz. Eklenti mevcut yerel servise bağlanır; tarayıcı eklentisi değildir. [GNOME eklentisini kur](memOShield/desktop/README.md). Güvenlik modeli: [SECURITY.md](memOShield/SECURITY.md).
