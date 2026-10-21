# memOShield Personal

**Bilgisayarımda güvenlikle ilgili ne değişti?** sorusunu cevaplamayı hedefleyen, Linux için yerel güvenlik kontrol merkezi.

Go + SQLite arka plan servisi, siyah–kırmızı **GTK4/libadwaita masaüstü uygulaması** ve GNOME üst panelinden hızlı erişim. Proje **v4 masaüstü ön sürümü** aşamasındadır.

**Tarayıcı paneli, WebView ve TCP dinleyicisi yoktur.** Arayüzler kullanıcıya özel Unix socket üzerinden servise bağlanır. Yerel anahtar otomatik okunur; elle giriş gerekmez.

## Mevcut özellikler

- Root-owned `sshd` / `sshd-session` journal kayıtlarından belirli başarılı ve başarısız SSH girişleri.
- İki dakikada en az 10 başarısız SSH parola girişinin ilişkilendirilmesi.
- İsteğe bağlı harici Suricata EVE `alert` kayıtları.
- SQLite olay geçmişi, tekrar önleme ve kalıcı sensör checkpoint'leri.
- Yerel pencerede sensör durumu, olay arama, JSON dışa aktarımı ve koruma yönetimi.
- Kalıcı güvenilir IP/CIDR listesi.
- Ayrı firewall yardımcısıyla süreli nftables INPUT kaynak IP engelleri.
- GNOME panelinde kısa durum, son üç olay ve uygulamayı açma.

## Yol haritası

| Aşama | Kapsam | Durum |
|---|---|---|
| Yerel masaüstü | GTK pencere, Unix socket, GNOME hızlı erişim | Uygulandı |
| Envanter | İlk gözlenen durumun kalıcı kaydı ve karşılaştırma altyapısı | Sıradaki aşama |
| Ağ değişiklikleri | Yeni/kapanan dinleme noktaları ve dinleme adresi değişiklikleri | Planlandı |
| Başlangıç değişiklikleri | Otomatik başlangıç girdileri ve seçilmiş servis değişiklikleri | Planlandı |
| Güvenlik ayarları | Seçilmiş SSH ayarlarında önce/sonra karşılaştırması | Planlandı |
| Uyumluluk | Hyprland doğrulaması, ardından diğer dağıtımlar | Planlandı |

Yeni olaylar **ne değişti, nereden biliyoruz, neden önemli olabilir, ne yapılabilir** biçiminde açıklanacak. İlk envanter güvenli sistem onayı sayılmayacak; okunamayan kaynaklar silinmiş olarak yorumlanmayacak.

**Envanter ve değişiklik sensörleri henüz uygulanmadı.** Değişiklikler sayfası hazırlık durumunu gösterir. Mevcut SSH ve Suricata olay toplama işlevleri kullanılabilir.

## Başlangıç

İlk hedef: CachyOS/Arch ve GNOME 51. Go 1.26+, GJS, GTK **4.10+**, libadwaita ve libsoup 3 gerekir. Hyprland'da yerel pencere uyumluluğu sonraki doğrulama hedefidir; GNOME panel eklentisi Hyprland'da çalışmaz.

Arch/CachyOS üzerinde masaüstü bağımlılıkları:

```sh
sudo pacman -S --needed gjs gtk4 libadwaita libsoup3
```

```sh
git clone https://github.com/MemoS778/memOShield.git
cd memOShield/memOShield
go build -o memoshield-personal .
sh desktop/install.sh
./memoshield-personal
```

Başka bir terminalde `~/.local/bin/memoshield-desktop` veya uygulamalar menüsünden memOShield. Kalıcı servis ve eklenti kurulumu: **[Masaüstü rehberi](memOShield/desktop/README.md)**.

## Çalışma modları

| Mod | Davranış |
|---|---|
| `monitor` | Varsayılan; olay toplar, engelleme yapmaz. |
| `manual` | Kullanıcı kararıyla 1–60 dakikalık engeller; helper gerekir. |
| `auto` | Manuel işlemlere ek olarak taze yerel SSH parola hataları eşik aştığında 10 dakikalık engel. |

Suricata uyarıları otomatik engel üretmez. Tarihsel SSH kayıtları otomatik engel oluşturmaz. `applied` son başarılı firewall transaction'ını gösterir; sürekli bağımsız trafik doğrulaması değildir. Başarısız işlemler `unconfirmed` görünür.

## Yapılandırma

| Değişken | Varsayılan |
|---|---|
| `MEMOSHIELD_SOCKET` | `$XDG_RUNTIME_DIR/memoshield/control.sock`; fallback için masaüstü rehberi |
| `MEMOSHIELD_DATA_DIR` | `$XDG_STATE_HOME/memoshield` veya `~/.local/state/memoshield` |
| `MEMOSHIELD_MODE` | `monitor` |
| `MEMOSHIELD_JOURNAL` | `1`; kapatmak için `0` |
| `MEMOSHIELD_EVE_PATH` | Boş; ör. `/var/log/suricata/eve.json` |
| `MEMOSHIELD_FIREWALL_SOCKET` | `/run/memoshield/firewall.sock` |

Olaylar 30 gün / yaklaşık 100.000 kayıt sınırıyla saklanır. Görünüm ve JSON dışa aktarımı en yeni 200 kayıtla sınırlıdır; tam veritabanı yedeği değildir.

## Kaynak yapısı

```text
memOShield/
├── main.go                 Go servisinin giriş noktası
├── internal/personal/      Olay motoru, sensörler, SQLite ve yerel API
├── internal/firewallctl/   Sınırlı firewall protokolü
├── cmd/memoshield-fw/      Yetkili nftables yardımcı süreci
├── desktop/app/            GTK4/libadwaita uygulaması ve tema
├── desktop/gnome/          GNOME hızlı erişimi ve ortak yerel istemci
├── deploy/                systemd servisleri ve örnek Suricata kuralı
└── docs/                  Kurulum ve mimari
```

## Sınırlar

Antivirüs, genel DDoS koruması, WAF veya tüm Wi-Fi ağını izleyen bir ürün değildir. Varsayılan kurulum paket yakalamaz; Suricata ayrıca kurulmalıdır. IP adresi kişi kimliği veya başarılı saldırı kanıtı değildir. Aynı kullanıcı hesabını ele geçiren süreçler yerel anahtara ve verilere erişebilir.

- [Güvenlik modeli](memOShield/SECURITY.md)
- [Mimari ve geliştirme planı](memOShield/docs/personal-design.md)
- [SSH, Suricata ve firewall kurulumu](memOShield/docs/deployment.md)

## Test

```sh
cd memOShield  # depo kökünden
go test -race ./...
go vet ./...
MEMOSHIELD_UI_TEST=1 go test -count=1 -run TestNativeUnixSocketClient ./internal/personal
```

GTK testi grafik oturumu veya Xvfb gerektirir. Geçici veritabanı ve Unix socket kullanır; host firewall'u değiştirmez. CI ayrıca Go bağımlılık zafiyet taramasını çalıştırır.
