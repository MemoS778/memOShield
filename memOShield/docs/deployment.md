# Yerel Linux kurulumu

İlk hedef CachyOS/Arch + GNOME 51. Masaüstü bağımlılıkları ve eklenti için [masaüstü rehberi](../desktop/README.md). Go 1.26+ gerekir. Aşağıdaki komutlar `go.mod` dosyasının bulunduğu dizinden çalıştırılır.

## 1. Derleme ve masaüstü

```sh
go build -o memoshield-personal .
go build -o memoshield-fw ./cmd/memoshield-fw
sh desktop/install.sh
```

Servis elle `./memoshield-personal`, pencere `~/.local/bin/memoshield-desktop` ile başlatılır. Tarayıcı girişi yoktur. Varsayılan iletişim `$XDG_RUNTIME_DIR/memoshield/control.sock`; anahtar `~/.local/state/memoshield/access-token` dosyasından otomatik okunur. Özel yollar ve XDG fallback davranışı masaüstü rehberindedir.

## 2. Kullanıcı servisi

`deploy/memoshield-personal.service` içindeki `ExecStart` yolunu derlediğiniz binary'nin mutlak yoluna ayarlayın. Dosyayı `~/.config/systemd/user/memoshield-personal.service` konumuna yerleştirin:

```sh
systemctl --user daemon-reload
systemctl --user enable --now memoshield-personal.service
systemctl --user status memoshield-personal.service
journalctl --user -u memoshield-personal.service -n 40
```

Servis kullanıcı oturumuyla çalışır; oturum kapalıyken çalışma için ayrıca systemd linger politikası gerekir. Durdurmak için `systemctl --user disable --now memoshield-personal.service`.

Güncellemede çalışan binary'yi doğrudan üzerine yazmak yerine:

```sh
go build -o memoshield-personal.next .
mv memoshield-personal.next memoshield-personal
systemctl --user restart memoshield-personal.service
```

Masaüstü dosyaları için `sh desktop/install.sh` komutunu yeniden çalıştırıp pencereyi kapatıp açın.

## 3. SSH günlük erişimi

```sh
journalctl --system -n 1 -o json
journalctl --system SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session -n 10
```

Sensör root `_UID=0` ve `_COMM=sshd`/`sshd-session` metadata'sını doğrular. `logger -t sshd` ile yazılmış sıradan kullanıcı kayıtları otomatik engel oluşturamaz. Erişim yoksa dağıtımınızın journal grup/ACL politikasını uygulayın. `systemd-journal` grubu diğer sistem günlüklerine de erişim verir; grup değişiminden sonra yeniden oturum gerekir.

SSH servisini sırf paneli doldurmak için açmak gerekmez. `watching` durumu günlük kaynağının izlendiğini söyler; SSH portunun açık veya sistemin güvenli olduğunu göstermez.

İlk açılış son 24 saatin en fazla 200 SSH kaydını okur, sonra kalıcı cursor'dan devam eder. Journal vacuum sonrası geçersiz cursor sensör hatası oluşturabilir. Kurtarma için uygulama kapalıyken `personal_checkpoints` tablosundaki `source='journal'` satırı sıfırlanabilir; bu geçmişin yeniden okunmasına neden olur, deduplikasyon korunur.

## 4. İsteğe bağlı Suricata

```sh
sudo pacman -Syu suricata
ip -brief link
```

`/etc/suricata/suricata.yaml` içinde doğru arayüzü, `HOME_NET` ve EVE JSON `alert` çıktısını ayarlayın. Sensörü dağıtımın servis tanımıyla çalıştırın. EVE dosyasını yalnızca okunabilir grup/ACL ile paylaşın; rotation sonrası izinlerin korunmasını sağlayın.

`deploy/personal.rules`, yüksek TCP SYN hacmi için örnek başlangıç kuralıdır. Farklı port sayısını ölçmez, Nmap'i kesin tanımaz; meşru yoğun trafik de uyarı verebilir. Kuralları `suricata -T -c /etc/suricata/suricata.yaml` ile doğrulayın ve uygun kural güncelleme sürecini kullanın.

`systemctl --user edit memoshield-personal` ile:

```ini
[Service]
Environment=MEMOSHIELD_EVE_PATH=/var/log/suricata/eve.json
```

Servisi yeniden başlatın. `watching` dosyanın okunabildiğini, `receiving` bir alert alındığını söyler; gerçek paket yakalama sağlığının bağımsız kontrolü değildir.

Okuyucu tamamlanmamış JSON satırlarını bekler, rename rotation'da eski inode'u tüketip yenisine geçer. Copytruncate çok hızlı yeniden büyürse kayıt kaybı olabilir. İlk okuma dosya başından ve saniyede en fazla 500 satırdır. Suricata uyarıları otomatik engel üretmez. Normal Wi-Fi istemcisi başka iki cihazın tüm trafiğini göremez.

## 5. İsteğe bağlı firewall yardımcısı

Go servisi ve arayüz normal kullanıcıyla kalır. Helper `nft` ve `ip` komutlarına ihtiyaç duyar. Binary'yi kullanıcı tarafından değiştirilemeyen root-owned konuma kurun:

```sh
sudo install -o root -g root -m 0755 memoshield-fw /usr/local/sbin/memoshield-fw
id -u
```

`deploy/memoshield-firewall.service` içindeki `--uid 1000` değerini kullanıcı UID'nize ayarlayıp dosyayı `/etc/systemd/system/memoshield-firewall.service` olarak kurun:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now memoshield-firewall.service
```

Kullanıcı servisine `systemctl --user edit memoshield-personal` ile ekleyin:

```ini
[Service]
Environment=MEMOSHIELD_MODE=manual
```

Ardından kullanıcı servisini yeniden başlatın. `auto`, yalnızca son 30 saniye içinde alınmış yerel SSH kayıtlarından iki dakikada en az 10 parola hatasında 10 dakikalık engel ekler. Tarihsel replay engel üretmez.

### İşlem kapsamı

- Helper socket'i seçilen kullanıcıya `0600`; kontrol API'sinden ayrı bir socket'tir.
- Yalnızca `inet memoshield_personal` tablosu ve gelen INPUT kaynak IP trafiği yönetilir; FORWARD trafiği korunmaz.
- En fazla 256 IP ve 1–60 dakika. Kernel timeout, uygulamalar dursa da süreyi bitirir.
- Yerel adres/gateway ve görülebilen DNS adresleri korunur. systemd-resolved upstream DNS adresleri görünmeyebilir; gerekirse güvenilir listeye ekleyin.
- Her 10 saniyede tek nft transaction ile uzlaştırılır. Geçersiz/korunan hedef tüm transaction'ı reddedebilir; hatalı talebi iptal edin.
- `applied` son başarılı işlemdir; dışarıdan ruleset değişiklikleri sonraki uzlaştırmaya kadar fark edilmeyebilir. Uygulamanın tablosu dışarıdan silinirse helper'ı yeniden başlatın.
- `monitor` moduna geçiş önceki kernel engellerini hemen kaldırmaz. Manual modunda iptal edin veya yalnızca uygulamanın tablosunu kaldırın:

```sh
sudo systemctl stop memoshield-firewall.service
sudo nft delete table inet memoshield_personal
```

Güvenlik modeli: [SECURITY.md](../SECURITY.md). Özelliklerin gerçek host üzerindeki etkinliği ayrıca doğrulanmalıdır.
