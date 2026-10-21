# Linux üzerinde kişisel kullanım

> **Masaüstü geçişi:** Güncel servis TCP portu ve web paneli sunmaz. Güncel kurulum için [masaüstü rehberini](../desktop/README.md) kullanın. Bu sayfadaki SSH, Suricata ve ayrı firewall yardımcısı kurulumu geçerlidir; tarayıcı girişine ve 5000 portuna ilişkin adımlar önceki sürüme aittir. Native servis önerilir; önceki Docker panel örneği güncel masaüstü dağıtımı değildir.

## 1. Derleme ve izleme

Go 1.26+ ile, uygulamanın `go.mod` dosyasının bulunduğu dizinde:

```sh
go build -o memoshield-personal .
go build -o memoshield-fw ./cmd/memoshield-fw
./memoshield-personal
```

Yönetim paneli yalnızca `127.0.0.1:5000` üzerinde açılır. Parola yerine ilk açılışta oluşturulan `~/.local/state/memoshield/access-token` dosyasındaki rastgele anahtar kullanılır. `XDG_STATE_HOME` ayarlıysa yol değişir. Bu dosyayı paylaşmayın. Anahtarı yenilemek için uygulama kapalıyken dosyayı kaldırıp yeniden başlatın; mevcut oturumlar zaten yeniden başlatmada geçersizleşir.

## 2. Kullanıcı servisi

`deploy/memoshield-personal.service` örneğindeki `ExecStart` yolunu kendi derlediğiniz binary'nin mutlak yoluna ayarlayın. Dosyayı `~/.config/systemd/user/memoshield-personal.service` olarak yerleştirin:

```sh
systemctl --user daemon-reload
systemctl --user enable --now memoshield-personal.service
systemctl --user status memoshield-personal.service
journalctl --user -u memoshield-personal.service -n 40
```

Bu servis kullanıcı oturumu ile çalışır; oturum kapalıyken çalışması için ayrıca systemd linger politikası gerekir. Kapatmak için `systemctl --user disable --now memoshield-personal.service`.

Tarayıcı açmadan GNOME üst panelinden kullanmak için [GNOME Shell 51 eklentisini](../desktop/README.md) kurabilirsiniz. Eklenti bu kullanıcı servisini kullanır; servisin yerini almaz.

## 3. SSH günlük erişimi

Uygulama `journalctl --system` ile yalnızca SSH etiketli kayıtları takip eder. Root `_UID=0` ve `_COMM=sshd`/`sshd-session` metadata doğrulaması yapılır. Bir kullanıcının `logger -t sshd` ile yazdığı satır otomatik engel üretemez.

Kendi terminalinizde sistem günlüğüne erişimi kontrol edin:

```sh
journalctl --system -n 1 -o json
journalctl --system SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session -n 10
```

Erişim yoksa dağıtımınızın journal grup/ACL politikasını kullanın. Örneğin yönetici tarafından `systemd-journal` grubuna ekleme yapılabilir; grup değişimi sonrası oturumu yeniden açmak gerekir. Bu grup diğer sistem günlüklerini de okumaya izin verir. SSH servisi yoksa bunu sırf test için açmak gerekmez. Panelde SSH sensörü hazır görünmesi SSH portunun açık olduğunu göstermez.

İlk açılışta son 24 saatin en fazla 200 SSH kaydı alınır; sonraki açılışlarda kalıcı cursor'dan devam edilir. Journal dosyalarının tamamen silinmesi/taşınması sonucu geçersiz cursor oluşursa sensör hata gösterir. `personal_checkpoints` tablosundaki `source='journal'` satırını uygulama kapalıyken silmek geçmişe dönüşü sıfırlar; olay deduplikasyonu korunur.

## 4. Suricata: gerçek ağ uyarıları

Suricata uygulamaya gömülü değildir. CachyOS/Arch üzerinde yönetici terminalinde:

```sh
sudo pacman -Syu suricata
ip -brief link
```

Dağıtımın `/etc/suricata/suricata.yaml` yapılandırmasında doğru arayüzü ve `HOME_NET` değerini seçin; EVE JSON `alert` çıktısını açın. Kendi bilgisayarını hedefleyen olaylar için `HOME_NET` bu bilgisayarın adreslerini kapsamalıdır. Kurulumun sensör yerleşimine göre ağ kapsamı değişir.

`deploy/personal.rules` isteğe bağlı, yüksek TCP SYN hacmi için başlangıç kuralıdır. **Tek başına farklı port sayısını ölçmez ve Nmap'i kesin tanımaz.** Meşru yoğun bağlantılar da uyarı üretebilir. Kuralı mevcut kurallarınıza ekleyip `suricata -T -c /etc/suricata/suricata.yaml` ile doğrulayın; genel tespit kapsamı için dağıtımın uygun kural güncelleme iş akışını kullanın.

Sensörü dağıtımın servis tanımıyla çalıştırın. EVE dosyasını panel kullanıcısının sadece okuyabileceği bir grup/ACL ile paylaşın; dosyayı herkese yazılabilir yapmayın. Rotation sonrası yeni dosyanın aynı erişim politikasını korumasını sağlayın.

Paneli şu ortam değişkeniyle başlatın:

```sh
MEMOSHIELD_EVE_PATH=/var/log/suricata/eve.json ./memoshield-personal
```

Kullanıcı servisinde `systemctl --user edit memoshield-personal` ile:

```ini
[Service]
Environment=MEMOSHIELD_EVE_PATH=/var/log/suricata/eve.json
```

Ardından servisi yeniden başlatın. `watching` yalnızca dosyanın okunabildiğini, `receiving` ise bir alert kaydı alındığını belirtir. Son olay zamanı panelde görünür; sensör sürecinin çalıştığına tek başına kanıt değildir.

Okuyucu partial JSON satırlarını bekler, inode değişiminde eski dosyayı tüketip yenisine geçer. Kalıcı offset ve içerik anahtarı tekrarları önler. Rename rotation tercih edin; copytruncate çok hızlı yeniden büyürse arada kayıp olabilir. Mevcut EVE dosyası ilk seferde baştan, saniyede en fazla 500 satır okunur. Suricata uyarıları otomatik engelleme yapmaz.

Normal Wi-Fi bağlantısında başka müşteriler ile kameralar arasındaki trafik görünmeyebilir. Ağ çapındaki kullanım router/AP veya SPAN sensörü gerektirir; panel Wi-Fi monitor mode veya aktif tarama başlatmaz.

## 5. İsteğe bağlı IPS yardımcı süreci

Önce izleme sonuçlarını değerlendirin. Web uygulaması normal kullanıcıyla kalır. Yalnızca derlenmiş `memoshield-fw` root olarak çalıştırılır. Helper `nft` ve `ip` komutlarına ihtiyaç duyar.

Binary'yi root-owned bir konuma kurun; kullanıcı tarafından değiştirilebilir proje yolunu root servisine vermeyin:

```sh
sudo install -o root -g root -m 0755 memoshield-fw /usr/local/sbin/memoshield-fw
id -u
```

`deploy/memoshield-firewall.service` içindeki `--uid 1000` değerini panel kullanıcısının UID'sine ayarlayıp `/etc/systemd/system/memoshield-firewall.service` olarak kurun. Sonra:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now memoshield-firewall.service
```

Socket `0600` ile sadece seçilen kullanıcıya açılır. Yardımcı süreç yalnızca kendi `inet memoshield_personal` tablosunu kullanır; genel ruleset veya diğer firewall tabloları temizlenmez. Sadece INPUT yönünde kaynak IP engellenir, başka cihazlara giden FORWARD trafiği korunmaz.

Paneli `MEMOSHIELD_MODE=manual` ile yeniden başlatın. `auto` modunu seçerseniz yalnızca taze SSH parola hataları otomatik engelleme üretir. Ağ geçidi, yerel IP'ler ve `/etc/resolv.conf` DNS adresleri helper tarafından her işlemde korunur; systemd-resolved arkasındaki upstream DNS adresleri görünmeyebilir, bunları güvenilir listeye ekleyin. Panelde CIDR güvenilir listesi eklenmesi mevcut eşleşen engellerin kaldırılmasını da talep eder.

Her 10 saniyede istenen engeller tek nft transaction ile uzlaştırılır. Tek bir geçersiz/korunan hedef tüm transaction'ı reddeder; hata panelde görünür, hatalı talebi iptal edin. En fazla 256 aktif IP, en fazla 60 dakika. Kernel timeout sayesinde uygulama kapansa bile engel süresi dolacaktır. `monitor` moduna geçmek önceki engelleri hemen kaldırmaz; mevcut kernel süreleri dolar. Hemen kaldırmak için manual modunda iptal edin veya yönetici olarak yalnızca uygulamanın tablosunu silin:

```sh
sudo systemctl stop memoshield-firewall.service
sudo nft delete table inet memoshield_personal
```

Helper yeniden başladığında kurallar kurulur, setler panelin ilk uzlaştırmasına kadar önceki kernel durumunu koruyabilir. Başka bir araç uygulamanın tablosunu silerse helper'ı yeniden başlatın. Panelin `applied` durumu son başarılı transaction'ı gösterir; dışarıdan yapılan firewall değişiklikleri ancak sonraki uzlaştırmada fark edilir.

## Docker

Docker imajı yalnızca izole panel/EVE okuyucusu içindir; host journal ve host firewall otomatik olarak erişilebilir değildir. Kişisel bilgisayar kullanımı için native kullanıcı servisi tercih edilir.

```sh
docker build -t memoshield-personal .
docker run --rm --network host -e MEMOSHIELD_JOURNAL=0 -v memoshield-state:/data memoshield-personal
```

Linux host network kullanımı loopback bind ve Host doğrulamasını korur. Bu örnekte de sadece yerel panel vardır; `--privileged` kullanmayın. Kalıcı volume'un imaj UID 10001 için yazılabilir olması gerekir.
