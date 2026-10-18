# GNOME panel eklentisi

GNOME Shell **51** için `memoshield@MemoS778`. Tarayıcı sekmesi yerine üst paneldeki menüden çalışır. KDE Plasma ve tarayıcı eklentisi değildir.

## Neler sunar?

- 15 saniyede bir çalışma modu, sensör durumu ve en yeni 200 kayıt içindeki olay sayısı.
- Son 5 olayın zamanı, kaynak IP'si ve kanıt metni; IP kopyalama ve güvenilir listeye ekleme.
- `manual` / `auto` modunda olayın IP'sini 10 dakika engelleme ve mevcut süreli engelleme taleplerini kaldırma.
- Yerel servis kapalı olduğunda bağlantı hatası. Bağlantı varlığı, sistemin saldırısız olduğunu göstermez.
- Servis adresi ve anahtar dosyası yolu için GNOME ayar penceresi.

## Gereksinimler

GNOME Shell 51, GJS, libsoup 3, GNOME Extensions araçları; ayar penceresi için GTK4/libadwaita. Ayrıca [kurulum belgesindeki](../docs/deployment.md) `memoshield-personal` kullanıcı servisi çalışmalıdır. Gerçek engelleme için ayrı firewall yardımcı süreci gerekir.

Eklenti sensör motoru değildir. Paneli veya eklentiyi kapatmak servisi durdurmaz; var olan kernel engelleri süreleri dolana kadar kalabilir. Tarayıcı panelini açmak zorunlu değildir, ancak mevcut loopback API servisi çalışmaya devam eder.

## Paketleme ve kurulum

`memOShield/go.mod` dosyasının bulunduğu dizinde:

```sh
mkdir -p build
gnome-extensions pack desktop/gnome --extra-source=client.js --out-dir=build --force
gnome-extensions install --force build/memoshield@MemoS778.shell-extension.zip
gnome-extensions enable memoshield@MemoS778
```

Yeni eklenti mevcut oturumda tanınmazsa oturumu kapatıp yeniden açın ve son komutu tekrar çalıştırın. Wayland oturumunda Shell'i zorla yeniden başlatmayın. Durum ve ayarlar:

```sh
gnome-extensions info memoshield@MemoS778
gnome-extensions prefs memoshield@MemoS778
systemctl --user status memoshield-personal.service
```

Varsayılan bağlantı `http://127.0.0.1:5000`; anahtar `${XDG_STATE_HOME:-$HOME/.local/state}/memoshield/access-token` dosyasından okunur. Özel `MEMOSHIELD_DATA_DIR` veya port kullanıyorsanız eklenti ayarlarını buna göre değiştirin. Anahtarın kendisi GSettings'e kaydedilmez. HTTP proxy kullanılmaz, yönlendirmeler takip edilmez, yalnızca izin verilen loopback adreslerine bağlanılır.

Kaldırmak için:

```sh
gnome-extensions disable memoshield@MemoS778
gnome-extensions uninstall memoshield@MemoS778
```

Bu işlem kişisel servisi ve veritabanını kaldırmaz.

## Geliştirme testi

GJS ve libsoup 3 kurulu ortamda, `tests/ui` dizininde:

```sh
npm ci
npx playwright install chromium
GNOME_CLIENT_TEST=1 npm test
```

Test geçici bir servis/veritabanı kullanır. GJS istemcisinin gerçek HTTP girişini, cookie kullanımını, izin verilen adresleri, güvenilir listeyi, monitor modundaki engelleme reddini ve yeniden girişini doğrular; ardından tarayıcı testlerini çalıştırır. Bu test GNOME Shell menüsünün görsel testi değildir.
