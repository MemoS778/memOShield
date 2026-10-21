# memOShield masaüstü

GTK4/libadwaita ile siyah–kırmızı yerel uygulama. WebView, tarayıcı paneli veya TCP dinleyicisi yoktur. GNOME eklentisi yalnızca kısa durum, son üç olay ve uygulamayı açma işlevi sunar. Pencereyi kapatmak arka plan servisini durdurmaz.

## Gereksinimler

İlk doğrulama hedefi CachyOS/Arch + GNOME 51: Go 1.26+, GJS, GTK 4.10+, libadwaita, libsoup 3. Native pencere GNOME Shell'e bağımlı değildir; Hyprland üzerinde ayrı doğrulama henüz yapılmadı. Diğer dağıtımlar sonraki aşamadır.

## Kurulum

`memOShield/go.mod` dosyasının bulunduğu dizinde:

```sh
go build -o memoshield-personal .
sh desktop/install.sh
```

Mevcut kullanıcı servisinin ExecStart yolu yeni binary'yi göstermelidir. Servis çalışırken binary'yi üzerine yazmak yerine yeni bir dosyaya derleyip atomik olarak değiştirin. Ardından:

```sh
systemctl --user restart memoshield-personal.service
~/.local/bin/memoshield-desktop
```

Uygulamalar menüsünden de **memOShield** açılabilir. Tek uygulama kimliği aynı kullanıcı oturumunda ikinci pencere yerine mevcut pencereye odaklanır.

Varsayılan socket `$XDG_RUNTIME_DIR/memoshield/control.sock`. Runtime dizini yoksa `~/.local/state/memoshield/memoshield/control.sock` kullanılır (`XDG_STATE_HOME` desteklenir). Servis ve uygulama için `MEMOSHIELD_SOCKET` aynı mutlak yolu göstermelidir. Anahtar standart state dizinindeki `memoshield/access-token` dosyasından otomatik okunur. Özel `MEMOSHIELD_DATA_DIR` kullanıyorsanız masaüstü uygulamasını da aynı ortam değişkeniyle başlatın; GNOME eklentisinde anahtar dosyasının tam yolunu seçin.

## GNOME hızlı erişim

```sh
mkdir -p build
gnome-extensions pack desktop/gnome --extra-source=client.js --out-dir=build --force
gnome-extensions install --force build/memoshield@MemoS778.shell-extension.zip
gnome-extensions enable memoshield@MemoS778
```

Gerekirse oturumu kapatıp açın. Eklenti ayarlarında özel socket ve anahtar yolu seçilebilir. Yeni ayarlar eklenti yeniden etkinleştirildiğinde uygulanır.

## Mevcut ekranlar

- Genel bakış: son olaylar ve sensör durumları.
- Olay geçmişi: en yeni 200 olay, güvenilir liste ve süreli engel işlemleri.
- Koruma: engel durumları ve güvenilir IP/CIDR yönetimi.
- Ayarlar: bağlantı ve sensör tanılama; servis modu burada değiştirilemez.
- Değişiklikler: henüz hazırlık ekranı. Envanter/sistem değişikliği sensörleri uygulanmadı.

`monitor` modunda engelleme kapalıdır. Gerçek engelleme ayrı firewall yardımcısı gerektirir. `applied` son başarılı nft işlemini gösterir, kesintisiz bağımsız trafik doğrulaması değildir. SSH/Suricata/helper kurulumu için [deployment.md](../docs/deployment.md).

## Doğrulama

```sh
go test -race ./...
go vet ./...
glib-compile-schemas --strict --dry-run desktop/gnome/schemas
MEMOSHIELD_UI_TEST=1 go test -count=1 -run TestNativeUnixSocketClient ./internal/personal
```

Son komut grafik oturumu veya Xvfb gerektirir. Geçici SQLite, özel Unix socket, gerçek GJS/libsoup istemcisi ve GTK sayfalarını kullanır; kişisel verileri veya host firewall'u değiştirmez. GTK testi görünümün görsel/erişilebilirlik denetiminin yerine geçmez.

Kaldırma: `~/.local/bin/memoshield-desktop`, `$XDG_DATA_HOME/memoshield` ve `$XDG_DATA_HOME/applications/io.github.MemoS778.memOShield.desktop` dosyalarını kaldırın (`XDG_DATA_HOME` varsayılanı `~/.local/share`). Bu işlem servis veya olay veritabanını silmez.
