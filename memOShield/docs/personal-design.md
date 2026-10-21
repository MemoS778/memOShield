# Mimari ve geliştirme planı

## Çalışan yapı

```text
Root-owned SSH journal ─┐
                       ├─ doğrulama → tekrar önleme → SQLite
Suricata EVE alerts ────┘                               │
                                                       ↓
                                            özel Unix socket API
                                               ↙             ↘
                                  GTK4/libadwaita pencere   GNOME hızlı erişim

Taze SSH eşiği / kullanıcı kararı
               ↓
       kalıcı engel talebi
               ↓
    ayrı yetkili firewall yardımcısı
               ↓
    nftables INPUT setleri + kernel timeout
```

Go servisi, GTK uygulaması ve GNOME eklentisi normal kullanıcıyla çalışır. Yalnızca ayrı firewall yardımcısı yetkilidir. Web paneli, WebView veya TCP dinleyicisi yoktur. JSON protokolü Unix socket üzerinden taşınır; oturum, Host, Origin ve gövde doğrulaması yerel API'de yapılır.

GTK uygulaması ayrıntılı arayüzdür. GNOME eklentisi kısa durum, son üç olay ve uygulama başlatmayı sunar. Pencereyi veya eklentiyi kapatmak servisi durdurmaz. Kullanıcı servisi oturumla çalışır; oturum dışı çalışma ayrıca yapılandırılmalıdır.

## Sıradaki aşama: Bilgisayarımda ne değişti?

Bu bölüm plandır; aşağıdaki sensörler henüz uygulanmadı.

1. **Kalıcı envanter:** İzlenen nesneler için ilk/son gözlem, nesne kimliği, önceki/yeni değer ve veri kaynağı.
2. **Dinleme noktaları:** Yeni/kapanan soketler ve dinleme adresi değişiklikleri; IPv4/IPv6 ve mümkünse süreç/servis bilgisi.
3. **Başlangıç girdileri:** Seçilmiş kullanıcı/sistem servisleri ve otomatik başlangıç girdileri.
4. **SSH ayarları:** Include ve koşullu Match kapsamını hesaba katan seçilmiş güvenlik ayarı değişiklikleri.
5. **Açıklanabilir olay kartları:** Ne değişti, hangi kanıt var, neden önemli olabilir, ne yapılabilir?

### Kabul ilkeleri

- İlk görülen durum güvenli kabul edilmez; başlangıç referansıdır.
- İlk taramadaki nesneler yeni oluşmuş gibi bildirilmez.
- Okuma/yetki hatası, nesnelerin kaldırılması olarak yorumlanmaz.
- Yeniden başlatma aynı değişikliği tekrar tekrar üretmez.
- Gözlem zamanı ile değişikliğin kesin gerçekleşme zamanı ayrılır.
- Yeni servis veya port tek başına saldırı olarak etiketlenmez.
- Bir olayı okumak, onu beklenen değişiklik olarak onaylamak değildir.
- İlk aşamada değişiklik sensörleri otomatik sistem müdahalesi başlatmaz.

## Sonraki uyumluluk aşamaları

İlk ortam CachyOS/Arch + GNOME 51. GTK pencere GNOME Shell'e bağımlı değildir; Hyprland uyumluluğu ayrıca test edilecek. Diğer dağıtımlar bu doğrulamadan sonra ele alınacak. Hyprland üzerinde GNOME eklentisi kullanılmaz.

## Mevcut teknik sınırlar

- SSH dışı günlük adaptörleri, dosya bütünlüğü sensörü ve uygulama bazlı dış bağlantı engelleme yoktur.
- Suricata'nın paket yakalaması ve kural yönetimi harici kurulumun sorumluluğudur. EVE dosyasını okumak gerçek sensör canlılığını kanıtlamaz.
- Journal vacuum sonrası geçersiz cursor otomatik sıfırlanmaz; sensör hata verir.
- Değiştirilemez audit izi ve çok kullanıcılı yetkilendirme yoktur.
- `applied` son başarılı nft transaction'ıdır; bağımsız sürekli ruleset/trafik doğrulaması değildir.

## Doğrulama

Go testleri gerçek SQLite, SSH kaynak doğrulaması, zaman pencereleri, tekrar önleme, EVE partial-write/rotation ve firewall hata durumlarını kapsar. Yerel istemci testi gerçek Unix socket ve GJS/libsoup kullanır. İsteğe bağlı GTK smoke testi beş sayfayı açar. HTTP protokol birim testleri yalnızca test sunucusunda auth/Origin/Host/SSE davranışını sınar; üretim servisi TCP açmaz.

Kurulum: [deployment.md](deployment.md). Güven sınırları: [SECURITY.md](../SECURITY.md).
