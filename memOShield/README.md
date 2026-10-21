# memOShield Personal — Go uygulaması

Güncel özellikler ve başlangıç adımları: [ana README](../README.md).

Bu dizinde:

```sh
go build -o memoshield-personal .
./memoshield-personal
```

Masaüstü kurulumu: [desktop/README.md](desktop/README.md). Sensörler ve firewall: [deployment.md](docs/deployment.md). Mimari ve plan: [personal-design.md](docs/personal-design.md).

Servis `internal/personal`, ayrı firewall yardımcı süreci `cmd/memoshield-fw` ve `internal/firewallctl` üzerinden çalışır. Yerel GTK uygulaması `desktop/app`, GNOME hızlı erişimi `desktop/gnome` içindedir. İletişim Unix socket üzerinden gerçekleşir; web paneli yoktur. Envanter/değişiklik sensörleri sonraki aşamadır. Güvenlik modeli: [SECURITY.md](SECURITY.md).
