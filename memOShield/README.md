# memOShield Personal — Go uygulaması

Güncel özellikler ve başlangıç adımları: [ana README](../README.md).

Bu dizinde:

```sh
go build -o memoshield-personal .
./memoshield-personal
```

Kurulum: [deployment.md](docs/deployment.md). Mimari: [personal-design.md](docs/personal-design.md).

Uygulama `internal/personal`, ayrı firewall yardımcı süreci `cmd/memoshield-fw` ve `internal/firewallctl` üzerinden çalışır. Panel dosyaları `internal/personal/ui` içinden binary'ye gömülür. Güvenlik modeli: [SECURITY.md](SECURITY.md).
