# Ubuntu / systemd Deployment Notes for memOShield

Bu belge, memOShield'un Ubuntu üzerinde production amaçlı çalıştırılması için temel adımları içerir.

1) Sistem Hazırlığı

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip golang-go docker.io
```

2) Python virtualenv ve bağımlılıklar

```bash
cd /opt/memOShield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3) Go engine (alternatif performans motoru)

```bash
cd go-engine
go build -o memoengine .
sudo cp memoengine /usr/local/bin/
```

4) systemd servis örneği

- `/etc/systemd/system/memoshield-go.service`

```
[Unit]
Description=memOShield Go Engine
After=network.target

[Service]
User=memoshield
Group=memoshield
ExecStart=/usr/local/bin/memoengine
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

- `memoshield-python.service` için benzer bir yapı: `ExecStart=/opt/memOShield/venv/bin/python /opt/memOShield/app.py`

Ortam değişkenleri (örnek):

Create `/etc/memoshield.env` with:

```
# memoshield env
AUTH_TOKEN=s3cr3t
# Optional TLS cert paths
TLS_CERT=/etc/ssl/certs/memoshield.crt
TLS_KEY=/etc/ssl/private/memoshield.key
```

And update service file to load it:

```
[Service]
EnvironmentFile=/etc/memoshield.env
ExecStart=/usr/local/bin/memoengine
```

If you prefer mutual-TLS, terminate TLS at a reverse proxy (nginx) and secure the backend via mTLS or internal network.

5) Firewall entegrasyonu

- production ortamda `iptables` veya `nftables` kullanın. Go core engine doğrudan AF_PACKET/pcap ile paket toplayıp, tespit edildiğinde hızlıca `nft`/`iptables` kuralı eklemelidir.

6) Güvenlik

- Hizmetler arasında TLS ve token tabanlı bir auth uygulanmalı.
- `GODEBUG` veya log seviyeleri prod/ops gereksinimine göre ayarlanmalı.

7) İzleme

- systemd journal (journalctl -u memoshield-go) ile logları izleyin.
- Prometheus export eklemek istenirse /metrics endpointi eklenebilir.

