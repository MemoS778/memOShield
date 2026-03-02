import threading
import socket
import logging
from .db import log_event

class Honeypot:
    def __init__(self, ids, firewall, geoip=None, ports=None):
        self.ids = ids
        self.firewall = firewall
        self.geoip = geoip
        self.ports = ports or [2121, 2323, 3307]
        self._threads = []

    def start(self):
        for p in self.ports:
            t = threading.Thread(target=self._listen_port, args=(p,), daemon=True)
            t.start()
            self._threads.append(t)

    def _listen_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            logging.info('Honeypot listening on port %d', port)
            while True:
                conn, addr = sock.accept()
                src_ip = addr[0]
                logging.info('Honeypot triggered by %s on port %d', src_ip, port)
                geo = self.geoip.lookup(src_ip) if self.geoip else {'country':'Unknown','lat':None,'lon':None}
                country = geo.get('country', 'Unknown')
                lat = geo.get('lat')
                lon = geo.get('lon')
                log_event(src_ip, country, 'Honeypot Trigger', f'Port {port}', lat=lat, lon=lon)
                self.firewall.add_rule(src_ip, reason='Honeypot triggered')
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as e:
            logging.warning('Honeypot port %d failed: %s', port, e)
