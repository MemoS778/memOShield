import threading
import time
import collections
import logging
from .db import log_event
from .whitelist import is_whitelisted

class IDS:
    """Rate-limit (eşik) tabanlı IDS.

    - Her IP için zaman damgası kuyruğu tutar.
    - Eşik aşılıp ban uygulanırsa, Firewall üzerinden işlem yapılır.
    - Arka plan sweeper ile süresi dolan banlar (placeholder) temizlenir.
    """
    def __init__(self, firewall, geoip_client=None, threshold=100, window_seconds=10, ban_duration_seconds=3600, port_threshold=20, ua_rules=None):
        self.firewall = firewall
        self.geoip = geoip_client
        self.threshold = threshold
        self.window = window_seconds
        self.ban_duration = ban_duration_seconds
        self.port_threshold = port_threshold
        self.ua_rules = ua_rules or []
        self._events = collections.defaultdict(collections.deque)
        # track ports seen per ip in sliding window
        self._ports = collections.defaultdict(lambda: collections.defaultdict(float))
        self._banned = {}  # ip -> banned_at
        self._lock = threading.Lock()
        self._stop = False
        self._sweeper = threading.Thread(target=self._sweeper_loop, daemon=True)

    def start(self):
        if not self._sweeper.is_alive():
            self._sweeper.start()

    def stop(self):
        self._stop = True
        self._sweeper.join(timeout=1)

    def record_packet(self, src_ip, dest_port=None, user_agent=None):
        now = time.time()
        if is_whitelisted(src_ip):
            logging.debug('IDS: %s is whitelisted, skipping', src_ip)
            return
        with self._lock:
            dq = self._events[src_ip]
            dq.append(now)
            # temizle
            while dq and dq[0] < now - self.window:
                dq.popleft()
            count = len(dq)
            if count >= self.threshold and src_ip not in self._banned:
                self._banned[src_ip] = now
                reason = f"IDS threshold {count}/{self.window}s"
                self.firewall.add_rule(src_ip, reason=reason)
                geo = self.geoip.lookup(src_ip) if self.geoip else {'country':'Unknown','lat':None,'lon':None}
                country = geo.get('country', 'Unknown')
                lat = geo.get('lat')
                lon = geo.get('lon')
                log_event(src_ip, country, 'DoS/DDoS', reason, lat=lat, lon=lon)
                logging.warning('IDS: banned %s (%d packets)', src_ip, count)

            # port scan detection: record port and check unique ports
            if dest_port is not None:
                ports_map = self._ports[src_ip]
                ports_map[dest_port] = now
                # cleanup old ports
                for p, ts in list(ports_map.items()):
                    if ts < now - self.window:
                        del ports_map[p]
                if len(ports_map) >= self.port_threshold and src_ip not in self._banned:
                    self._banned[src_ip] = now
                    reason = f"Port-scan detected ({len(ports_map)} ports)"
                    self.firewall.add_rule(src_ip, reason=reason)
                    geo = self.geoip.lookup(src_ip) if self.geoip else {'country':'Unknown','lat':None,'lon':None}
                    log_event(src_ip, geo.get('country','Unknown'), 'PortScan', reason, lat=geo.get('lat'), lon=geo.get('lon'))
                    logging.warning('IDS: port-scan banned %s (%d ports)', src_ip, len(ports_map))

            # user-agent analysis
            if user_agent:
                for rule in self.ua_rules:
                    if rule.lower() in user_agent.lower():
                        if src_ip not in self._banned:
                            self._banned[src_ip] = now
                            reason = f"User-Agent rule matched: {rule}"
                            self.firewall.add_rule(src_ip, reason=reason)
                            geo = self.geoip.lookup(src_ip) if self.geoip else {'country':'Unknown','lat':None,'lon':None}
                            log_event(src_ip, geo.get('country','Unknown'), 'UA-Detect', reason, lat=geo.get('lat'), lon=geo.get('lon'))
                            logging.warning('IDS: UA banned %s rule=%s', src_ip, rule)

    def _sweeper_loop(self):
        while not self._stop:
            now = time.time()
            to_unban = []
            with self._lock:
                for ip, banned_at in list(self._banned.items()):
                    if now - banned_at > self.ban_duration:
                        to_unban.append(ip)
                        del self._banned[ip]
                        # Not: firewall removal mantığı platforma göre eklenebilir
            time.sleep(5)
