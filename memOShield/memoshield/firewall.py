import platform
import subprocess
import logging
from .db import add_rule as db_add_rule, add_ban as db_add_ban
import datetime

class Firewall:
    """Basit, platform-a bağımlı olmayan firewall soyutlaması.

    - Geliştirme: Windows üzerinde simüle eder (DB'ye yazar).
    - Prod (Linux): yorum satırındaki iptables çağrılarını kullanabilirsiniz (root gerektirir).
    """
    def __init__(self):
        self.is_linux = platform.system() == 'Linux'
        self._rules = []

    def add_rule(self, ip, reason='manual'):
        ts = datetime.datetime.utcnow().isoformat()
        self._rules.append({'ip': ip, 'reason': reason, 'created_at': ts})
        db_add_rule(ip, reason)
        db_add_ban(ip, reason)
        logging.info('Firewall: added rule %s (%s)', ip, reason)

        if self.is_linux:
            try:
                # Örnek (kullanmak için root ve iptables gereklidir):
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            except Exception as e:
                logging.warning('OS firewall apply failed (need root): %s', e)
        return True

    def remove_rule(self, ip):
        self._rules = [r for r in self._rules if r['ip'] != ip]
        logging.info('Firewall: removed (in-memory) %s', ip)
        # Gerçek ortam için iptables -D komutu eklenebilir.
        return True

    def list_rules(self):
        return list(self._rules)
