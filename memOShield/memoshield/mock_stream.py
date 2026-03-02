import threading
import time
import random
import os
from .db import log_event

ATTACK_TYPES = ['Honeypot Trigger','Port Scan','DoS/DDoS','Brute Force','SQL Injection','XSS']
SAMPLE_COUNTRIES = [
    ('US',37.7749,-122.4194),('TR',39.9255,32.8663),('DE',52.52,13.405),
    ('RU',55.7558,37.6173),('CN',39.9042,116.4074),('BR',-23.5505,-46.6333),
]

_stop = False

def _emit_one():
    ip = '.'.join(str(random.randint(1,254)) for _ in range(4))
    country, lat, lon = random.choice(SAMPLE_COUNTRIES)
    attack = random.choice(ATTACK_TYPES)
    details = f"Live mock: {attack} from {ip}"
    try:
        log_event(ip, country, attack, details, lat=lat + random.uniform(-0.5,0.5), lon=lon + random.uniform(-0.5,0.5))
    except Exception:
        pass


def _steady(interval=3):
    while not _stop:
        _emit_one()
        time.sleep(interval)


def _burst(burst_size=10, base_interval=10, spread=0.5):
    while not _stop:
        # wait base interval
        time.sleep(base_interval)
        # emit a burst of events quickly
        for _ in range(burst_size):
            if _stop: break
            _emit_one()
            time.sleep(max(0.05, base_interval * spread / burst_size))


def _randomized(min_interval=1, max_interval=5):
    while not _stop:
        _emit_one()
        time.sleep(random.uniform(min_interval, max_interval))


def start(mode='steady', interval=3, burst_size=10, base_interval=10):
    """Start mock stream in given mode. Modes: 'steady', 'burst', 'random'"""
    global _stop
    _stop = False
    m = os.environ.get('MOCK_STREAM_MODE', mode)
    try:
        if m == 'burst':
            t = threading.Thread(target=_burst, args=(int(burst_size), int(base_interval)), daemon=True)
        elif m == 'random':
            t = threading.Thread(target=_randomized, args=(1, max(2, int(interval))), daemon=True)
        else:
            t = threading.Thread(target=_steady, args=(int(interval),), daemon=True)
        t.start()
        return t
    except Exception:
        return None


def stop():
    global _stop
    _stop = True
