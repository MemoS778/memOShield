import sqlite3
import datetime
from .config import DB_PATH

DB_PATH = str(DB_PATH)

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    # events table now includes optional lat/lon for GeoIP visualization
    cur.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            src_ip TEXT,
            country TEXT,
            lat REAL,
            lon REAL,
            attack_type TEXT,
            details TEXT
        )
    ''')
    # ensure historic DBs get new columns
    cur.execute("PRAGMA table_info(events)")
    cols = [r[1] for r in cur.fetchall()]
    if 'lat' not in cols:
        try:
            cur.execute('ALTER TABLE events ADD COLUMN lat REAL')
        except Exception:
            pass
    if 'lon' not in cols:
        try:
            cur.execute('ALTER TABLE events ADD COLUMN lon REAL')
        except Exception:
            pass

    cur.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            src_ip TEXT,
            reason TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            created_at TEXT,
            ip TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

from .broadcaster import broadcaster

def log_event(src_ip, country, attack_type, details, lat=None, lon=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO events (timestamp, src_ip, country, lat, lon, attack_type, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (datetime.datetime.utcnow().isoformat(), src_ip, country, lat, lon, attack_type, details)
    )
    conn.commit()
    conn.close()

    # publish to any realtime subscribers
    try:
        event = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'src_ip': src_ip,
            'country': country,
            'lat': lat,
            'lon': lon,
            'attack_type': attack_type,
            'details': details
        }
        broadcaster.publish(event)
    except Exception:
        pass

def add_ban(src_ip, reason):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('INSERT INTO bans (timestamp, src_ip, reason) VALUES (?, ?, ?)',
                (datetime.datetime.utcnow().isoformat(), src_ip, reason))
    conn.commit()
    conn.close()

def add_rule(ip, reason):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('INSERT INTO rules (created_at, ip, reason) VALUES (?, ?, ?)',
                (datetime.datetime.utcnow().isoformat(), ip, reason))
    conn.commit()
    conn.close()

def get_events(limit=100):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_bans(limit=100):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM bans ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_rules():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM rules ORDER BY id DESC')
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
