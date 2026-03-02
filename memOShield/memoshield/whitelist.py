# Simple whitelist module

WHITELIST = set()

def load_whitelist(path):
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    WHITELIST.add(line)
    except FileNotFoundError:
        pass

def is_whitelisted(ip):
    return ip in WHITELIST

def add(ip):
    WHITELIST.add(ip)

def remove(ip):
    WHITELIST.discard(ip)

def get_whitelist():
    return list(WHITELIST)

def add_to_whitelist(ip):
    WHITELIST.add(ip)
