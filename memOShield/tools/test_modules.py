import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

tests = []

try:
    from memoshield.firewall import Firewall
    tests.append(("firewall", True))
except Exception:
    tests.append(("firewall", False))

try:
    from memoshield.geoip import GeoIPClient
    tests.append(("geoip", True))
except Exception:
    tests.append(("geoip", False))

try:
    from memoshield.ids import IDS
    tests.append(("ids", True))
except Exception:
    tests.append(("ids", False))

try:
    from memoshield.whitelist import add, is_whitelisted
    tests.append(("whitelist", True))
except Exception:
    tests.append(("whitelist", False))

try:
    from memoshield.honeypot import Honeypot
    tests.append(("honeypot", True))
except Exception:
    tests.append(("honeypot", False))

try:
    from memoshield.broadcaster import broadcaster
    tests.append(("broadcaster", True))
except Exception:
    tests.append(("broadcaster", False))

passed = sum(1 for _, ok in tests if ok)
failed = sum(1 for _, ok in tests if not ok)

for name, ok in tests:
    status = "OK" if ok else "FAIL"
    print(f"  {name}: {status}")

print(f"Result: {passed}/{len(tests)} passed")
if failed > 0:
    sys.exit(1)
