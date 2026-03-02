#!/bin/bash
# memOShield Quick Test Script (Linux/Ubuntu)
# Bu script memOShield projesini otomatik test eder

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  memOShield Automatic Test Script${NC}"
echo -e "${BLUE}========================================${NC}\n"

# 1. Python ortamını kontrol et
echo -e "${YELLOW}[1/6] Checking Python environment...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python3 found${NC}"

# 2. Bağımlılıkları kur
echo -e "\n${YELLOW}[2/6] Installing dependencies...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual env created${NC}"
fi

source venv/bin/activate

pip install -q -r requirements.txt 2>/dev/null
echo -e "${GREEN}✓ Dependencies installed${NC}"

# 3. Database'i kontrol et / oluştur
echo -e "\n${YELLOW}[3/6] Checking database...${NC}"
python3 << 'EOF'
from memoshield.db import init_db
try:
    init_db()
    print("✓ Database initialized")
except Exception as e:
    print(f"✗ Database error: {e}")
    exit(1)
EOF

# 4. Modülleri test et
echo -e "\n${YELLOW}[4/6] Testing modules...${NC}"
python3 << 'EOF'
import sys

tests_passed = 0
tests_failed = 0

# Test 1: Firewall
try:
    from memoshield.firewall import Firewall
    fw = Firewall()
    print("✓ Firewall module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ Firewall module failed: {e}")
    tests_failed += 1

# Test 2: GeoIP
try:
    from memoshield.geoip import GeoIPClient
    geo = GeoIPClient()
    print("✓ GeoIP module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ GeoIP module failed: {e}")
    tests_failed += 1

# Test 3: IDS
try:
    from memoshield.ids import IDS
    from memoshield.firewall import Firewall
    fw = Firewall()
    ids = IDS(fw)
    print("✓ IDS module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ IDS module failed: {e}")
    tests_failed += 1

# Test 4: Whitelist
try:
    from memoshield.whitelist import add, is_whitelisted
    add("10.0.0.1")
    assert is_whitelisted("10.0.0.1")
    print("✓ Whitelist module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ Whitelist module failed: {e}")
    tests_failed += 1

# Test 5: Honeypot
try:
    from memoshield.honeypot import Honeypot
    from memoshield.ids import IDS
    from memoshield.firewall import Firewall
    fw = Firewall()
    ids = IDS(fw)
    hp = Honeypot(ids, fw)
    print("✓ Honeypot module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ Honeypot module failed: {e}")
    tests_failed += 1

# Test 6: Notifier
try:
    from memoshield.notifier import Notifier
    notifier = Notifier()
    print("✓ Notifier module OK")
    tests_passed += 1
except Exception as e:
    print(f"✗ Notifier module failed: {e}")
    tests_failed += 1

print(f"\nModule tests: {tests_passed} passed, {tests_failed} failed")
if tests_failed > 0:
    sys.exit(1)
EOF

# 5. Flask app syntax check
echo -e "\n${YELLOW}[5/6] Testing Flask app...${NC}"
python3 << 'EOF'
try:
    import app
    print("✓ Flask app module OK (no syntax errors)")
except Exception as e:
    print(f"✗ Flask app failed: {e}")
    exit(1)
EOF

# 6. API endpoints check
echo -e "\n${YELLOW}[6/6] Testing API endpoints...${NC}"
python3 << 'EOF'
import threading
import time
import requests
import sys
from app import app

# Start Flask in background
def run_flask():
    app.run(port=5000, debug=False, use_reloader=False)

# Run Flask server in daemon thread
server_thread = threading.Thread(target=run_flask, daemon=True)
server_thread.start()

time.sleep(2)  # Wait for server to start

api_tests = 0
api_passed = 0

try:
    # Test 1: Landing page
    resp = requests.get('http://127.0.0.1:5000/', timeout=5)
    api_tests += 1
    if resp.status_code == 200 and 'memOShield' in resp.text:
        print("✓ GET / returns 200")
        api_passed += 1
    else:
        print("✗ GET / failed")
except Exception as e:
    api_tests += 1
    print(f"✗ GET / error: {e}")

try:
    # Test 2: API events
    resp = requests.get('http://127.0.0.1:5000/api/events', timeout=5)
    api_tests += 1
    if resp.status_code == 200 and resp.json():
        print("✓ GET /api/events returns JSON")
        api_passed += 1
    else:
        print("✗ GET /api/events failed")
except Exception as e:
    api_tests += 1
    print(f"✗ GET /api/events error: {e}")

try:
    # Test 3: Ban API (should require auth)
    resp = requests.post('http://127.0.0.1:5000/api/ban',
                        json={"ip": "203.0.113.1", "reason": "test"},
                        timeout=5)
    api_tests += 1
    if resp.status_code == 403:
        print("✓ POST /api/ban requires authentication")
        api_passed += 1
    else:
        print("✗ POST /api/ban auth check failed")
except Exception as e:
    api_tests += 1
    print(f"✗ POST /api/ban error: {e}")

print(f"\nAPI tests: {api_passed}/{api_tests} passed")
if api_passed < api_tests:
    sys.exit(1)
EOF

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}✓ All tests passed!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Start the server:"
echo -e "   ${BLUE}python app.py${NC}"
echo -e "\n2. Open in browser:"
echo -e "   ${BLUE}http://127.0.0.1:5000${NC}"
echo -e "\n3. Demo mode (no login needed):"
echo -e "   ${BLUE}http://127.0.0.1:5000/demo${NC}"
