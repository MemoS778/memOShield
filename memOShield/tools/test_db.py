import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from memoshield.db import init_db
    init_db()
    print("DB_OK")
except Exception as e:
    print(f"DB_ERROR: {e}")
    sys.exit(1)
