import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import app
    print("APP_OK")
except Exception as e:
    print(f"APP_ERROR: {e}")
    sys.exit(1)
