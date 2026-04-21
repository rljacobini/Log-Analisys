import sys
import os
os.chdir(os.path.join(os.path.dirname(__file__), 'server'))
sys.path.insert(0, '.')

try:
    import server
    print("OK - server imported")
except Exception as e:
    print(f"Error: {e}")