import time, os
from detector import start_monitor
from capture import capture_evidence

WATCH_DIR = "watched_folder"
os.makedirs(WATCH_DIR, exist_ok=True)

def on_trigger():
    capture_evidence("evidence_output")
    print("\n[Pipeline] Phase 1 -> Phase 2 complete.")
    print("[Pipeline] Volatile evidence captured and SHA-256 hashed.")
    print("[Pipeline] Check C:\\CryptoTripwire\\evidence_output for results.\n")

print("=" * 60)
print("        CRYPTO-TRIPWIRE v1.0")
print("        Entropy-Based Ransomware Detection +")
print("        Automated Volatile Evidence Capture")
print("=" * 60 + "\n")
observer = start_monitor(WATCH_DIR, on_trigger)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Shutting down monitor...")
    observer.stop()
observer.join()
print("[*] Crypto-Tripwire stopped.")