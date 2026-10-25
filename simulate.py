import os, time

WATCH_DIR = "watched_folder"
os.makedirs(WATCH_DIR, exist_ok=True)

print("=" * 60)
print("        RANSOMWARE SIMULATION SCRIPT")
print("        Writing high-entropy encrypted files...")
print("=" * 60 + "\n")

for i in range(20):
    path = os.path.join(WATCH_DIR, f"encrypted_{i:04d}.locked")
    with open(path, 'wb') as f:
        f.write(os.urandom(4096))
    print(f"  [SIM] Written: encrypted_{i:04d}.locked  (entropy ~8.0 bits/byte)")
    time.sleep(0.15)

print("\n[Simulation] All 20 files written.")
print("[Simulation] Check Terminal 1 for detection output.")