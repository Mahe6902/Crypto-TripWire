import os, math, time
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

ENTROPY_THRESHOLD = 7.2
TIME_WINDOW = 5
COUNT_THRESHOLD = 3

def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        for c in counts:
            if c:
                p = c / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except:
        return 0

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, on_trigger):
        self.on_trigger = on_trigger
        self.hits = deque()
        self.triggered = False

    def on_modified(self, event):
        if not event.is_directory:
            self._check(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._check(event.src_path)

    def _check(self, path):
        if self.triggered:
            return
        h = calculate_entropy(path)
        if h >= ENTROPY_THRESHOLD:
            now = time.time()
            self.hits.append(now)
            while self.hits and now - self.hits[0] > TIME_WINDOW:
                self.hits.popleft()
            print(f"  [!] High entropy: {os.path.basename(path)} | H = {h} bits/byte")
            if len(self.hits) >= COUNT_THRESHOLD:
                self.triggered = True
                print("\n  *** RANSOMWARE BEHAVIOUR DETECTED ***")
                print("  *** Triggering Phase 2 evidence capture ***\n")
                self.on_trigger()

def start_monitor(watch_dir, on_trigger):
    handler = RansomwareHandler(on_trigger)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()
    print(f"[Phase 1] Monitoring directory : {watch_dir}")
    print(f"[Phase 1] Entropy threshold    : {ENTROPY_THRESHOLD} bits/byte")
    print(f"[Phase 1] Alert condition      : {COUNT_THRESHOLD}+ files above threshold in {TIME_WINDOW}s")
    print(f"[Phase 1] Status               : ACTIVE\n")
    return observer