import os
import time
import logging
import hashlib
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SENSITIVE_DIR = "sensitive"
IGNORED_DIRS = ["logs"]
SUSPICIOUS_THRESHOLD = 10  # number of file events in TIME_WINDOW
TIME_WINDOW = 60            # seconds

# Store file hashes
file_hashes = {}

class MonitorHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.recent_events = defaultdict(list)  # {directory_path: [timestamps]}
        self.last_suspicious_alert = 0          # timestamp of last suspicious movement alert

    def is_ignored(self, path):
        for folder in IGNORED_DIRS:
            if folder in path.lower():
                return True
        return False

    def is_sensitive(self, path):
        return SENSITIVE_DIR in path.lower()

    def calculate_hash(self, file_path):
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception:
            return None

    def log(self, level, message):
        print(message)
        if level == "ALERT":
            logging.warning(message)
        else:
            logging.info(message)

    # ---------------- Suspicious movement helper ----------------
    def check_suspicious_movement(self, directory):
        now = time.time()
        # Keep only timestamps within TIME_WINDOW
        self.recent_events[directory] = [t for t in self.recent_events[directory] if now - t <= TIME_WINDOW]
        
        # Trigger alert only if threshold exceeded AND last alert > TIME_WINDOW ago
        if len(self.recent_events[directory]) > SUSPICIOUS_THRESHOLD:
            if now - self.last_suspicious_alert > TIME_WINDOW:
                self.log(
                    "ALERT",
                    f"SUSPICIOUS MOVEMENT: {len(self.recent_events[directory])} files changed in last {TIME_WINDOW} seconds in {directory}"
                )
                self.last_suspicious_alert = now
                self.recent_events[directory] = []  # reset counter to avoid spam

    # ---------------- Event Handlers ----------------
    def on_created(self, event):
        if self.is_ignored(event.src_path) or event.is_directory:
            return

        file_hash = self.calculate_hash(event.src_path)
        if file_hash:
            file_hashes[event.src_path] = file_hash

        directory = os.path.dirname(event.src_path)
        self.recent_events[directory].append(time.time())
        self.check_suspicious_movement(directory)

        if self.is_sensitive(event.src_path):
            self.log("ALERT", f"ALERT: Sensitive file CREATED -> {event.src_path}")
        else:
            # Only log INFO if not part of suspicious bulk movement
            if len(self.recent_events[directory]) <= SUSPICIOUS_THRESHOLD:
                self.log("INFO", f"CREATED -> {event.src_path}")

    def on_modified(self, event):
        if self.is_ignored(event.src_path) or event.is_directory:
            return

        old_hash = file_hashes.get(event.src_path)
        new_hash = self.calculate_hash(event.src_path)

        directory = os.path.dirname(event.src_path)
        self.recent_events[directory].append(time.time())
        self.check_suspicious_movement(directory)

        if old_hash and new_hash and old_hash != new_hash:
            self.log(
                "ALERT",
                f"INTEGRITY ALERT: File modified -> {event.src_path} | OLD HASH: {old_hash} | NEW HASH: {new_hash}"
            )
        elif new_hash and not self.is_sensitive(event.src_path):
            if len(self.recent_events[directory]) <= SUSPICIOUS_THRESHOLD:
                self.log("INFO", f"MODIFIED -> {event.src_path}")

        if new_hash:
            file_hashes[event.src_path] = new_hash

    def on_deleted(self, event):
        if self.is_ignored(event.src_path) or event.is_directory:
            return

        if event.src_path in file_hashes:
            del file_hashes[event.src_path]

        directory = os.path.dirname(event.src_path)
        self.recent_events[directory].append(time.time())
        self.check_suspicious_movement(directory)

        if self.is_sensitive(event.src_path):
            self.log("ALERT", f"ALERT: Sensitive file DELETED -> {event.src_path}")
        else:
            if len(self.recent_events[directory]) <= SUSPICIOUS_THRESHOLD:
                self.log("INFO", f"DELETED -> {event.src_path}")

# ---------------- Main ----------------
if __name__ == "__main__":
    path = "."
    logging.basicConfig(
        filename="logs/activity.log",
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print("Monitoring started with integrity evidence and suspicious movement detection... Press CTRL+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped")

    observer.join()
