"""Background adapter to the same read-only probe embedded in the native app."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

class RuntimeCollector:
    def __init__(self, stop_event):
        self.stop = stop_event
        self.value = {"reachable":False,"jobs":[]}
        self.lock = threading.Lock()
        threading.Thread(target=self._run,daemon=True).start()

    def _run(self):
        source = Path(__file__).parents[1].joinpath("src/live_probe.py").read_text(encoding="utf-8")
        while not self.stop.is_set():
            try:
                config = "{}"
                if os.environ.get("RBZK_LIVE_CONFIG"):
                    with open(os.environ["RBZK_LIVE_CONFIG"], encoding="utf-8") as f:
                        config = f.read(65536)
                args = ["wsl.exe","-d","Ubuntu-24.04","-u","root","--","python3","-c",source] if os.name == "nt" else [sys.executable,"-c",source]
                result = subprocess.run(args,input=config,text=True,capture_output=True,timeout=12,creationflags=0x08000000 if os.name == "nt" else 0)
                value = json.loads(result.stdout)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                value = {"reachable":False,"jobs":[]}
            with self.lock:
                self.value = value
            self.stop.wait(3)

    def snapshot(self):
        with self.lock:
            value = copy.deepcopy(self.value)
        stamp = value.get("sampled_at_unix")
        age = time.time() - stamp if isinstance(stamp,(float,int)) else None
        value["age_seconds"] = age
        value["fresh"] = value.get("reachable") is True and age is not None and -2 <= age <= 15
        if not value["fresh"]:
            for job in value.get("jobs",[]):
                job.update(running=False,status="stale / unknown")
        return value
