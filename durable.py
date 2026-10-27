"""Atomic checkpoints shared by the local controller and VM worker."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
import threading


FORMAT = 2


def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, indent=2, default=str) + "\n")


@contextmanager
def run_lock(directory):
    path = Path(directory) / ".controller.lock"
    with path.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another controller or cleanup owns this run") from None
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


class Journal:
    def __init__(self, path, identity):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {
            "format": FORMAT, "identity": identity, "operations": {}, "pairs": {},
        }
        if self.data.get("format") != FORMAT or self.data.get("identity") != identity:
            raise RuntimeError("Checkpoint version or workload changed; refusing to reuse results")
        self.save()

    def save(self):
        with self.lock:
            atomic_json(self.path, self.data)
