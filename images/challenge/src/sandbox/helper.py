import fcntl
import os
import pickle
from typing import Any, Optional

class FileLock:
    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.fd = None

    def __enter__(self):
        self.fd = open(self.lock_file, 'w')
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            self.fd.close()
            try:
                os.remove(self.lock_file)
            except FileNotFoundError:
                pass

class PersistentStore:
    def __init__(self, filename: str):
        self.filename = filename
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from store by key."""
        try:
            with open(self.filename, "rb") as f:
                data = pickle.load(f)
                return data.get(key)
        except (FileNotFoundError, pickle.UnpicklingError) as e:
            return None
            
    def set(self, key: str, value: Any) -> None:
        """Set key-value pair in store."""
        try:
            with open(self.filename, "rb") as f:
                data = pickle.load(f)
        except (FileNotFoundError, pickle.UnpicklingError):
            data = {}
            
        data[key] = value
        
        with open(self.filename, "wb") as f:
            pickle.dump(data, f)