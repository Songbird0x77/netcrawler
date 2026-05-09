"""Global rate limiter — prevents hammering targets."""
from __future__ import annotations
import time
import threading


class RateLimiter:
    """
    Simple token bucket rate limiter.
    Ensures the agent never fires more than `max_per_second` tool launches per second.
    """
    def __init__(self, min_delay_between_tools: float = 1.0):
        self.min_delay = min_delay_between_tools
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now     = time.time()
            elapsed = now - self._last_call
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
            self._last_call = time.time()


# Global instance — imported by agent loop
limiter = RateLimiter(min_delay_between_tools=1.0)
