"""A small in-process sliding-window rate limiter.

Deliberately dependency-free. State lives in memory, so each gunicorn worker
keeps its own counters: with N workers the effective ceiling is N x the
configured limit. That is fine for the intended scale (a handful of analysts).
For a hard global limit across workers, back this with Redis instead.
"""

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, per_minute: int = 30, per_hour: int = 400):
        self.per_minute = per_minute
        self.per_hour = per_hour
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float) -> None:
        """Drop identities with no recent activity so memory stays bounded."""
        if now - self._last_sweep < 300:
            return
        self._last_sweep = now
        stale = [key for key, hits in self._hits.items() if not hits or now - hits[-1] > 3600]
        for key in stale:
            del self._hits[key]

    def check(self, identity: str) -> tuple[bool, int]:
        """Record a hit for ``identity``.

        Returns ``(allowed, retry_after_seconds)``. ``retry_after`` is 0 when
        the request is allowed.
        """
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            hits = self._hits[identity]

            while hits and now - hits[0] > 3600:
                hits.popleft()

            in_last_minute = sum(1 for t in hits if now - t <= 60)

            if self.per_minute and in_last_minute >= self.per_minute:
                oldest_in_window = next(t for t in hits if now - t <= 60)
                return False, max(1, int(61 - (now - oldest_in_window)))

            if self.per_hour and len(hits) >= self.per_hour:
                return False, max(1, int(3601 - (now - hits[0])))

            hits.append(now)
            return True, 0
