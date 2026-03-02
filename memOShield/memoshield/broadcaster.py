import threading
import queue
import json

class Broadcaster:
    def __init__(self):
        self._queues = []
        self._lock = threading.Lock()

    def register(self):
        q = queue.Queue()
        with self._lock:
            self._queues.append(q)
        return q

    def unregister(self, q):
        with self._lock:
            if q in self._queues:
                try:
                    self._queues.remove(q)
                except ValueError:
                    pass

    def publish(self, obj):
        data = json.dumps(obj, default=str)
        with self._lock:
            for q in list(self._queues):
                try:
                    q.put(data, block=False)
                except Exception:
                    # drop if queue full / closed
                    pass

# singleton
broadcaster = Broadcaster()
