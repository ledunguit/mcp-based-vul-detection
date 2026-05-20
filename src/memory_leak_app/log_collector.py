"""
Log collector for capturing server logs and streaming them to clients.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class LogEntry:
    """Represents a single log entry."""
    timestamp: float
    level: str
    message: str
    logger_name: str
    thread_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "message": self.message,
            "logger_name": self.logger_name,
            "thread_name": self.thread_name,
        }


class LogCollector:
    """
    Collects logs from Python logging system and makes them available for streaming.
    Thread-safe circular buffer with configurable max size.
    """

    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self._entries: deque[LogEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._event_id = 0
        self._condition = threading.Condition(self._lock)

    def add_entry(self, entry: LogEntry) -> None:
        """Add a log entry to the buffer."""
        with self._lock:
            self._entries.append(entry)
            self._event_id += 1
            self._condition.notify_all()

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get the most recent log entries."""
        with self._lock:
            entries = list(self._entries)[-limit:]
            return [entry.to_dict() for entry in entries]

    def get_all(self) -> list[dict[str, Any]]:
        """Get all buffered log entries."""
        with self._lock:
            return [entry.to_dict() for entry in self._entries]

    def wait_for_new_entries(self, after_id: int, timeout: float = 5.0) -> tuple[list[dict[str, Any]], int]:
        """
        Wait for new log entries after the given event ID.
        Returns (entries, latest_event_id).
        """
        with self._condition:
            deadline = time.time() + timeout
            while self._event_id <= after_id:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return [], self._event_id
                self._condition.wait(timeout=remaining)

            # Return all entries (client will filter by timestamp if needed)
            entries = [entry.to_dict() for entry in self._entries]
            return entries, self._event_id

    def clear(self) -> None:
        """Clear all buffered entries."""
        with self._lock:
            self._entries.clear()


class LogCollectorHandler(logging.Handler):
    """
    Logging handler that forwards log records to a LogCollector.
    """

    def __init__(self, collector: LogCollector):
        super().__init__()
        self.collector = collector

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = LogEntry(
                timestamp=record.created,
                level=record.levelname,
                message=self.format(record),
                logger_name=record.name,
                thread_name=record.threadName,
            )
            self.collector.add_entry(entry)
        except Exception:
            self.handleError(record)


# Global log collector instance
_global_collector: LogCollector | None = None


def get_global_collector() -> LogCollector:
    """Get or create the global log collector instance."""
    global _global_collector
    if _global_collector is None:
        _global_collector = LogCollector(max_entries=1000)
    return _global_collector


def setup_log_collection(logger: logging.Logger | None = None, level: int = logging.INFO) -> LogCollector:
    """
    Set up log collection for the given logger (or root logger if None).
    Returns the global collector instance.
    """
    collector = get_global_collector()

    if logger is None:
        logger = logging.getLogger()

    handler = LogCollectorHandler(collector)
    handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return collector
