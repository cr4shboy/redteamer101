"""Bounded, socket-free Spider and AJAX Spider runners.

The runners in this module own the *polling* loops for ZAP discovery scans.
They never perform HTTP themselves: every request goes through the explicit
:class:`~red_teaming.tools.zap.client.ZapApiClient` wrappers, and the daemon
process, monotonic clock, and sleep function are all injectable so the loops
can be exercised deterministically without a process or a socket.

Completion rules:

* the traditional Spider is complete when its integer progress reaches 100;
* the AJAX Spider is complete when its documented status is ``stopped``
  (matched case-insensitively).

Both runners are bounded by a positive, finite timeout and stop the remote scan
before re-raising any timeout, process-exit, or status error.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

from .models import ZapError

__all__ = [
    "AJAX_STATUS_RUNNING",
    "AJAX_STATUS_STOPPED",
    "DEFAULT_AJAX_MAX_RESULTS",
    "DEFAULT_AJAX_PAGE_SIZE",
    "DEFAULT_AJAX_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_SPIDER_TIMEOUT",
    "AjaxSpiderRunner",
    "DiscoveryError",
    "DiscoveryProcessExitedError",
    "DiscoveryResult",
    "DiscoveryStateError",
    "DiscoveryTimeoutError",
    "SpiderRunner",
]

DEFAULT_SPIDER_TIMEOUT = 300.0
DEFAULT_AJAX_TIMEOUT = 300.0
DEFAULT_POLL_INTERVAL = 0.25
DEFAULT_AJAX_PAGE_SIZE = 100
DEFAULT_AJAX_MAX_RESULTS = 10000

AJAX_STATUS_RUNNING = "running"
AJAX_STATUS_STOPPED = "stopped"


class DiscoveryError(ZapError):
    """Base class for bounded Spider/AJAX Spider runner failures."""


class DiscoveryTimeoutError(DiscoveryError):
    """The discovery scan exceeded its bounded timeout."""


class DiscoveryProcessExitedError(DiscoveryError):
    """The ZAP daemon exited while a discovery scan was running."""


class DiscoveryStateError(DiscoveryError):
    """ZAP reported an unexpected status for a discovery scan."""


class _DiscoveryClient(Protocol):
    """The subset of :class:`ZapApiClient` the runners depend on."""

    def start_spider(self, url: str, **kwargs: Any) -> int: ...

    def spider_status(self, scan_id: int) -> int: ...

    def spider_results(self, scan_id: int) -> list: ...

    def stop_spider(self, scan_id: int) -> None: ...

    def start_ajax_spider(self, url: str, **kwargs: Any) -> Optional[int]: ...

    def ajax_spider_status(self) -> str: ...

    def ajax_spider_results(self, **kwargs: Any) -> list: ...

    def stop_ajax_spider(self) -> None: ...


@dataclass(frozen=True)
class DiscoveryResult:
    """The bounded outcome of one discovery run."""

    mode: str
    scan_id: Optional[int]
    results: list
    status: str


def _validate_positive(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise DiscoveryError(f"{name} must be a positive finite number")
    return float(value)


def _validate_positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DiscoveryError(f"{name} must be a positive integer")
    return value


class _BaseRunner:
    """Shared bounded-polling machinery for discovery runners."""

    def __init__(
        self,
        client: _DiscoveryClient,
        *,
        timeout: float,
        poll_interval: float,
        process_exited: Optional[Callable[[], bool]] = None,
        observer: Optional[Callable[[], None]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._timeout = _validate_positive("timeout", timeout)
        self._poll_interval = _validate_positive("poll_interval", poll_interval)
        self._process_exited = process_exited
        if observer is not None and not callable(observer):
            raise DiscoveryError("observer must be callable or None")
        self._observer = observer
        self._clock = clock
        self._sleep = sleep

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def poll_interval(self) -> float:
        return self._poll_interval

    def _check_process(self) -> None:
        if self._process_exited is not None and self._process_exited():
            raise DiscoveryProcessExitedError(
                "ZAP process exited while a discovery scan was running"
            )

    def _check_observer(self) -> None:
        """Invoke the optional fail-closed runtime observer.

        The observer is a no-op unless one was supplied. Any exception it
        raises propagates unchanged, so the caller's existing best-effort stop
        path runs before the original error is re-raised.
        """

        if self._observer is not None:
            self._observer()

    def _budget(self) -> tuple[float, int]:
        deadline = self._clock() + self._timeout
        attempts = max(1, int(math.ceil(self._timeout / self._poll_interval)))
        return deadline, attempts

    def _expired(self, deadline: float, attempts: int, max_attempts: int) -> bool:
        return attempts >= max_attempts or self._clock() >= deadline


class SpiderRunner(_BaseRunner):
    """Bounded traditional Spider run against one seed URL."""

    def run(
        self,
        url: str,
        *,
        context_name: Optional[str] = None,
        subtree_only: bool = True,
        recurse: bool = True,
    ) -> DiscoveryResult:
        """Start, poll to completion, and collect Spider results.

        On timeout, process exit, or any API/status error the remote scan is
        asked to stop before the original error is re-raised.
        """

        self._check_process()
        scan_id = self._client.start_spider(
            url, context_name=context_name, subtree_only=subtree_only, recurse=recurse
        )
        try:
            self._await_completion(scan_id)
            # Inspect once more before collecting results so a violation on the
            # final poll cannot be masked by result retrieval.
            self._check_observer()
            results = self._client.spider_results(scan_id)
        except BaseException:
            self._safe_stop(scan_id)
            raise
        return DiscoveryResult(
            mode="spider", scan_id=scan_id, results=list(results), status="100"
        )

    def _await_completion(self, scan_id: int) -> None:
        deadline, max_attempts = self._budget()
        attempts = 0
        while True:
            self._check_process()
            # Runs after Spider start and on every polling cycle.
            self._check_observer()
            status = self._client.spider_status(scan_id)
            if isinstance(status, bool) or not isinstance(status, int):
                raise DiscoveryStateError("spider status was not an integer")
            if status < 0 or status > 100:
                raise DiscoveryStateError("spider status was outside 0..100")
            if status >= 100:
                return
            attempts += 1
            if self._expired(deadline, attempts, max_attempts):
                raise DiscoveryTimeoutError(
                    "spider did not finish within the bounded timeout"
                )
            self._sleep(self._poll_interval)

    def _safe_stop(self, scan_id: int) -> None:
        try:
            self._client.stop_spider(scan_id)
        except Exception:
            pass


class AjaxSpiderRunner(_BaseRunner):
    """Bounded AJAX Spider run against one seed URL."""

    def __init__(
        self,
        client: _DiscoveryClient,
        *,
        timeout: float,
        poll_interval: float,
        page_size: int = DEFAULT_AJAX_PAGE_SIZE,
        max_results: int = DEFAULT_AJAX_MAX_RESULTS,
        process_exited: Optional[Callable[[], bool]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            client,
            timeout=timeout,
            poll_interval=poll_interval,
            process_exited=process_exited,
            clock=clock,
            sleep=sleep,
        )
        self._page_size = _validate_positive_int("page_size", page_size)
        self._max_results = _validate_positive_int("max_results", max_results)

    def run(
        self,
        url: str,
        *,
        context_name: Optional[str] = None,
        in_scope_only: bool = True,
        subtree_only: bool = True,
    ) -> DiscoveryResult:
        """Start, poll status, and collect paginated AJAX Spider results."""

        self._check_process()
        scan_id = self._client.start_ajax_spider(
            url,
            context_name=context_name,
            in_scope_only=in_scope_only,
            subtree_only=subtree_only,
        )
        try:
            self._await_completion()
            results = self._collect_results()
        except BaseException:
            self._safe_stop()
            raise
        return DiscoveryResult(
            mode="ajax", scan_id=scan_id, results=results, status=AJAX_STATUS_STOPPED
        )

    def _await_completion(self) -> None:
        deadline, max_attempts = self._budget()
        attempts = 0
        while True:
            self._check_process()
            status = self._client.ajax_spider_status()
            normalized = status.strip().lower() if isinstance(status, str) else ""
            if normalized == AJAX_STATUS_STOPPED:
                return
            if normalized != AJAX_STATUS_RUNNING:
                raise DiscoveryStateError(
                    f"unexpected AJAX spider status: {status!r}"
                )
            attempts += 1
            if self._expired(deadline, attempts, max_attempts):
                raise DiscoveryTimeoutError(
                    "AJAX spider did not finish within the bounded timeout"
                )
            self._sleep(self._poll_interval)

    def _collect_results(self) -> list:
        collected: list = []
        start = 0
        while True:
            page = self._client.ajax_spider_results(
                start=start, count=self._page_size
            )
            if not isinstance(page, list):
                raise DiscoveryStateError("AJAX spider results page was not a list")
            if not page:
                break
            collected.extend(page)
            if len(page) < self._page_size:
                break
            if len(collected) >= self._max_results:
                collected = collected[: self._max_results]
                break
            start += len(page)
        return collected

    def _safe_stop(self) -> None:
        try:
            self._client.stop_ajax_spider()
        except Exception:
            pass
