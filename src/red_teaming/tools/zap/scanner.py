"""High-level, one-target ZAP Spider/AJAX Spider scan workflow.

:class:`ZapScanner` is the composition point for a single bounded discovery
run. It owns only the *sequence* and the *state/artifact persistence*:

1. persist a ``planned`` state (creating the scan directory);
2. start the daemon and wait for a minimum-version API;
3. create a context and apply an anchored, subtree-scoped include regex;
4. run exactly the selected mode(s);
5. write raw results as JSON objects under ``raw/``;
6. mark the run ``succeeded``;
7. always attempt exactly one bounded daemon shutdown, even on failure.

On any failure a sanitized ``failed`` state records the phase, the error type,
and a redacted message before the original error is re-raised. A shutdown
failure after otherwise successful discovery is itself a scan failure: it is
persisted as a sanitized ``failed`` state and propagated. When discovery
already failed and shutdown also fails, the original discovery error is
re-raised unchanged and the sanitized shutdown failure is recorded separately
as ``shutdown_error``. The ZAP API key is never passed to this class and never
becomes part of state, artifacts, or error text.
"""

from __future__ import annotations

import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from ...orchestration.state import atomic_write_json, write_state
from ...projects.models import Target
from ...projects.paths import ScanPath, is_within
from .discovery import (
    DEFAULT_AJAX_MAX_RESULTS,
    DEFAULT_AJAX_PAGE_SIZE,
    DEFAULT_AJAX_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SPIDER_TIMEOUT,
    AjaxSpiderRunner,
    SpiderRunner,
)
from .models import ZapError

__all__ = [
    "AJAX_ARTIFACT_FILENAME",
    "MODE_AJAX",
    "MODE_BOTH",
    "MODE_SPIDER",
    "RAW_DIRNAME",
    "SCHEMA_VERSION",
    "SPIDER_ARTIFACT_FILENAME",
    "ScanConfigurationError",
    "ScanError",
    "ZapScanner",
    "build_scope_regex",
]

SCHEMA_VERSION = 1

MODE_SPIDER = "spider"
MODE_AJAX = "ajax"
MODE_BOTH = "both"

VALID_MODES = (MODE_SPIDER, MODE_AJAX, MODE_BOTH)

RAW_DIRNAME = "raw"
SPIDER_ARTIFACT_FILENAME = "spider.json"
AJAX_ARTIFACT_FILENAME = "ajax.json"


class ScanError(ZapError):
    """Base class for ZAP scan orchestration failures."""


class ScanConfigurationError(ScanError, ValueError):
    """The scanner was configured with an invalid value."""


def build_scope_regex(target: Target) -> str:
    """Build an anchored, escaped include-URL regex for *target*.

    The regex pins the exact normalized scheme and host and, when present, the
    seed path subtree. Only the scheme-default port may optionally appear.
    Escaping the host prevents lookalike/sibling hosts from matching.

    Path semantics:

    * A root seed (``""`` or ``"/"``) matches the bare origin plus any
      ``/path``, ``?query``, or ``#fragment`` suffix.
    * A non-trailing-slash seed such as ``/api`` matches exactly ``/api``, any
      ``/api/...`` descendant, and ``/api?query`` / ``/api#fragment`` suffixes,
      but never ``/api2``.
    * A trailing-slash seed such as ``/api/`` stays distinct: it matches
      ``/api/`` and its descendants but never ``/api``.
    """

    if not isinstance(target, Target):
        raise ScanConfigurationError("target must be a Target instance")

    scheme = re.escape(target.scheme)
    host = re.escape(target.host)
    base = f"{scheme}://{host}(?::{target.port})?"

    path = target.path
    if path in ("", "/"):
        return rf"^{base}(?:[/?#].*)?$"
    if path.endswith("/"):
        # Keep the trailing slash significant: descendants continue directly
        # after it, while a shortened seed such as ``/api`` must not match.
        return rf"^{base}{re.escape(path)}.*$"
    return rf"^{base}{re.escape(path)}(?:[/?#].*)?$"


def _validate_positive(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScanConfigurationError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise ScanConfigurationError(f"{name} must be a positive finite number")
    return float(value)


def _validate_positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ScanConfigurationError(f"{name} must be a positive integer")
    return value


class ZapScanner:
    """Compose one bounded ZAP discovery run and persist its state."""

    def __init__(
        self,
        *,
        scan_path: ScanPath,
        target: Target,
        project: str,
        mode: str,
        manager: Any,
        client: Any,
        spider_timeout: float = DEFAULT_SPIDER_TIMEOUT,
        ajax_timeout: float = DEFAULT_AJAX_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        ajax_page_size: int = DEFAULT_AJAX_PAGE_SIZE,
        ajax_max_results: int = DEFAULT_AJAX_MAX_RESULTS,
        access_url: bool = True,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Optional[Callable[[], datetime]] = None,
        spider_runner_factory: Optional[Callable[[], Any]] = None,
        ajax_runner_factory: Optional[Callable[[], Any]] = None,
        secret_redactor: Optional[Callable[[str], str]] = None,
    ) -> None:
        if not isinstance(scan_path, ScanPath):
            raise ScanConfigurationError("scan_path must be a ScanPath instance")
        if not isinstance(target, Target):
            raise ScanConfigurationError("target must be a Target instance")
        if not isinstance(project, str) or not project.strip():
            raise ScanConfigurationError("project must be a non-blank string")
        if mode not in VALID_MODES:
            raise ScanConfigurationError(
                f"mode must be one of {', '.join(VALID_MODES)}"
            )
        if manager is None:
            raise ScanConfigurationError("manager must be provided")
        if client is None:
            raise ScanConfigurationError("client must be provided")

        self._scan_path = scan_path
        self._target = target
        self._project = project
        self._mode = mode
        self._manager = manager
        self._client = client

        self._spider_timeout = _validate_positive("spider_timeout", spider_timeout)
        self._ajax_timeout = _validate_positive("ajax_timeout", ajax_timeout)
        self._poll_interval = _validate_positive("poll_interval", poll_interval)
        self._ajax_page_size = _validate_positive_int("ajax_page_size", ajax_page_size)
        self._ajax_max_results = _validate_positive_int(
            "ajax_max_results", ajax_max_results
        )
        self._access_url = bool(access_url)

        self._clock = clock
        self._sleep = sleep
        self._now = now if now is not None else (lambda: datetime.now(timezone.utc))
        self._secret_redactor = secret_redactor

        self._context_name = f"scan-{scan_path.scan_id}"
        self._scope_regex = build_scope_regex(target)

        if spider_runner_factory is None:
            spider_runner_factory = self._default_spider_runner
        if ajax_runner_factory is None:
            ajax_runner_factory = self._default_ajax_runner
        self._spider_runner_factory = spider_runner_factory
        self._ajax_runner_factory = ajax_runner_factory

        self._state: dict = {}

    # -- safe introspection -------------------------------------------------

    @property
    def context_name(self) -> str:
        return self._context_name

    @property
    def scope_regex(self) -> str:
        return self._scope_regex

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def state(self) -> dict:
        return self._state

    def __repr__(self) -> str:
        return (
            f"ZapScanner(scan_id={self._scan_path.scan_id!r}, "
            f"mode={self._mode!r}, target={self._target.url!r})"
        )

    # -- orchestration ------------------------------------------------------

    def run(self) -> dict:
        """Run the selected mode(s) and return the final persisted state."""

        self._state = self._initial_state()
        primary_error: Optional[BaseException] = None
        try:
            self._persist()

            self._begin_step("start", "starting")
            self._manager.start()
            version = self._manager.wait_until_ready()
            self._state["zap_version"] = version
            self._finish_step("start")

            self._begin_step("context", "context")
            self._client.create_context(self._context_name)
            self._client.include_in_context(self._context_name, self._scope_regex)
            self._access_seed()
            self._finish_step("context")

            if self._mode in (MODE_SPIDER, MODE_BOTH):
                self._run_spider()
            if self._mode in (MODE_AJAX, MODE_BOTH):
                self._run_ajax()

            self._state["status"] = "succeeded"
            self._state["phase"] = "done"
            self._persist()
        except BaseException as exc:
            primary_error = exc

        # Exactly one bounded shutdown attempt, whether or not discovery
        # succeeded. Shutdown is part of the run's success contract.
        shutdown_error = self._stop_manager()

        if primary_error is not None:
            # Preserve and re-raise the original discovery error; record the
            # shutdown failure only as a sanitized secondary detail.
            self._record_failure(primary_error)
            if shutdown_error is not None:
                self._record_shutdown_error(shutdown_error)
            raise primary_error

        if shutdown_error is not None:
            # Otherwise-successful discovery fails when the daemon survives.
            self._record_failure(shutdown_error, phase="shutdown")
            self._record_shutdown_error(shutdown_error)
            raise shutdown_error

        return self._state

    # -- steps --------------------------------------------------------------

    def _run_spider(self) -> None:
        self._begin_step("spider", "spider")
        runner = self._spider_runner_factory()
        result = runner.run(
            self._target.url,
            context_name=self._context_name,
            subtree_only=True,
        )
        relative = f"{RAW_DIRNAME}/{SPIDER_ARTIFACT_FILENAME}"
        self._write_artifact(
            relative,
            {"mode": "spider", "scan_id": result.scan_id, "results": result.results},
        )
        self._state["artifacts"]["spider"] = relative
        self._finish_step("spider")

    def _run_ajax(self) -> None:
        self._begin_step("ajax", "ajax")
        runner = self._ajax_runner_factory()
        result = runner.run(
            self._target.url,
            context_name=self._context_name,
            in_scope_only=True,
            subtree_only=True,
        )
        relative = f"{RAW_DIRNAME}/{AJAX_ARTIFACT_FILENAME}"
        self._write_artifact(
            relative,
            {"mode": "ajax", "scan_id": result.scan_id, "results": result.results},
        )
        self._state["artifacts"]["ajax"] = relative
        self._finish_step("ajax")

    def _access_seed(self) -> None:
        """Best-effort seed access; never aborts the run."""

        step = self._state["steps"].setdefault("access", {})
        if not self._access_url:
            step["status"] = "skipped"
            return
        try:
            self._client.access_url(self._target.url)
        except ZapError as exc:
            step["status"] = "warning"
            step["error"] = self._redact(str(exc))
        else:
            step["status"] = "succeeded"

    # -- runner factories ---------------------------------------------------

    def _default_spider_runner(self) -> SpiderRunner:
        return SpiderRunner(
            self._client,
            timeout=self._spider_timeout,
            poll_interval=self._poll_interval,
            process_exited=self._process_exited,
            clock=self._clock,
            sleep=self._sleep,
        )

    def _default_ajax_runner(self) -> AjaxSpiderRunner:
        return AjaxSpiderRunner(
            self._client,
            timeout=self._ajax_timeout,
            poll_interval=self._poll_interval,
            page_size=self._ajax_page_size,
            max_results=self._ajax_max_results,
            process_exited=self._process_exited,
            clock=self._clock,
            sleep=self._sleep,
        )

    def _process_exited(self) -> bool:
        running = getattr(self._manager, "running", None)
        return running is False

    # -- state helpers ------------------------------------------------------

    def _initial_state(self) -> dict:
        timestamp = self._now_iso()
        return {
            "schema_version": SCHEMA_VERSION,
            "scan_id": self._scan_path.scan_id,
            "project": self._project,
            "target": self._target.url,
            "mode": self._mode,
            "status": "planned",
            "phase": "plan",
            "created_at": timestamp,
            "updated_at": timestamp,
            "zap_version": None,
            "context_name": self._context_name,
            "scope_regex": self._scope_regex,
            "steps": {},
            "artifacts": {},
        }

    def _begin_step(self, name: str, phase: str) -> None:
        self._state["phase"] = phase
        step = self._state["steps"].setdefault(name, {})
        step["status"] = "running"
        step["started_at"] = self._now_iso()
        self._persist()

    def _finish_step(self, name: str, status: str = "succeeded") -> None:
        step = self._state["steps"].setdefault(name, {})
        step["status"] = status
        step["finished_at"] = self._now_iso()
        self._persist()

    def _record_failure(self, exc: BaseException, *, phase: Optional[str] = None) -> None:
        if not self._state:
            self._state = self._initial_state()
        self._state["status"] = "failed"
        if phase is not None:
            self._state["phase"] = phase
        self._state["error"] = self._error_record(exc)
        try:
            self._persist()
        except Exception:
            # Never mask the original failure with a persistence error.
            pass

    def _record_shutdown_error(self, exc: BaseException) -> None:
        if not self._state:
            self._state = self._initial_state()
        self._state["shutdown_error"] = self._error_record(exc)
        try:
            self._persist()
        except Exception:
            # Shutdown detail must never mask the propagated failure.
            pass

    def _error_record(self, exc: BaseException) -> dict:
        message = self._redact(str(exc)).strip() or type(exc).__name__
        return {"type": type(exc).__name__, "message": message}

    def _persist(self) -> Path:
        self._state["updated_at"] = self._now_iso()
        return write_state(self._scan_path, self._state)

    def _now_iso(self) -> str:
        value = self._now()
        if not isinstance(value, datetime):
            raise ScanConfigurationError("now() must return a datetime")
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    def _redact(self, text: str) -> str:
        if self._secret_redactor is None:
            return str(text)
        return self._secret_redactor(str(text))

    def _write_artifact(self, relative: str, payload: dict) -> Path:
        if not isinstance(payload, dict):
            raise ScanConfigurationError("artifact payload must be a JSON object")

        raw_dir = self._scan_path.scan_dir / RAW_DIRNAME
        if not is_within(raw_dir, self._scan_path.scan_dir):
            raise ScanError("refusing to write artifacts outside the scan directory")
        raw_dir.mkdir(parents=True, exist_ok=True)

        name = Path(relative).name
        target = raw_dir / name
        if not is_within(target, raw_dir):
            raise ScanError("refusing to write an artifact outside the raw directory")
        atomic_write_json(target, payload, scan_dir=self._scan_path.scan_dir)
        return target

    def _stop_manager(self) -> Optional[BaseException]:
        """Attempt exactly one bounded shutdown, returning any raised error."""

        try:
            self._manager.stop()
        except Exception as exc:
            return exc
        return None
