"""OWASP ZAP daemon process management and low-level API access.

The public surface is intentionally small:

* :class:`~red_teaming.tools.zap.client.ZapApiClient` owns every low-level ZAP
  API request and validates that it only ever talks to a configured loopback
  endpoint.
* :class:`~red_teaming.tools.zap.process.ZapProcessManager` is the only
  component that starts, waits for, and stops the ZAP daemon.
* :class:`~red_teaming.tools.zap.discovery.SpiderRunner` and
  :class:`~red_teaming.tools.zap.discovery.AjaxSpiderRunner` own the bounded,
  injectable polling loops.
* :class:`~red_teaming.tools.zap.scanner.ZapScanner` composes one bounded
  discovery run and persists its state/artifacts.

Nothing here performs network or process activity at import time.
"""

from .client import UrllibTransport, ZapApiClient
from .models import (
    DEFAULT_MIN_ZAP_VERSION,
    DEFAULT_API_TIMEOUT,
    HttpResponse,
    ZapApiError,
    ZapApiResultError,
    ZapConfigError,
    ZapEndpoint,
    ZapError,
    ZapHttpError,
    ZapResponseError,
    ZapTransportError,
    ZapVersionError,
    version_at_least,
)
from .discovery import (
    AjaxSpiderRunner,
    DiscoveryError,
    DiscoveryProcessExitedError,
    DiscoveryResult,
    DiscoveryStateError,
    DiscoveryTimeoutError,
    SpiderRunner,
)
from .process import (
    ZapExecutableError,
    ZapProcessError,
    ZapProcessExitedError,
    ZapProcessManager,
    ZapProcessStateError,
    ZapReadyTimeoutError,
    ZapStartError,
)
from .scanner import (
    ScanConfigurationError,
    ScanError,
    ZapScanner,
    build_scope_regex,
)

__all__ = [
    "DEFAULT_API_TIMEOUT",
    "DEFAULT_MIN_ZAP_VERSION",
    "HttpResponse",
    "UrllibTransport",
    "ZapApiClient",
    "ZapApiError",
    "ZapApiResultError",
    "ZapConfigError",
    "ZapEndpoint",
    "ZapError",
    "ZapExecutableError",
    "ZapHttpError",
    "ZapProcessError",
    "ZapProcessExitedError",
    "ZapProcessManager",
    "ZapProcessStateError",
    "ZapReadyTimeoutError",
    "ZapResponseError",
    "ZapStartError",
    "ZapTransportError",
    "ZapVersionError",
    "version_at_least",
    "AjaxSpiderRunner",
    "DiscoveryError",
    "DiscoveryProcessExitedError",
    "DiscoveryResult",
    "DiscoveryStateError",
    "DiscoveryTimeoutError",
    "SpiderRunner",
    "ScanConfigurationError",
    "ScanError",
    "ZapScanner",
    "build_scope_regex",
]
