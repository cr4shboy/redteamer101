"""Command-line composition for bounded, one-target ZAP discovery runs."""

from .scan_target import EXIT_OK, EXIT_RUNTIME, EXIT_VALIDATION, build_parser, main

__all__ = [
    "EXIT_OK",
    "EXIT_RUNTIME",
    "EXIT_VALIDATION",
    "build_parser",
    "main",
]
