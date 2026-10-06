"""Domain-neutral foundation for approved red-team projects.

The package intentionally depends only on the Python standard library. It
performs no network activity and creates no files unless a caller explicitly
requests it (for example via ``ScanPath.create`` or ``write_state``).
"""

__all__ = ["__version__"]

__version__ = "0.0.1"
