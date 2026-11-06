"""Sentinel package bootstrap."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinel")
except PackageNotFoundError:
    __version__ = "0.3.0.dev0"

__all__ = ["__version__"]
