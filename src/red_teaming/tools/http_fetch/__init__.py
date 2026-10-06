"""Bounded HTTP metadata collection through an injected transport only."""

from .adapter import FetchRequest, FetchResult, FetchResponse, HttpFetchAdapter, HttpFetchError

__all__ = ["FetchRequest", "FetchResult", "FetchResponse", "HttpFetchAdapter", "HttpFetchError"]
