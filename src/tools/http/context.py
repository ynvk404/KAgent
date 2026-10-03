"""Runtime-only, exact-origin and identity-scoped HTTP cookie context."""
from __future__ import annotations

import threading

import httpx

from src.target.origin import HTTPOrigin


class HTTPContextStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cookies: dict[tuple[HTTPOrigin, str], httpx.Cookies] = {}
        self._authorization: dict[tuple[HTTPOrigin, str], str] = {}
        self._scope_revision: tuple[int, int, str | None] = (-1, -1, None)

    def sync_target(self, revision: int, engagement_revision: int = 0,
                    epoch: str | None = None) -> None:
        with self._lock:
            key = (revision, engagement_revision,
                   epoch if epoch is not None else self._scope_revision[2])
            if self._scope_revision != key:
                self._cookies.clear()
                self._authorization.clear()
                self._scope_revision = key

    def add_cookies(self, request: httpx.Request, identity: str | None) -> None:
        if not identity:
            return
        with self._lock:
            jar = self._cookies.get((HTTPOrigin.from_url(str(request.url)), identity))
            if jar is not None and "cookie" not in request.headers:
                jar.set_cookie_header(request)

    def cookie_for(self, request: httpx.Request, identity: str | None) -> str | None:
        probe = httpx.Request(request.method, str(request.url))
        self.add_cookies(probe, identity)
        return probe.headers.get("cookie")

    def authorization_for(self, request: httpx.Request, identity: str | None) -> str | None:
        if not identity:
            return None
        with self._lock:
            return self._authorization.get((HTTPOrigin.from_url(str(request.url)), identity))

    def add_identity(self, request: httpx.Request, identity: str | None) -> None:
        if not identity:
            return
        with self._lock:
            authorization = self.authorization_for(request, identity)
            if authorization:
                if "authorization" in request.headers and request.headers["authorization"] != authorization:
                    raise ValueError("explicit Authorization conflicts with runtime identity")
                request.headers.setdefault("Authorization", authorization)
            cookie = self.cookie_for(request, identity)
            if cookie and "cookie" in request.headers and request.headers["cookie"] != cookie:
                raise ValueError("explicit Cookie conflicts with runtime identity")
            self.add_cookies(request, identity)

    def extract(self, request: httpx.Request, response: httpx.Response, identity: str | None,
                origin_url: str | None = None, *,
                generation: tuple[int, int, str] | None = None) -> None:
        if not identity:
            return
        with self._lock:
            if generation is not None and generation != self._scope_revision:
                return
            origin = HTTPOrigin.from_url(origin_url or str(request.url))
            if "authorization" in request.headers:
                self._authorization[(origin, identity)] = request.headers["authorization"]
            jar = self._cookies.setdefault((origin, identity), httpx.Cookies())
            if origin_url and origin_url != str(request.url):
                original = httpx.Request(request.method, origin_url)
                cookie_response = httpx.Response(response.status_code, headers=response.headers, request=original)
                jar.extract_cookies(cookie_response)
            else:
                jar.extract_cookies(response)
