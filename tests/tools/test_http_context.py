import httpx
import pytest

from src.tools.http_context import HTTPContextStore


def issue(store, url, identity, cookie):
    request = httpx.Request("GET", url)
    response = httpx.Response(200, headers={"Set-Cookie": cookie}, request=request)
    store.extract(request, response, identity)


def cookie(store, url, identity):
    request = httpx.Request("GET", url)
    store.add_cookies(request, identity)
    return request.headers.get("cookie")


def test_cookie_rfc_semantics_and_identity_scope():
    store = HTTPContextStore()
    store.sync_target(1, 1)
    issue(store, "https://target.test/login", "user", "sid=one; Path=/private; Secure; HttpOnly")
    issue(store, "https://target.test/login", "user", "mode=two; Path=/private; Secure")
    assert cookie(store, "https://target.test/private/a", "user") in {"sid=one; mode=two", "mode=two; sid=one"}
    assert cookie(store, "https://target.test/public", "user") is None
    assert cookie(store, "http://target.test/private/a", "user") is None
    assert cookie(store, "https://other.test/private/a", "user") is None
    assert cookie(store, "https://target.test/private/a", "admin") is None
    issue(store, "https://target.test/login", "user", "sid=deleted; Path=/private; Max-Age=0; Secure")
    assert cookie(store, "https://target.test/private/a", "user") == "mode=two"
    store.sync_target(2, 1)
    assert cookie(store, "https://target.test/private/a", "user") is None


def test_cookie_domain_does_not_expand_exact_origin_scope():
    store = HTTPContextStore()
    store.sync_target(1, 1)
    issue(store, "https://target.test/login", "user", "sid=one; Domain=.target.test; Path=/")
    assert cookie(store, "https://target.test/home", "user") == "sid=one"
    assert cookie(store, "https://sub.target.test/home", "user") is None
    store.sync_target(1, 2)
    assert cookie(store, "https://target.test/home", "user") is None


def test_runtime_authorization_is_identity_scoped_and_conflicts_fail_closed():
    store = HTTPContextStore()
    store.sync_target(1, 1)
    request = httpx.Request("GET", "https://target.test/login", headers={"Authorization": "Bearer user"})
    store.extract(request, httpx.Response(200, request=request), "user")
    replay = httpx.Request("GET", "https://target.test/private")
    store.add_identity(replay, "user")
    assert replay.headers["authorization"] == "Bearer user"
    admin = httpx.Request("GET", "https://target.test/private")
    store.add_identity(admin, "admin")
    assert "authorization" not in admin.headers
    wrong_origin = httpx.Request("GET", "https://other.test/private")
    store.add_identity(wrong_origin, "user")
    assert "authorization" not in wrong_origin.headers
    with pytest.raises(ValueError, match="Authorization conflicts"):
        store.add_identity(httpx.Request("GET", "https://target.test/private",
                                         headers={"Authorization": "Bearer admin"}), "user")


@pytest.mark.parametrize("generation", [(2, 1, "first"), (1, 2, "first"), (1, 1, "reset")])
def test_context_reset_rejects_late_cookie_and_authorization(generation):
    store = HTTPContextStore()
    store.sync_target(1, 1, "first")
    old_request = httpx.Request("GET", "https://target.test/login",
                               headers={"Authorization": "Bearer fixture"})
    old_response = httpx.Response(200, headers={"Set-Cookie": "sid=fixture; Path=/"},
                                  request=old_request)
    store.extract(old_request, old_response, "user", generation=(1, 1, "first"))
    assert cookie(store, "https://target.test/private", "user") == "sid=fixture"
    assert store.authorization_for(old_request, "user") == "Bearer fixture"
    store.sync_target(*generation)
    store.extract(old_request, old_response, "user", generation=(1, 1, "first"))
    assert cookie(store, "https://target.test/private", "user") is None
    assert store.authorization_for(old_request, "user") is None
    new_request = httpx.Request("GET", "https://target.test/login")
    new_response = httpx.Response(200, headers={"Set-Cookie": "sid=current; Path=/"},
                                  request=new_request)
    store.extract(new_request, new_response, "user", generation=generation)
    assert cookie(store, "https://target.test/private", "user") == "sid=current"
