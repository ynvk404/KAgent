import pytest

from src.target.origin import HTTPOrigin


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTPS://Example.COM./path?q=1", "https://example.com"),
        ("https://example.com:443/a", "https://example.com"),
        ("http://example.com:8080/a", "http://example.com:8080"),
        ("http://[0:0:0:0:0:0:0:1]/", "http://[::1]"),
        ("https://täst.example/a", "https://xn--tst-qla.example"),
    ],
)
def test_canonicalizes_http_origins(url: str, expected: str):
    assert HTTPOrigin.from_url(url).as_url() == expected


@pytest.mark.parametrize(
    "url", ["file:///tmp/a", "https:///missing-host", "https://bad host/", ""]
)
def test_rejects_non_http_or_hostless_urls(url: str):
    with pytest.raises(ValueError):
        HTTPOrigin.from_url(url)
