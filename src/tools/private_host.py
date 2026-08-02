"""
Shared private/internal-host detection and SSRF gate.

Port từ:
pentestagent/src/tools/privateHost.ts

Chức năng:
- Parse HTTP URL
- Detect localhost/private/internal str(addr)ess
- DNS resolve để phát hiện domain trỏ vào IP nội bộ
- SSRF permission gate
- Hỗ trợ IPv4 / IPv6 / NAT64 / 6to4
"""

import ipaddress
import socket
from urllib.parse import urlparse


# ============================================================
# Parse HTTP URL
# ============================================================

def parse_http_url(raw: str):
    """
    Parse và validate HTTP(S) URL.

    Chỉ cho phép:
    - http
    - https
    """
    try:
        parsed = urlparse(raw)
    except Exception:
        raise ValueError(
            f"invalid URL: {raw}"
        )

    if parsed.scheme not in (
        "http",
        "https",
    ):
        raise ValueError(
            f"unsupported URL scheme: {parsed.scheme}"
        )

    return parsed


# ============================================================
# SSRF Gate
# ============================================================

async def gate_private_request(
    prompter,
    parsed,
    signal,
    tool_name: str,
) -> str:
    """
    Nếu request tới private/internal host
    thì yêu cầu permission.
    """
    reason = await private_host_reason(
        parsed.hostname
    )

    if not reason:
        return ""

    decision = await prompter.ask(
        {
            "tool": tool_name,
            "summary":
                f"{tool_name}: private/internal URL {parsed.geturl()}",
            "detail":
                f"host: {parsed.hostname}\n"
                f"reason: {reason}\n\n"
                "This points at a private/internal/metadata address, "
                "a classic SSRF target. Approve only if this host "
                "is intentionally in scope.",
            "noSessionCache": True,
        },
        signal,
    )

    if decision == "deny":
        raise Exception(
            f"request to private/internal URL denied: "
            f"{parsed.geturl()}"
        )

    return reason


# ============================================================
# Detect private host
# ============================================================

async def private_host_reason(
    hostname: str | None,
) -> str:
    if not hostname:
        return ""

    host = (
        hostname
        .replace("[", "")
        .replace("]", "")
        .rstrip(".")
        .lower()
    )

    # localhost
    if (
        host == "localhost"
        or host.endswith(".localhost")
    ):
        return "localhost name"

    # IP trực tiếp
    try:
        ip = ipaddress.ip_address(host)

        if ip.version == 4:
            return private_ipv4_reason(
                host
            )
        else:
            return private_ipv6_reason(
                host
            )
    except ValueError:
        pass

    # DNS resolve
    try:
        resolved = socket.getaddrinfo(
            host,
            None,
            proto=socket.IPPROTO_TCP,
        )

        for item in resolved:
            addr = item[4][0]

            try:
                ip = ipaddress.ip_address(
                    addr
                )

                if ip.version == 4:
                    reason = private_ipv4_reason(
                        str(addr)
                    )
                else:
                    reason = private_ipv6_reason(
                        str(addr)
                    )

                if reason:
                    return (
                        f"DNS resolves to "
                        f"{reason} ({addr})"
                    )

            except ValueError:
                continue

    except Exception:
        # để fetch xử lý DNS error
        pass

    return ""


# ============================================================
# IPv4
# ============================================================

def private_ipv4_reason(
    host: str,
) -> str:
    parts = host.split(".")

    if len(parts) != 4:
        return ""

    try:
        nums = [
            int(x)
            for x in parts
        ]
    except ValueError:
        return ""

    a = nums[0]
    b = nums[1]

    if a == 10:
        return "RFC1918 private IPv4"

    if a == 127:
        return "loopback IPv4"

    if a == 169 and b == 254:
        return "link-local/metadata IPv4"

    if a == 172 and 16 <= b <= 31:
        return "RFC1918 private IPv4"

    if a == 192 and b == 168:
        return "RFC1918 private IPv4"

    if a == 0:
        return "this-network IPv4"

    return ""


# ============================================================
# IPv6
# ============================================================

def private_ipv6_reason(
    host: str,
) -> str:
    # IPv4 mapped IPv6
    mapped = host.lower()

    if mapped.startswith(
        "::ffff:"
    ):
        v4 = mapped.replace(
            "::ffff:",
            ""
        )
        reason = private_ipv4_reason(
            v4
        )
        if reason:
            return reason

    # NAT64
    if mapped.startswith(
        "64:ff9b::"
    ):
        tail = mapped.replace(
            "64:ff9b::",
            ""
        )
        v4 = embedded_ipv4(
            tail
        )
        if v4:
            reason = private_ipv4_reason(
                v4
            )
            if reason:
                return (
                    f"NAT64-embedded "
                    f"{reason} ({v4})"
                )

    # 6to4
    if mapped.startswith(
        "2002:"
    ):
        parts = mapped.split(":")

        if len(parts) >= 3:
            v4 = hextets_to_ipv4(
                parts[1],
                parts[2]
            )

            if v4:
                reason = private_ipv4_reason(
                    v4
                )
                if reason:
                    return (
                        f"6to4-embedded "
                        f"{reason} ({v4})"
                    )

    ip = ipaddress.IPv6Address(
        host
    )

    if ip == ipaddress.IPv6Address(
        "::1"
    ):
        return "loopback IPv6"

    if ip == ipaddress.IPv6Address(
        "::"
    ):
        return "unspecified IPv6"

    if ip.is_link_local:
        return "link-local IPv6"

    if ip.is_private:
        return "unique-local IPv6"

    return ""


# ============================================================
# IPv6 helpers
# ============================================================

def embedded_ipv4(
    tail: str,
):
    # dạng 169.254.169.254
    if "." in tail:
        return tail

    parts = tail.split(":")

    if len(parts) >= 2:
        return hextets_to_ipv4(
            parts[-2],
            parts[-1],
        )

    return None


def hextets_to_ipv4(
    hi_hex: str,
    lo_hex: str,
):
    try:
        hi = int(
            hi_hex,
            16
        )
        lo = int(
            lo_hex,
            16
        )

        return (
            f"{hi >> 8}."
            f"{hi & 0xff}."
            f"{lo >> 8}."
            f"{lo & 0xff}"
        )
    except ValueError:
        return None