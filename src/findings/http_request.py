from __future__ import annotations

import base64
import urllib.parse
from typing import Optional


CURL_DATA_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "--form",
    "-F",
}

CURL_SKIP_VALUE_FLAGS = {
    "--connect-timeout",
    "--max-time",
    "--retry",
    "--retry-delay",
    "--proxy",
    "-o",
    "--output",
    "-w",
    "--write-out",
}


def finding_request_for_burp(finding) -> str:
    if getattr(finding, "curl", None):
        request = http_request_from_curl(
            finding.curl,
            getattr(finding, "method", None),
        )
        if request:
            return request

    return fallback_request(
        finding.url,
        getattr(finding, "method", None),
    )


def http_request_from_curl(
    command: str,
    fallback_method: Optional[str] = None,
) -> Optional[str]:

    tokens = shell_words(
        command.replace("\\\n", " ")
    )

    if not tokens:
        return None

    curl_idx = -1

    for i, token in enumerate(tokens):
        if token == "curl" or token.endswith("/curl"):
            curl_idx = i
            break

    args = (
        tokens[curl_idx + 1 :]
        if curl_idx >= 0
        else tokens
    )

    method = fallback_method or ""
    target = ""
    body_parts: list[str] = []
    headers: list[str] = []

    i = 0

    while i < len(args):

        arg = args[i]

        if arg in ("-X", "--request"):
            i += 1
            if i < len(args):
                method = args[i]
            i += 1
            continue

        if arg.startswith("--request="):
            method = arg[len("--request="):]
            i += 1
            continue

        if arg.startswith("-X") and len(arg) > 2:
            method = arg[2:]
            i += 1
            continue


        if arg in ("-H", "--header"):
            i += 1
            if i < len(args):
                headers.append(args[i])
            i += 1
            continue


        if arg.startswith("-H") and len(arg) > 2:
            headers.append(arg[2:])
            i += 1
            continue


        if arg.startswith("--header="):
            headers.append(arg[len("--header="):])
            i += 1
            continue


        if arg == "--url":
            i += 1
            if i < len(args):
                target = args[i]
            i += 1
            continue


        if arg.startswith("--url="):
            target = arg[len("--url="):]
            i += 1
            continue


        if arg in CURL_DATA_FLAGS:
            i += 1
            value = args[i] if i < len(args) else ""

            if (
                arg == "--json"
                and not has_header(headers, "content-type")
            ):
                headers.append(
                    "Content-Type: application/json"
                )

            body_parts.append(
                encode_curl_data(arg, value)
            )

            if not method:
                method = "POST"

            i += 1
            continue


        data = data_flag_value(arg)

        if data:
            flag, value = data

            if (
                flag == "--json"
                and not has_header(headers, "content-type")
            ):
                headers.append(
                    "Content-Type: application/json"
                )

            body_parts.append(
                encode_curl_data(flag, value)
            )

            if not method:
                method = "POST"

            i += 1
            continue


        if arg in ("-b", "--cookie"):
            i += 1
            if i < len(args):
                cookie = args[i]
                if not has_header(headers, "cookie"):
                    headers.append(
                        f"Cookie: {cookie}"
                    )
            i += 1
            continue


        if arg.startswith("--cookie="):
            cookie = arg[len("--cookie="):]

            if cookie and not has_header(headers, "cookie"):
                headers.append(
                    f"Cookie: {cookie}"
                )

            i += 1
            continue


        if arg in ("-u", "--user"):
            i += 1

            if i < len(args):
                user = args[i]

                if not has_header(headers, "authorization"):
                    encoded = base64.b64encode(
                        user.encode()
                    ).decode()

                    headers.append(
                        f"Authorization: Basic {encoded}"
                    )

            i += 1
            continue


        if arg in ("-A", "--user-agent"):
            i += 1

            if i < len(args):
                ua = args[i]

                if not has_header(headers, "user-agent"):
                    headers.append(
                        f"User-Agent: {ua}"
                    )

            i += 1
            continue


        if arg.startswith("-A") and len(arg) > 2:
            ua = arg[2:]

            if not has_header(headers, "user-agent"):
                headers.append(
                    f"User-Agent: {ua}"
                )

            i += 1
            continue


        if arg.startswith("--user-agent="):
            ua = arg[len("--user-agent="):]

            if not has_header(headers, "user-agent"):
                headers.append(
                    f"User-Agent: {ua}"
                )

            i += 1
            continue


        if arg in CURL_SKIP_VALUE_FLAGS:
            i += 2
            continue


        if arg.startswith(
            ("http://", "https://")
        ):
            target = arg


        i += 1


    if not target:
        return None


    parsed = urllib.parse.urlparse(target)

    if not parsed.scheme:
        return None


    body = "&".join(body_parts)

    normalized_method = (
        method
        or ("POST" if body else "GET")
    ).upper()


    path = (
        parsed.path or "/"
    )

    if parsed.query:
        path += f"?{parsed.query}"


    out = [
        f"{normalized_method} {path} HTTP/1.1"
    ]


    host = parsed.netloc

    if not has_header(headers, "host"):
        out.append(
            f"Host: {host}"
        )


    for header in headers:
        if ":" in header:
            out.append(header)


    if not has_header(headers, "user-agent"):
        out.append(
            "User-Agent: kagent"
        )


    if body and not has_header(
        headers,
        "content-length",
    ):
        out.append(
            f"Content-Length: {len(body.encode())}"
        )


    out.append("")
    out.append(body)

    return "\r\n".join(out)



def fallback_request(
    raw_url: str,
    method: Optional[str] = None,
) -> str:

    parsed = urllib.parse.urlparse(raw_url)

    if not parsed.scheme:
        return (
            f"{method or 'GET'} / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    return (
        f"{method or 'GET'} {path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "User-Agent: kagent\r\n"
        "\r\n"
    )



def has_header(
    headers: list[str],
    name: str,
) -> bool:
    prefix = name.lower() + ":"

    return any(
        h.lower().startswith(prefix)
        for h in headers
    )



def encode_curl_data(
    flag: str,
    value: str,
) -> str:

    if flag == "--data-urlencode":
        return encode_urlencode_arg(value)

    if flag == "--data-raw":
        return value

    if (
        flag in {
            "-d",
            "--data",
            "--data-binary",
        }
        and value.startswith("@")
    ):
        return (
            f"<contents of file {value[1:]}>"
        )

    return value



def encode_urlencode_arg(
    value: str,
) -> str:

    if value.startswith("@"):
        return (
            f"<URL-encoded contents of file {value[1:]}>"
        )

    if "=" in value:
        name, content = value.split("=", 1)

        return (
            f"{name}="
            f"{urllib.parse.quote(content)}"
        )

    return urllib.parse.quote(value)



def data_flag_value(arg: str):
    for flag in CURL_DATA_FLAGS:
        prefix = flag + "="

        if arg.startswith(prefix):
            return (
                flag,
                arg[len(prefix):],
            )

    if arg.startswith("-d") and len(arg) > 2:
        return "-d", arg[2:]

    if arg.startswith("-F") and len(arg) > 2:
        return "-F", arg[2:]

    return None



def shell_words(
    text: str,
) -> list[str]:

    import shlex

    return shlex.split(text)