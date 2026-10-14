from __future__ import annotations

import re
import json
from dataclasses import replace

from rich.console import Group, RenderableType
from rich.text import Text

from src.target.origin import HTTPOrigin
from src.ui.theme import BOLD_ACCENT, WARNING
from src.ui.theme import DARK_UI, UIPalette
from src.permission.network.grants import WARNING as HTTP_WARNING

from src.tools.common.tool_display import display_tool_name
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.permission.permission import Decision, PermissionReviewCancelled
from src.ui.render.sanitize import sanitize_text as redact

_COMMAND_TITLES = {
    "shell": "Shell command",
    "bash": "Shell command",
    "BashTool": "Shell command",
    "http": "HTTP request",
    "file_write": "File write",
    "FileWriteTool": "File write",
    "file_edit": "File edit",
    "FileEditTool": "File edit",
}

_CAPTURE_SCOPE = (
    "Use only this immutable capture and its identity for input mutations. "
    "No redirects or shared HTTP context import. Rights end on target/scope/session reset."
)
_CONCLUSION_SOURCE = (
    "Source: operator-reviewed, not autonomous. This reviews a conclusion, "
    "not execution permission.\n"
)
_BROWSER_WARNINGS = {
    "read": "Read access may expose page data, screenshots and console logs.",
    "navigate": "Navigation changes the selected tab location.",
    "interaction": ("Click/type may submit forms, change application state or enter sensitive data. "
                    "Accept unknown application effects on this lab."),
}
_BROWSER_EXTENSION = (
    "The Extension does not authenticate tab/profile identity or constrain all Chrome traffic. "
    "Revoke: /permissions browser revoke"
)


def _sensitive_action(req: BridgedPermissionRequest) -> tuple[str, str, str] | None:
    if req.tool != "file" or not req.no_session_cache:
        return None
    verb, marker, resolved = req.summary.partition(" sensitive file: ")
    paths, boundary, warning = req.detail.rpartition("\n\n")
    expected = ("This path is on the sensitive-path list "
                "(private keys, cloud credentials, shell history, config dirs, etc.). "
                f"Approve only if you intend to {verb} it.")
    if (not marker or not verb or not resolved or "\n" in resolved
            or not boundary or warning != expected or not paths.startswith("path: ")):
        return None
    path_text = paths.removeprefix("path: ")
    original, separator, target = path_text.rpartition("\nresolves to: ")
    if separator and target == resolved and "\n" not in original:
        explanation = "Original: " + original + "\n"
    elif path_text == resolved:
        explanation = ""
    else:
        return None
    return verb.capitalize() + " sensitive file", resolved, explanation + "Sensitive-path access may expose secrets."


def _framed_action(req: BridgedPermissionRequest) -> tuple[str, str, str] | None:
    """Return the existing structured action and any explanatory remainder."""
    detail = req.detail
    sensitive = _sensitive_action(req)
    if sensitive is not None:
        return sensitive

    if req.tool in {"shell", "bash", "BashTool"} and detail:
        return _COMMAND_TITLES[req.tool], detail, ""

    if req.tool == "http":
        private_prefix = "http: private/internal URL "
        if req.summary.startswith(private_prefix):
            return _COMMAND_TITLES[req.tool], req.summary.removeprefix(private_prefix), detail
        if re.match(r"^[A-Z]+\s+\S+", detail):
            return _COMMAND_TITLES[req.tool], detail, ""

    if req.tool in {"file_write", "FileWriteTool", "file_edit", "FileEditTool"}:
        path, separator, remainder = detail.partition("\n")
        if path.startswith("path: "):
            return (
                _COMMAND_TITLES[req.tool],
                path.removeprefix("path: "),
                remainder if separator else "",
            )

    return None



class PermissionModal:

    def __init__(
        self,
        req: BridgedPermissionRequest,
    ):
        self.req = req

    def _review_kind(self) -> str:
        """Recognize internal reviews by their verified producer contract."""
        req = self.req
        source, _, rest = req.detail.partition("\n")
        if (req.tool == "http_capture_credentials" and req.force_operator and req.no_session_cache
                and req.summary.startswith("Authorize captured credentials for ")
                and source.startswith("source: ") and "; baseline: " in source
                and rest.startswith(_CAPTURE_SCOPE + "\n")):
            return "capture"
        if (req.tool == "review_result" and req.no_session_cache
                and req.summary.startswith("Review ") and req.detail.startswith(_CONCLUSION_SOURCE)):
            return "conclusion"
        return ""

    def _capture_detail(self, detail: str) -> str:
        # These are configured limits, not a countdown or a freshly renewed TTL.
        head, sep, tail = detail.partition("\nCurrent HTTP execution limits: ")
        limits, boundary, request = tail.partition("\n\n")
        lifetime, separator, rest = limits.partition("; ")
        if (sep and boundary and separator and lifetime.startswith("expires in ")
                and lifetime.endswith("s") and rest.startswith("requests <= ")):
            return (head + "\nReviewed HTTP limits: configured lifetime: "
                    + lifetime.removeprefix("expires in ") + "; " + rest + "\n\n" + request)
        # Unrecognized/session formats retain all producer text; the heading
        # clarifies that no remaining lifetime/quota has been calculated here.
        return detail.replace("\nCurrent HTTP execution limits: ",
                              "\nReviewed HTTP limits (configured, not remaining): ", 1)

    def _browser_preview(self, detail: str, supports_reuse: bool) -> tuple[str, bool]:
        """Deduplicate only the complete, adapter-owned Browser grant trailer."""
        req = self.req
        if not req.force_operator or not req.no_session_cache:
            return detail, False
        scope = req.session_scope_display or ""
        group = req.offer_browser_grant
        if group in _BROWSER_WARNINGS and supports_reuse and scope:
            remote = req.tool.removeprefix("mcp_browser_")
            if not req.tool.startswith("mcp_browser_browser_") or req.summary != "mcp: browser/" + remote:
                return detail, False
            preview, separator, trailer = detail.rpartition("\n\n" + scope + "\n")
            if not separator:
                return detail, False
            # Validate the producer's envelope, but preserve its JSON verbatim.
            try:
                value = json.loads(preview)
            except (TypeError, ValueError, RecursionError):
                return detail, False
            if (not isinstance(value, dict) or set(value) != {"server", "executor", "tool", "args"}
                    or value["server"] != "browser" or value["tool"] != remote
                    or not isinstance(value["args"], dict)):
                return detail, False
        elif req.tool == "browser_lab_grant" and req.summary.startswith("Activate Browser "):
            scope = req.summary.removeprefix("Activate ")
            if not detail.startswith(scope + "\n"):
                return detail, False
            preview = ""
            trailer = detail[len(scope) + 1:]
            group = next((key for key, warning in _BROWSER_WARNINGS.items()
                          if trailer == "Session lifetime; no call quota. " + warning + "\n" + _BROWSER_EXTENSION), None)
            if group is None:
                return detail, False
        else:
            return detail, False
        warning = _BROWSER_WARNINGS[group]
        if trailer != "Session lifetime; no call quota. " + warning + "\n" + _BROWSER_EXTENSION:
            return detail, False
        # Keep the consequence and Extension limitation, without repeating scope
        # or the second generic statement about accepting unknown effects.
        warning = warning.removesuffix(" Accept unknown application effects on this lab.")
        compact = ("Session lifetime; no call quota. " + warning + "\n"
                   "Extension does not authenticate tab/profile or constrain all Chrome traffic.\n"
                   "Revoke: /permissions browser revoke")
        return (preview + "\n\n" if preview else "") + compact, True

    def _discovery_presentation(self, detail: str, supports_reuse: bool) -> tuple[str, str, bool]:
        req = self.req
        if not supports_reuse:
            return req.summary, detail, False
        lines = detail.splitlines()
        if req.tool == "content_discovery":
            labels = ("origin: ", "base path: ", "backend: ", "paths: ",
                      "maximum requests: ", "rate limit: ", "timeout: ")
            restriction = "method: GET; recursion: disabled; redirects: not followed"
            if len(lines) != 8 or lines[-1] != restriction or not all(
                    line.startswith(label) for line, label in zip(lines, labels)):
                return req.summary, detail, False
            origin, path, backend, paths, maximum, rate, timeout = (
                line.removeprefix(label) for line, label in zip(lines, labels))
            if not rate.endswith("/s") or not timeout.endswith("s"):
                return req.summary, detail, False
            rate, timeout = rate.removesuffix("/s"), timeout.removesuffix("s")
            expected = (f"content discovery on {origin}{path} using {backend} "
                        f"({paths} paths, <= {maximum} requests, <= {rate}/s, {timeout}s)")
            if req.summary == f"content discovery: {origin}{path}" and req.session_scope_display == expected:
                return "Content discovery", restriction, True
        elif req.tool == "service_discovery":
            labels = ("active origin: ", "target host: ", "backend: ", "ports: ", "network scan timeout: ")
            restriction = "protocol: TCP only; scripts, UDP, OS detection, and host ranges: disabled"
            if len(lines) != 6 or lines[-1] != restriction or not all(
                    line.startswith(label) for line, label in zip(lines, labels)):
                return req.summary, detail, False
            origin, host, backend, ports, timeout = (line.removeprefix(label) for line, label in zip(lines, labels))
            suffix = "s (DNS and permission wait excluded)"
            if timeout.endswith(suffix):
                seconds = timeout.removesuffix(suffix)
                expected = f"TCP service discovery on {host}, ports {ports} using {backend} (scan timeout {seconds}s)"
                if (req.summary == f"service discovery: {host} ({len(ports.split(','))} TCP ports)"
                        and req.session_scope_display == expected):
                    return "Service discovery", "active origin: " + origin + "\n" + restriction, True
        return req.summary, detail, False

    def _other_presentation(self, detail: str, supports_reuse: bool) -> tuple[str, str, bool]:
        req = self.req
        # Preserve Native HTTP's existing presentation, including its fallback.
        if req.tool in {"http", "http_lab_grant"}:
            return req.summary, detail, False
        if req.tool in {"content_discovery", "service_discovery"}:
            return self._discovery_presentation(detail, supports_reuse)
        if req.tool == "browser_capture_clear" and req.no_session_cache:
            original = ("Wipes all captured requests, endpoints, and snapshots from memory. "
                        "Forwarding continues — new captures will repopulate the store.")
            if req.summary == "clear browser capture store" and detail == original:
                return ("Clear browser capture memory",
                        "Removes all captured requests, endpoints and snapshots. Forwarding continues.", True)
        if req.summary == "plugin: " + req.tool:
            command, separator, stdin = detail.partition("\nstdin:\n")
            try:
                arguments = json.loads(stdin) if separator and command else None
            except (TypeError, ValueError, RecursionError):
                arguments = None
            if isinstance(arguments, dict):
                return req.summary, detail, True
        if not (req.tool.startswith("mcp_") or req.tool in {"coverage", "read_tool_result"}):
            return req.summary, detail, req.summary == req.tool
        try:
            value = json.loads(detail)
        except (TypeError, ValueError, RecursionError):
            value = None
        if isinstance(value, dict):
            if (req.tool.startswith("mcp_") and set(value) == {"server", "executor", "tool", "args"}
                    and isinstance(value["server"], str) and isinstance(value["tool"], str)
                    and isinstance(value["args"], dict)
                    and req.summary == f"mcp: {value['server']}/{value['tool']}"):
                return req.summary, detail, True
            if req.tool == "coverage" and req.no_session_cache and req.summary == "coverage" and value.get("action") == "clear":
                return "Clear all coverage records", detail, True
            if (req.tool == "read_tool_result" and req.no_session_cache
                    and req.summary in {req.tool, "Read a retained sanitized tool result range"}
                    and set(value) == {"result_ref", "start_char", "max_chars"}
                    and isinstance(value["result_ref"], str)
                    and type(value["start_char"]) is int and type(value["max_chars"]) is int):
                return "Read retained tool result range", detail, True
        return req.summary, detail, req.summary == req.tool

    def _preview_detail(self) -> tuple[str, tuple[str, ...]]:
        """Omit native HTTP presentation metadata without changing the request.

        Only strip complete producer-owned suffixes. Unknown layouts and
        metadata-like text inside command/payload content remain visible.
        """
        detail = self.req.detail
        if self.req.tool not in {"http", "http_lab_grant"}:
            return detail, ()
        head, sep, warning = detail.rpartition("\n\n")
        if not sep or warning != HTTP_WARNING:
            return detail, ()
        limits_pattern = (
            r"(?:expires in [0-9.]+s|session lifetime); (?:requests <= [0-9]+|no request quota); "
            r"token bucket [0-9.]+/s, burst [0-9]+; concurrency <= [0-9]+; "
            r"request URL \+ headers \+ body <= [0-9]+ bytes; "
            r"decoded response body retained <= [0-9]+ bytes\. "
            r"These are application limits, not total wire-byte/server-resource guarantees\."
        )
        if self.req.tool == "http":
            preview, sep, envelope = head.rpartition("\n\n")
            prefix = next((value for value in ("Once-only execution envelope: ", "Current execution limits: ")
                           if envelope.startswith(value)), "")
            if sep and prefix and re.fullmatch(limits_pattern, envelope[len(prefix):]):
                request, footer_sep, footer = preview.rpartition("\n\n")
                metadata = re.fullmatch(
                    r"response body cap: [0-9]+; timeout: 60s; redirects: "
                    r"(?P<redirects>off|explicit follow-up, at most [0-9]+ hops); "
                    r"TLS verification: off; socket: [^\n]+", footer
                ) if footer_sep else None
                if metadata:
                    try:
                        method, url = request.split("\n", 1)[0].split(" ", 1)
                        origin = HTTPOrigin.from_url(url)
                    except ValueError:
                        # Unknown action identity: retain supplied warnings.
                        return preview, ()
                    notices: list[str] = []
                    # Both facts come from the native execution preview. The
                    # scheme only determines whether disabled TLS is relevant.
                    if origin.scheme == "https":
                        notices.append("TLS verification: off")
                    redirects = metadata.group("redirects")
                    if redirects != "off":
                        notices.append("Redirects: " + redirects)
                    return request, tuple(notices)
                return preview, ()
        else:
            issuer, sep, limits = head.partition("\n")
            if (sep and re.fullmatch(r"issuer: operator; session: [^\n]+", issuer)
                    and re.fullmatch(limits_pattern, limits)):
                lifetime, quota, _ = limits.split("; ", 2)
                return ("Grant: all endpoints, methods and payloads on the stated origin\n"
                        + lifetime + "; " + quota), ()
        return detail, ()

    def _supports_reuse(self) -> bool:
        # The bridge remains authoritative at decision time. Do not advertise
        # a reusable decision for a review whose lifecycle has already ended.
        try:
            return self.req.supports_session and (
                self.req.is_current is None or self.req.is_current()
            )
        except Exception:
            return False

    def handle_key(
        self,
        key: str,
    ) -> None:

        key = key.lower()

        if key in ("escape", "esc"):
            self.req.reject(PermissionReviewCancelled())

        elif key == "y":
            self.req.resolve(Decision.ALLOW_ONCE)

        elif key == "a" and self._supports_reuse():
            self.req.resolve(Decision.ALLOW_SESSION)

        elif key == "n":
            self.req.resolve(Decision.DENY)

    def _reuse_label(self) -> str:
        if self.req.offer_browser_grant:
            return "trust Browser " + self.req.offer_browser_grant
        if self.req.tool == "http":
            return "trust origin"
        if self.req.tool in {"file_write", "FileWriteTool", "file_edit", "FileEditTool"}:
            # The authoritative scope row names the exact file or artifact root.
            return "trust artifact root" if (self.req.session_scope_display or "").startswith(("writes under ", "edits under ")) else "trust file scope"
        return "trust scope"

    def instructions(self, *, ui: UIPalette = DARK_UI) -> Text:
        grant_review = self.req.tool in {"http_lab_grant", "browser_lab_grant"}
        kind = self._review_kind()
        keys = "y " + ("authorize capture use" if kind == "capture" else "approve conclusion"
                       if kind == "conclusion" else "approve grant" if grant_review else "allow once")
        if self._supports_reuse():
            keys += " · a " + self._reuse_label()
        keys += (" · n decline review" if kind == "conclusion" else " · n deny") + " · Esc cancel"
        return Text(keys, style=ui.muted)

    def render(self, *, include_instructions: bool = True, ui: UIPalette = DARK_UI) -> RenderableType:

        req = self.req
        supports_reuse = self._supports_reuse()
        kind = self._review_kind()

        preview, notices = self._preview_detail()
        if kind == "capture":
            preview = self._capture_detail(preview)
        preview, browser_compact = self._browser_preview(preview, supports_reuse)
        summary, preview, other_compact = self._other_presentation(preview, supports_reuse)
        # Framing operates on the presentation copy, never the reviewed request.
        action = _framed_action(replace(req, detail=preview))
        parts: list[RenderableType] = [] if action or kind or browser_compact or other_compact else [Text(f"Tool: {display_tool_name(req.tool)}")]

        scope = req.session_scope_display if supports_reuse else "current invocation only"
        if supports_reuse and not scope and req.offer_browser_grant:
            scope = "Browser " + req.offer_browser_grant + "; review adapter grant scope before activation"
        scope_row = Text(("Session trust: " if supports_reuse else "Allow once: ") + redact(scope or ""))
        if (not supports_reuse and action is not None and req.session_scope_display
                and req.tool in {"file_write", "FileWriteTool", "file_edit", "FileEditTool"}):
            scope_row = Text("Allow once: " + redact(req.session_scope_display))
        if kind == "capture":
            scope_row = Text("Scope: selected immutable capture/identity · bounded reuse under reviewed HTTP limits")
        elif kind == "conclusion":
            scope_row = Text("Scope: conclusion review · no execution rights")

        show_detail = bool(req.detail) and req.detail != req.summary

        if action is None:
            parts.append(Text(redact(summary), style=BOLD_ACCENT))
            if req.tool not in {"http_lab_grant", "browser_lab_grant"}:
                parts.append(scope_row)

        if action is not None:
            title, action_text, explanation = action
            head, separator, tail = action_text.partition("\n")
            parts.append(Text(title, style=BOLD_ACCENT))
            parts.append(Text(redact(head)))
            parts.append(scope_row)
            parts.extend(Text(redact(notice), style=WARNING) for notice in notices)
            if separator:
                parts.append(Text(redact(tail)))
            if explanation:
                parts.append(Text(redact(explanation), style=WARNING if req.tool == "file" else ""))

        if req.offer_browser_grant == "interaction" and not browser_compact:
            parts.append(Text("Click/type may submit forms or change application state.", style=WARNING))

        if action is None and show_detail:
            # A Browser grant repeats its scope verbatim in summary and detail.
            scope_head = req.summary.removeprefix("Activate ")
            if req.tool == "browser_lab_grant" and preview.startswith(scope_head + "\n"):
                preview = preview[len(scope_head) + 1:]
            parts.extend((Text(""), Text(redact(preview))))

        if include_instructions:
            parts.extend((Text(""), self.instructions(ui=ui)))
        return Group(*parts)
