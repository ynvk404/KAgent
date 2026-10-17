"""Controller-owned typed trusted-host scanner plans and live authority checks."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, asdict, field
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import stat
import sys
import shutil
from typing import Any
from urllib.parse import urlsplit, unquote

from src.engagement.state import normalize_tcp_ip, parse_tcp_ports, format_tcp_ports
from src.permission.network.grants import check_cancelled
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.target.origin import HTTPOrigin
from src.target.target import Target
from src.tools.common.capabilities import CapabilityInventory
from src.tools.discovery.common import normalize_host, validate_relative_path
from src.tools.execution.scanner_resources import RESOURCES, ScannerResources
from src.tools.execution.scanner_runner import ScannerRuntime
from src.tools.execution.wordlists import wordlist_catalog, wordlist_files


def validate_scanner_args(args: dict[str, Any]) -> None:
    scanner = args.get('scanner')
    common = {'scanner', 'timeout_seconds', 'rate'}
    if not isinstance(scanner, str) or scanner not in {'nmap', 'ffuf'}:
        raise ValueError('scanner must be nmap or ffuf')
    allowed = common | ({'target', 'ports'} if scanner == 'nmap' else {
        'url', 'wordlist_id', 'threads', 'request_timeout_seconds',
        'calibration', 'match_status', 'filter_status', 'filter_size'})
    if set(args) - allowed:
        raise ValueError('unsupported scanner fields: ' + ', '.join(sorted(set(args) - allowed)))
    timeout = args.get('timeout_seconds', 300)
    if type(timeout) is not int or not 1 <= timeout <= 1800:
        raise ValueError('timeout_seconds must be an integer from 1 to 1800 (Shell deadline)')
    if 'rate' in args:
        rate = args['rate']
        if isinstance(rate, bool) or not isinstance(rate, (float, int)) or not math.isfinite(rate) or rate <= 0:
            raise ValueError('rate must be positive and finite. Omit it to use scanner defaults.')
        if scanner == 'ffuf' and type(rate) is not int:
            raise ValueError('ffuf rate must be a positive integer')
    if scanner == 'nmap':
        normalize_tcp_ip(args.get('target'))
        parse_tcp_ports(args.get('ports'))
        return
    scanner_url(args.get('url'))
    if not isinstance(args.get('wordlist_id'), str) or not 1 <= len(args['wordlist_id']) <= 128:
        raise ValueError('wordlist_id is required')
    for key, default in [('threads', 40), ('request_timeout_seconds', 10)]:
        if type(args.get(key, default)) is not int or args.get(key, default) <= 0:
            raise ValueError(f'{key} must be a positive integer')
    if args.get('threads', 40) > RESOURCES.max_threads:
        raise ValueError('threads must be at most 256 for the scanner resource profile')
    if args.get('request_timeout_seconds', 10) > 1800:
        raise ValueError('request_timeout_seconds must be at most 1800')
    if 'calibration' in args and type(args['calibration']) is not bool:
        raise ValueError('calibration must be boolean')
    for key in ('match_status', 'filter_status'):
        if key in args:
            status_codes(args[key], allow_all=key == 'match_status')
    if 'filter_size' in args:
        sizes = args['filter_size']
        if (not isinstance(sizes, list) or not 1 <= len(sizes) <= 256
                or any(type(n) is not int or not 0 <= n <= 2**63 - 1 for n in sizes)):
            raise ValueError('filter_size must contain 1 to 256 bounded nonnegative integers')


def status_codes(value: Any, *, allow_all: bool = False) -> str:
    if allow_all and value == 'all':
        return 'all'
    if not isinstance(value, str):
        raise ValueError('HTTP status matcher/filter must be a string')
    ports = parse_tcp_ports(value)
    if not all(100 <= p <= 599 for p in ports):
        raise ValueError('HTTP status codes must be between 100 and 599')
    return format_tcp_ports(ports)


def scanner_url(value: Any) -> tuple[HTTPOrigin, str]:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('scanner URL must be an HTTP URL without whitespace or control characters')
    parts = urlsplit(value)
    origin = HTTPOrigin.from_url(value)
    normalize_host(origin.hostname)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ValueError('scanner URL cannot contain credentials, query or fragment')
    if value.count('FUZZ') != 1 or parts.path.count('FUZZ') != 1:
        raise ValueError('exactly one FUZZ keyword is required, only in the URL path')
    if not parts.path.startswith('/') or parts.path.startswith('//'):
        raise ValueError('scanner URL requires an absolute path within its origin')
    path = validate_relative_path(parts.path[1:], max_length=None)
    # Reuse normalization, but do not silently change the reviewed URL template.
    if unquote(path).count('FUZZ') != 1:
        raise ValueError('encoded FUZZ aliases are not supported')
    return origin, origin.as_url() + '/' + path


@dataclass(frozen=True, slots=True)
class FileIdentity:
    source: str
    canonical: str
    signature: tuple[int, ...]
    sha256: str

    def current(self) -> bool:
        try:
            path = Path(self.source)
            return str(path.resolve(strict=True)) == self.canonical and file_signature(path.stat()) == self.signature
        except OSError:
            return False


def file_signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


def read_identity(path: Path, *, executable: bool = False, root: Path | None = None) -> tuple[FileIdentity, bytes]:
    canonical = path.resolve(strict=True)
    if not executable and (canonical != path.absolute() or canonical.stat().st_nlink != 1):
        raise ExecutionBlocked('blocked: wordlist must not use symlink/hardlink indirection')
    if not stat.S_ISREG(canonical.stat().st_mode):
        raise ExecutionBlocked('blocked: scanner resource must be a regular file')
    if executable and root is not None and (canonical.is_relative_to(root) or path.absolute().is_relative_to(root)):
        raise ExecutionBlocked('blocked: scanner binary cannot be in the model-writable project')
    descriptors: list[int] = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        for part in canonical.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        opened = os.open(canonical.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
    with os.fdopen(opened, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ExecutionBlocked('blocked: scanner resource must be a regular file')
        if not executable and before.st_nlink != 1:
            raise ExecutionBlocked('blocked: wordlist must not use symlink/hardlink indirection')
        if executable and (not before.st_mode & 0o111 or before.st_mode & 0o6022):
            raise ExecutionBlocked('blocked: scanner executable permissions are not trusted')
        limit = 128 * 1024**2 if executable else 8 * 1024**2
        if before.st_size > limit:
            raise ExecutionBlocked('blocked: scanner resource exceeds input limit')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ExecutionBlocked('blocked: scanner resource exceeds input limit')
        if file_signature(os.fstat(stream.fileno())) != file_signature(before):
            raise ExecutionBlocked('blocked: scanner resource changed during preparation')
    if executable:
        if not data.startswith(b'\x7fELF'):
            raise ExecutionBlocked('blocked: scanner requires a trusted Linux ELF binary')
        try:
            if os.getxattr(canonical, 'security.capability'):
                raise ExecutionBlocked('blocked: privileged scanner executable unsupported')
        except OSError as err:
            import errno
            if err.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise
    identity = FileIdentity(str(path.absolute()), str(canonical), file_signature(before), hashlib.sha256(data).hexdigest())
    if not identity.current():
        raise ExecutionBlocked('blocked: scanner resource changed during preparation')
    return identity, data


@dataclass(frozen=True, slots=True)
class WordlistSnapshot:
    name: str
    source: FileIdentity | None
    data: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ScannerPlan:
    scanner: str
    binary: FileIdentity
    argv: tuple[str, ...]
    target_url: str
    target_revision: int
    origin: HTTPOrigin
    address: str
    ports: tuple[int, ...]
    wordlist: WordlistSnapshot | None
    timeout_seconds: int
    authority_revision: tuple[str, int, int, int]
    origin_authority: tuple[str, int, str | None]
    binding_id: int
    arguments_digest: str
    launcher: FileIdentity
    resources: ScannerResources
    directory: str
    output_name: str
    semantic_key: str
    runtime_generation: int

    @property
    def command(self) -> tuple[str, ...]:
        return (self.launcher.canonical, *self.resources.arguments(self.timeout_seconds),
                self.binary.canonical, *self.argv)

    @property
    def digest(self) -> str:
        material = asdict(self)
        if self.wordlist is not None:
            # The content is immutable; bind its actual hash without huge JSON copies.
            material['wordlist']['data'] = hashlib.sha256(self.wordlist.data).hexdigest()
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()

    def display(self) -> str:
        # Explicit fields keep ffuf -u URL visible without weakening secret redaction.
        return json.dumps({'scanner': self.scanner, 'binary': self.binary.canonical,
            'permission_unit': 'scanner_job',
            'approval': 'One job for this exact plan; may send multiple requests/connections within reviewed scope.',
            'http_permissions': 'HTTP grants do not authorize this job. HTTP quota, rate, concurrency, body limits '
                                'and confirm-each apply to the existing governed network adapters, not scanner traffic.',
            'binary_sha256': self.binary.sha256, 'target_origin': self.origin.as_url(),
            'target_url': self.target_url, 'transport_ip': self.address,
            'tcp_ports': format_tcp_ports(self.ports), 'effective_argv': self.argv,
            'wordlist_id': self.wordlist.name if self.wordlist else None,
            'wordlist_sha256': self.wordlist.sha256 if self.wordlist else None,
            'wordlist_source': self.wordlist.source.canonical if self.wordlist and self.wordlist.source else None,
            'wordlist_source_sha256': self.wordlist.source.sha256 if self.wordlist and self.wordlist.source else None,
            'wordlist_bytes': len(self.wordlist.data) if self.wordlist else None,
            'wordlist_entries': self.wordlist.data.count(b'\n') if self.wordlist else None,
            'timeout_seconds': self.timeout_seconds, 'plan_digest': self.digest,
            'resource_profile': asdict(self.resources), 'launcher_sha256': self.launcher.sha256,
            'effective_command': self.command,
            'execution': 'typed trusted Linux host; one active scanner slot; no ordinary-shell fallback'}, indent=2)


@dataclass(frozen=True, slots=True)
class ScannerBinding:
    """Installed by the controller, never derived from model arguments."""
    policy: ExecutionPolicy
    target: Target
    capabilities: CapabilityInventory
    wordlists: tuple[tuple[str, Path], ...] = ()
    resources: ScannerResources = RESOURCES
    launcher_path: str = '/usr/bin/prlimit'
    runtime: ScannerRuntime = field(default_factory=ScannerRuntime, compare=False, repr=False)

    def __post_init__(self) -> None:
        wordlist_files(self.wordlists)  # Validate controller registration, never model-selected paths.
        if self.policy.scanner_runtime is None:
            self.policy.scanner_runtime = self.runtime
        else:
            object.__setattr__(self, 'runtime', self.policy.scanner_runtime)
        self.policy.scanner_binding = self

    def storage_ready(self) -> bool:
        # Fixed controller paths only, never discover resources by walking the
        # filesystem. Final descriptor checks remain mandatory at execution.
        for parts in (('.kagent',), ('.kagent', 'tmp'), ('.kagent', 'tmp', 'scanners'), ('.kagent', 'scanners')):
            path = self.policy.root.joinpath(*parts)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or (info.st_mode & 0o022 if len(parts) == 1 else stat.S_IMODE(info.st_mode) != 0o700)):
                return False
        return True

    def catalog(self) -> dict[str, Any]:
        from src.tools.execution.scanner_runner import SUPPORTED_BUILDS
        snapshot = self.capabilities.snapshot()
        # Installed path is reported separately; readiness also needs a tested
        # build, trusted limiter and an enforcing Linux controller binding.
        binaries = {}
        for name in ('nmap', 'ffuf'):
            path = getattr(snapshot, name)
            version = None
            try:
                identity, _ = read_identity(Path(path), executable=True, root=self.policy.root) if path else (None, b'')
                version = SUPPORTED_BUILDS.get(name, {}).get(identity.sha256) if identity else None
                limiter, _ = read_identity(Path(self.launcher_path), executable=True, root=self.policy.root)
                ready = bool(version and limiter and self.storage_ready() and sys.platform == 'linux' and not self.runtime.closed)
            except (OSError, ExecutionBlocked):
                ready = False
            binaries[name] = {'installed': bool(path), 'ready': ready, 'version': version}
        return {'permission_unit': 'scanner_job', 'binaries': binaries,
                'wordlists': wordlist_catalog(self.wordlists),
                'resources': asdict(self.resources)}

    def check_authority(self) -> HTTPOrigin:
        if self.policy.scanner_binding is not self:
            raise ExecutionBlocked('blocked: scanner controller binding changed')
        if sys.platform != 'linux':
            raise ExecutionBlocked('blocked: trusted scanners require Linux/WSL')
        if not self.storage_ready():
            raise ExecutionBlocked('blocked: private scanner storage ownership/permissions unavailable')
        if self.target.empty():
            raise ExecutionBlocked('blocked: scanner requires an active target')
        active_url = self.target.base_url()
        parts = urlsplit(active_url)
        if (parts.username is not None or parts.password is not None or parts.query or parts.fragment
                or any(ord(c) <= 32 or ord(c) == 127 for c in active_url) or '\\' in active_url):
            raise ExecutionBlocked('blocked: scanner active target must not contain credentials/query/fragment or control characters')
        self.policy.require_network(self.target.base_url())
        origin = HTTPOrigin.from_url(self.target.base_url())
        if origin in self.policy.engagement.http_permissions._blocked_gate:
            raise ExecutionBlocked('blocked: private-host permission declined')
        if '*' in self.policy.revoked or 'shell' in self.policy.revoked:
            raise ExecutionBlocked('blocked: tool/session-revoked')
        return origin

    async def prepare(self, args: dict[str, Any], signal: Any) -> ScannerPlan:
        validate_scanner_args(args)
        origin = self.check_authority()
        stamp = self.policy.stamp()
        runtime_generation = self.runtime.generation
        origin_authority = self.policy.engagement.http_permissions.origin_authority(origin)
        target_url, target_revision = self.target.base_url(), self.target.revision
        scanner, timeout = args['scanner'], args.get('timeout_seconds', 300)
        if scanner == 'ffuf' and scanner_url(args['url'])[0] != origin:
            raise ExecutionBlocked('blocked: ffuf must match the exact active origin')
        address = normalize_tcp_ip(args['target']) if scanner == 'nmap' else origin.hostname
        ports = parse_tcp_ports(args['ports']) if scanner == 'nmap' else ()
        explicit_tcp = scanner == 'nmap' and self.policy.engagement.tcp_allows(address, ports)
        if scanner == 'nmap' and not explicit_tcp and ports != (origin.port,):
            raise ExecutionBlocked('blocked: TCP destination/ports outside declared scope')
        check_cancelled(signal)
        if not explicit_tcp:
            addresses = await asyncio.wait_for(asyncio.to_thread(resolve_addresses, origin.hostname), timeout)
            if scanner == 'nmap' and address not in addresses:
                raise ExecutionBlocked('blocked: TCP address is not the active target or declared TCP scope')
            if scanner == 'ffuf':
                address = addresses[0]
        binary_path = getattr(self.capabilities.snapshot(), scanner)
        if not binary_path:
            raise ExecutionBlocked('blocked: scanner binary unavailable')
        binary, _ = await asyncio.to_thread(read_identity, Path(binary_path), executable=True, root=self.policy.root)
        if not shutil.which(self.launcher_path):
            raise ExecutionBlocked('blocked: scanner resource limiter unavailable')
        launcher, _ = await asyncio.to_thread(read_identity, Path(self.launcher_path), executable=True, root=self.policy.root)
        wordlist = await self.snapshot_wordlist(args['wordlist_id']) if scanner == 'ffuf' else None
        check_cancelled(signal)
        if (self.check_authority() != origin or self.policy.stamp() != stamp
                or self.runtime.generation != runtime_generation
                or self.policy.engagement.http_permissions.origin_authority(origin) != origin_authority
                or self.target.base_url() != target_url or self.target.revision != target_revision):
            raise ExecutionBlocked('blocked: scanner authority changed during preparation')
        # Bind every launcher/resource/output decision before operator review.
        key = hashlib.sha256(json.dumps([args, binary.sha256,
            wordlist.sha256 if wordlist else None, target_url, target_revision, stamp,
            origin_authority, asdict(self.resources), launcher.sha256], sort_keys=True).encode()).hexdigest()
        directory = self.policy.root / '.kagent' / 'tmp' / 'scanners' / key
        argv: list[str]
        if scanner == 'nmap':
            argv = ['-sT', '-n', '-Pn', '-p', format_tcp_ports(ports),
                '--host-timeout', f'{timeout}s', '-oX', str(directory / 'scan.xml')]
            if 'rate' in args:
                argv += ['--max-rate', str(args['rate'])]
            if ipaddress.ip_address(address).version == 6:
                argv += ['-6']
            argv += [address]
        else:
            _, url = scanner_url(args['url'])
            host = f'[{address}]' if ':' in address else address
            transport_url = f'{origin.scheme}://{host}:{origin.port}' + urlsplit(url).path
            authority = urlsplit(origin.as_url()).netloc
            argv = ['-u', transport_url, '-H', 'Host: ' + authority, '-w', str(directory / 'words.txt'),
                '-t', str(args.get('threads', 40)), '-timeout', str(args.get('request_timeout_seconds', 10)),
                '-maxtime', str(timeout), '-noninteractive', '-of', 'json', '-o', str(directory / 'results.json'),
                '-mc', status_codes(args.get('match_status', 'all'), allow_all=True)]
            if origin.scheme == 'https':
                argv += ['-sni', origin.hostname]
            if 'rate' in args:
                argv += ['-rate', str(args['rate'])]
            if args.get('calibration'):
                argv += ['-ac']
            if 'filter_status' in args:
                argv += ['-fc', status_codes(args['filter_status'])]
            if 'filter_size' in args:
                argv += ['-fs', ','.join(map(str, args['filter_size']))]
        # Effective options, rather than volatile args/approval/path IDs, define
        # reusable observations. Equivalent explicit defaults share a key.
        effective = [item.replace(str(directory), '<scratch>') for item in argv]
        semantic = hashlib.sha256(json.dumps([scanner, origin.as_url(), address, effective,
            binary.sha256, launcher.sha256, asdict(self.resources), wordlist.sha256 if wordlist else None],
            sort_keys=True).encode()).hexdigest()
        return ScannerPlan(scanner, binary, tuple(argv), target_url, target_revision, origin,
            address, ports, wordlist, timeout, stamp, origin_authority, id(self), arguments_digest(args),
            launcher, self.resources, str(directory), 'scan.xml' if scanner == 'nmap' else 'results.json', semantic,
            runtime_generation)

    async def snapshot_wordlist(self, name: str) -> WordlistSnapshot:
        path = dict(wordlist_files(self.wordlists)).get(name)
        if path is None:
            raise ExecutionBlocked('blocked: wordlist_id is not controller-approved')
        source, raw = await asyncio.to_thread(read_identity, path)
        words = tuple(raw.decode('utf-8').splitlines())
        normalized = []
        for word in words:
            if not word or word.startswith('#'):
                continue
            if word != word.strip() or word.startswith('/') or any(ord(c) < 32 or ord(c) == 127 for c in word):
                raise ValueError('wordlist entries must be relative paths without whitespace/control delimiters')
            normalized.append(validate_relative_path(word, max_length=None))
        if not normalized:
            raise ValueError('wordlist cannot be empty')
        data = ('\n'.join(normalized) + '\n').encode()
        if len(data) > 8 * 1024**2 or len(normalized) > 65535 or any(len(word) > 8192 for word in normalized):
            raise ValueError('approved wordlist exceeds scanner input bounds')
        return WordlistSnapshot(name, source, data, hashlib.sha256(data).hexdigest())

    def validate(self, plan: ScannerPlan) -> None:
        origin = self.check_authority()
        if (plan.binding_id != id(self) or plan.origin != origin or plan.authority_revision != self.policy.stamp()
                or plan.runtime_generation != self.runtime.generation
                or plan.origin_authority != self.policy.engagement.http_permissions.origin_authority(origin)
                or plan.target_url != self.target.base_url() or plan.target_revision != self.target.revision):
            raise ExecutionBlocked('blocked: stale scanner plan/authority')
        current_path = getattr(self.capabilities.snapshot(), plan.scanner)
        if current_path != plan.binary.source or not plan.binary.current():
            raise ExecutionBlocked('blocked: scanner binary changed after preparation')
        if (plan.resources != self.resources or self.launcher_path != plan.launcher.source
                or not plan.launcher.current() or self.runtime.closed):
            raise ExecutionBlocked('blocked: scanner launcher/resource profile unavailable or changed')
        if plan.scanner == 'nmap' and not self.policy.engagement.tcp_allows(plan.address, plan.ports):
            if plan.ports != (origin.port,):
                raise ExecutionBlocked('blocked: TCP ports no longer authorized')
        if plan.wordlist is not None:
            wordlist = plan.wordlist
            if wordlist.source is not None and not wordlist.source.current():
                raise ExecutionBlocked('blocked: wordlist changed after preparation')
            if hashlib.sha256(wordlist.data).hexdigest() != wordlist.sha256:
                raise ExecutionBlocked('blocked: wordlist snapshot changed')


def resolve_addresses(host: str) -> tuple[str, ...]:
    try:
        return (normalize_tcp_ip(host),)
    except ValueError:
        addresses = {normalize_tcp_ip(row[4][0]) for row in socket.getaddrinfo(
            host, None, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)}
        if not addresses:
            raise ExecutionBlocked('blocked: scanner target resolution failed')
        return tuple(sorted(addresses, key=lambda address: (ipaddress.ip_address(address).version, address)))


def arguments_digest(args: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()
