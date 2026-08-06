
from pathlib import Path
from os.path import expanduser

import pytest

from src.tools.sensitive import is_sensitive_path


home = Path(expanduser("~"))


@pytest.mark.parametrize(
    "path, want",
    [
        (home / ".ssh" / "id_rsa", True),
        (home / ".aws" / "credentials", True),
        (home / ".kube" / "config", True),
        (home / ".bash_history", True),

        (Path("/etc/shadow"), True),
        (Path("/etc/sudoers"), True),

        (home / "Documents" / "notes.txt", False),
        (Path("/etc/passwd"), False),
        (home / ".ssh_other", False),
        (home / ".aws-not", False),
    ],
)
def test_is_sensitive_path(path: Path, want: bool):
    assert is_sensitive_path(str(path)) is want

@pytest.mark.parametrize(
    "path, want",
    [
        (home / ".git-credentials", True),
        (home / ".azure" / "accessTokens.json", True),
        (home / ".config" / "gh" / "hosts.yml", True),
        (Path("/srv/app/.env"), True),
        (Path("/srv/app/.env.production"), True),
        (Path("/srv/app/credentials.json"), True),
        (Path("/srv/app/deploy/id_ed25519"), True),

        (Path("/srv/app/.environment_notes.md"), False),
        (Path("/srv/app/env.example"), False),
        (Path("/srv/app/settings.json"), False),
    ],
)
def test_is_sensitive_path_extra_locations(path: Path, want: bool):
    assert is_sensitive_path(str(path)) is want
