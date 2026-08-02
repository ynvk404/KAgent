# Sensitive-path classification test cases.

from pathlib import Path
from os.path import expanduser

import pytest

from tools.sensitive import is_sensitive_path


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