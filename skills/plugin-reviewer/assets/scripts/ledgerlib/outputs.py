"""The overwrite guard every file-writing command shares.

`build` writes a dashboard and `lock` writes a lockfile, and both refuse to
replace a file at `--out` that this tool did not write. Until 0.15.0 each
guard looked for a string -- `id="aio-payload"`, `"lock_version"` -- and a
document that merely described the format carried that string, so a typo'd
`--out` consumed it (finding 12 of the 2026-11-20 review). The guard now asks
the caller's own recognizer whether the bytes *are* the artifact, and refuses
a link at `--out` before anything reads through it.

`--force` means the same thing for both commands: skip this guard and replace
whatever is at `--out`. A link there is replaced by a regular file; its target
is never written, because the write is always a temporary file in the same
directory followed by `os.replace`, which acts on the link itself.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ledgerlib.errors import LedgerError


def guard_output(
    out: Path,
    *,
    force: bool,
    recognizes: Callable[[bytes], bool],
    artifact: str,
) -> None:
    """Raise `LedgerError` unless writing `out` replaces only our own artifact.

    A missing `out` passes. A link is refused whatever it points at: the page
    or lockfile behind it may belong to someone else, and the write would
    replace the link, not follow it, which is not what a caller naming that
    path expects. An existing regular file passes only when `recognizes`
    accepts its bytes. `force` skips every check.
    """
    if force:
        return
    if out.is_symlink():
        raise LedgerError(
            f"refusing to write {str(out)!r}: it is a link; pass --force to "
            "replace the link itself with a regular file (its target is never "
            "written)"
        )
    if not out.exists():
        return
    if not out.is_file():
        raise LedgerError(
            f"refusing to overwrite {str(out)!r}: it is not a regular file"
        )
    try:
        # Bytes, not text: a stray binary file at `out` is exactly what this
        # guard protects, and decoding it must not crash the guard.
        existing = out.read_bytes()
    except OSError as exc:
        raise LedgerError(
            f"cannot read existing file {str(out)!r} to check the "
            f"overwrite guard: {exc}"
        ) from exc
    if not recognizes(existing):
        raise LedgerError(
            f"refusing to overwrite {str(out)!r}: it does not look like "
            f"{artifact}; pass --force to overwrite it anyway"
        )
