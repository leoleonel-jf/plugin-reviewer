"""The overwrite guard every file-writing command shares.

`build` writes a dashboard and `lock` writes a lockfile, and both refuse to
replace a file at `--out` that this tool did not write. Until 0.15.0 each
guard looked for a string -- `id="aio-payload"`, `"lock_version"` -- and a
document that merely described the format carried that string, so a typo'd
`--out` consumed it (finding 12 of the 2026-11-20 review). The guard now asks
the caller's own recognizer whether the bytes *are* the artifact, and refuses
a link at `--out` before anything reads through it.

`--force` means the same thing for both commands: replace the file at `--out`
even when the guard does not recognize it. A link there is replaced by a
regular file; its target is never written, because the write is always a
temporary file in the same directory followed by `os.replace`, which acts on
the link itself. A directory, or anything else that is not a regular file, is
refused with or without `--force`.
"""

from __future__ import annotations

import os
import stat
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
    path expects. Anything else that is not a regular file -- a directory,
    above all -- is refused even with `force`, because no write can replace
    it and `update all` must learn that before it captures (Eve's review of
    0.15.0). An existing regular file passes only when `recognizes` accepts
    its bytes. `force` skips the link refusal and the recognizer, nothing
    else. A failure to inspect `out` is a `LedgerError` naming it.

    Every decision comes from one `os.lstat` of `out` itself, which never
    follows a link: a link is handled before anything could ask about its
    target, so a remote target is never contacted and a target that cannot
    be inspected never blocks a `--force` that only replaces the link (Eve's
    second review of 0.15.0). The file's bytes are read only once `out` is
    known to be a regular file and not a link.
    """
    try:
        status = os.lstat(out)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LedgerError(f"cannot inspect {str(out)!r}: {exc}") from exc
    if stat.S_ISLNK(status.st_mode):
        if force:
            return
        raise LedgerError(
            f"refusing to write {str(out)!r}: it is a link; pass --force to "
            "replace the link itself with a regular file (its target is never "
            "written)"
        )
    if not stat.S_ISREG(status.st_mode):
        raise LedgerError(
            f"refusing to overwrite {str(out)!r}: it is not a regular file"
        )
    if force:
        return
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
