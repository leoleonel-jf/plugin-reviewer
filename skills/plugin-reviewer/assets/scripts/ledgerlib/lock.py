"""Pinning the supply chain: turning a baseline into a lockfile.

A baseline answers "what was in this environment that day". It is an
observation, dated and immutable. A lockfile answers a different question --
**"what should be here"** -- and the difference is the one between a `pip
freeze` filed in a log and a `requirements.lock` committed to the repository:
the second is declared intent, small enough to read in a diff, and a CI pass
fails when reality drifts from it.

Two design decisions carry the module.

**Determinism is a requirement, not a quality.** The file is meant to be
committed and read in a diff, so two runs over one baseline produce identical
bytes: entries sorted by `(kind, scope, anchor, name)`, no timestamp, no absolute
path, nothing machine-specific beyond the platform the baseline itself
recorded. Canonicalization is `chain.canonical_text`, the one canonicalization
in this repository.

**`--check` never reads the environment.** It compares a lockfile against a
baseline recorded in the ledger, and nothing else. Verifying against the disk
as it is *now* already has a command -- `drift` -- and giving one question two
answers is worse than either answer alone. A caller who wants both runs both.

Which kinds are pinnable is declared per probe in the adapter (`lockable`),
never hardcoded here: configuration that legitimately changes every day --
instruction files, model settings, permission rules, environment variable
names -- is deliberately left out, because a lockfile that fails CI over an
edited `CLAUDE.md` is one somebody switches off in the first week.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path

from ledgerlib.chain import _write_atomically, canonical_text
from ledgerlib.errors import LedgerError
from ledgerlib.outputs import guard_output
from ledgerlib.paths import load_json


LOCK_VERSION = 1

# The closed vocabulary of differences, following `DRIFT_REASONS`.
LOCK_DIFFERENCES = frozenset({"added", "removed", "changed", "state_changed"})


def _baseline(ledger: Mapping, baseline_id: object) -> dict:
    """The one baseline with this id. Raises when there is none or more than one.

    Two baselines sharing an id are an invalid ledger that `verify` reports;
    picking the first would pin whichever came first in the file and call it
    the baseline the user named (finding 7 of the 2026-11-20 review).
    """
    baselines = ledger.get("baselines") if isinstance(ledger, Mapping) else None
    holders = [
        (position, entry)
        for position, entry in enumerate(baselines if isinstance(baselines, list) else [])
        if isinstance(entry, Mapping) and entry.get("id") == baseline_id
    ]
    if not holders:
        raise LedgerError(f"no baseline with id {baseline_id!r} exists in this ledger")
    if len(holders) > 1:
        places = ", ".join(f"baselines[{position}]" for position, _ in holders)
        raise LedgerError(
            f"baseline id {baseline_id!r} is held by {len(holders)} baselines "
            f"in this ledger ({places}): refusing to pin or compare an "
            "ambiguous baseline; `verify` reports the duplicate"
        )
    return dict(holders[0][1])


def _key(entry: Mapping) -> tuple[str, str, str, str]:
    """An entry's identity: kind, scope, anchor and name.

    The name is part of it because one file can declare several pinnable
    things: two MCP servers in one `config.toml` share kind, scope, anchor and
    the file's digest, and without the name they collapsed into one key, so a
    server taken out went unreported (finding 6 of the 2026-11-20 review).
    Pins have always carried `name`, so a pin written before 0.14.0 compares
    by the same key.
    """
    return (
        str(entry.get("kind") or ""),
        str(entry.get("scope") or ""),
        str(entry.get("anchor") or ""),
        str(entry.get("name") or ""),
    )


def _by_key(entries: list[Mapping], *, side: str) -> dict[tuple, Mapping]:
    """Index entries by identity, refusing one identity held twice.

    A repeated identity has no single "before" or "after" to compare, so it
    is a diagnostic of its own rather than a silent last-one-wins.
    """
    indexed: dict[tuple, Mapping] = {}
    for entry in entries:
        key = _key(entry)
        if key in indexed:
            kind, scope, anchor, name = key
            raise LedgerError(
                f"the {side} holds {kind} {name!r} at {anchor!r} (scope "
                f"{scope or None!r}) twice: one identity with two entries "
                "cannot be pinned or compared"
            )
        indexed[key] = entry
    return indexed


def _entries(
    baseline: Mapping,
    lockable: frozenset[str],
    unpinned: frozenset[tuple[str, str | None, str]] = frozenset(),
) -> list[dict]:
    rows: list[dict] = []
    items = baseline.get("items")
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = item.get("kind")
        if kind not in lockable:
            continue
        attributes = item.get("attributes")
        scope = attributes.get("scope") if isinstance(attributes, Mapping) else None
        pattern = attributes.get("glob") if isinstance(attributes, Mapping) else None
        # `validate_ledger` asks only that `attributes` be an object, so either
        # value can be a list or an object in an imported or hand-edited
        # baseline, and an unhashable one made the lookup below raise
        # `TypeError` out of `lock` and `lock --check` (Eve's third review of
        # 0.16.0). Only text is a recorded pattern; anything else leaves the
        # item pinnable by its kind, as before 0.16.0.
        match_scope = scope if isinstance(scope, str) and scope.strip() else None
        if isinstance(pattern, str) and (kind, match_scope, pattern) in unpinned:
            # Found by a probe that is not lockable, though its kind is: the
            # skills Codex caches under `.system` change with every client
            # update and are no configuration of the user's (Eve's second
            # review of 0.16.0).
            continue
        rows.append(
            {
                "kind": kind,
                "name": item.get("name"),
                "anchor": item.get("anchor"),
                "scope": scope if isinstance(scope, str) else None,
                "digest": item.get("digest"),
                "state": item.get("state"),
            }
        )
    _by_key(rows, side=f"baseline {baseline.get('id')!r}")
    rows.sort(key=_key)
    return rows


def build_lock(
    ledger: Mapping,
    *,
    baseline_id: str,
    lockable: frozenset[str],
    unpinned: frozenset[tuple[str, str | None, str]] = frozenset(),
) -> dict:
    """Assemble the lockfile document from one baseline. Raises on an unknown id.

    `unpinned` is what `unpinned_patterns` returns for the adapter: items
    whose kind is in `lockable` but whose pattern belongs to a probe that is
    not, left out.
    """
    baseline = _baseline(ledger, baseline_id)
    return {
        "lock_version": LOCK_VERSION,
        "generated_from": baseline_id,
        "client": baseline.get("client"),
        "adapter_version": baseline.get("adapter_version"),
        # Carried so a lock taken on one platform is not silently compared
        # against a baseline from another, where whole anchors legitimately
        # do not exist.
        "platform": baseline.get("platform"),
        "entries": _entries(baseline, lockable, unpinned),
    }


def render_lock(document: Mapping) -> str:
    """The bytes written to disk: indented for reading, ordered for diffing.

    Indented rather than compact because a human reads this in a pull request;
    `sort_keys` and the pre-sorted `entries` are what make the diff mean
    something.
    """
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def check_lock(
    locked: Mapping,
    ledger: Mapping,
    *,
    lockable: frozenset[str],
    unpinned: frozenset[tuple[str, str | None, str]] = frozenset(),
) -> tuple[list[dict], int]:
    """Compare a lockfile against the baseline it was generated from.

    Returns `(rows, code)`: one row per difference, `0` when identical and `1`
    otherwise. A mismatched `lock_version`, `client` or `platform` is raised
    rather than reported, because comparing across any of those would report
    every entry as added and removed at once, burying the real difference in
    noise that looks like data.
    """
    version = locked.get("lock_version")
    if version != LOCK_VERSION:
        raise LedgerError(
            f"unsupported lock_version {version!r}; this tool writes and reads "
            f"version {LOCK_VERSION}"
        )

    baseline_id = locked.get("generated_from")
    baseline = _baseline(ledger, baseline_id)

    for field in ("client", "platform"):
        expected, found = locked.get(field), baseline.get(field)
        if expected != found:
            raise LedgerError(
                f"this lockfile was generated for {field} {expected!r} and "
                f"baseline {baseline_id!r} records {found!r}: comparing across "
                f"{field}s would report every entry as both added and removed"
            )

    current = _by_key(
        _entries(baseline, lockable, unpinned), side=f"baseline {baseline_id!r}"
    )
    pinned_entries = locked.get("entries")
    pinned = _by_key(
        [
            entry
            for entry in (pinned_entries if isinstance(pinned_entries, list) else [])
            if isinstance(entry, Mapping)
        ],
        side="lockfile",
    )

    rows: list[dict] = []
    for key in sorted(set(pinned) | set(current)):
        before, after = pinned.get(key), current.get(key)
        if before is None:
            rows.append({**after, "difference": "added"})
            continue
        if after is None:
            rows.append({**before, "difference": "removed"})
            continue
        if before.get("state") != after.get("state"):
            rows.append({**after, "difference": "state_changed"})
        elif before.get("digest") != after.get("digest"):
            rows.append({**after, "difference": "changed"})

    return rows, 1 if rows else 0


def lockable_kinds(adapter: Mapping) -> frozenset[str]:
    """The kinds this adapter declares pinnable. Declared data, never hardcoded."""
    probes = adapter.get("probes") if isinstance(adapter, Mapping) else None
    return frozenset(
        probe["kind"]
        for probe in (probes if isinstance(probes, list) else [])
        if isinstance(probe, Mapping)
        and probe.get("lockable") is True
        and isinstance(probe.get("kind"), str)
    )


def unpinned_patterns(adapter: Mapping) -> frozenset[tuple[str, str | None, str]]:
    """`(kind, scope, glob)` of the probes that are not lockable though their kind is.

    `lockable_kinds` reduces the adapter to a set of kinds, and one lockable
    `skill` probe made every skill item pinnable, whichever probe found it:
    the skills Codex caches in `$USER_CONFIG/skills/.system`, recorded by a
    probe of their own without `lockable`, went into `agent.lock` and turned
    every client update into a lock difference (Eve's second review of
    0.16.0). Every glob item records the pattern that found it, so the
    probe's eligibility can be applied to the item. A pattern that a lockable
    probe of the same kind and scope also declares stays pinnable, so no
    system skill declared lockable is dropped, and nothing is filtered by
    scope alone.
    """
    probes = adapter.get("probes") if isinstance(adapter, Mapping) else None
    probes = [p for p in (probes if isinstance(probes, list) else []) if isinstance(p, Mapping)]
    kinds = lockable_kinds(adapter)

    def triple(probe: Mapping) -> tuple[str, str | None, str] | None:
        kind, scope, pattern = probe.get("kind"), probe.get("scope"), probe.get("glob")
        if kind not in kinds or not isinstance(pattern, str):
            return None
        return (kind, scope if isinstance(scope, str) and scope.strip() else None, pattern)

    pinned = {triple(p) for p in probes if p.get("lockable") is True}
    return frozenset(
        found
        for found in (triple(p) for p in probes)
        if found is not None and found not in pinned
    )


# The exact shape `build_lock` has written since 0.5.0, top level and entry.
_LOCK_KEYS = frozenset(
    {"lock_version", "generated_from", "client", "adapter_version", "platform", "entries"}
)
_ENTRY_KEYS = frozenset({"kind", "name", "anchor", "scope", "digest", "state"})


def looks_like_lock(data: bytes) -> bool:
    """Whether `data` is a lockfile this tool wrote, by its whole shape.

    A JSON object with exactly the keys `build_lock` writes, `lock_version`
    equal to `LOCK_VERSION`, a string `generated_from`, and `entries` a list
    of objects with exactly an entry's keys. Every released writer produced
    this shape, so a pin of any version is recognized; a schema, a note, or a
    JSON object that only borrows `lock_version` and `entries` is not
    (finding 12 of the 2026-11-20 review, and Eve's review of 0.15.0).
    """
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    if not isinstance(document, dict) or set(document) != _LOCK_KEYS:
        return False
    version = document.get("lock_version")
    if isinstance(version, bool) or version != LOCK_VERSION:
        return False
    if not isinstance(document.get("generated_from"), str):
        return False
    entries = document.get("entries")
    return isinstance(entries, list) and all(
        isinstance(entry, dict) and set(entry) == _ENTRY_KEYS for entry in entries
    )


def _write_lock(text: str, out: Path, *, force: bool) -> None:
    """Write the lockfile atomically, refusing to clobber a file that is not one.

    The guard `write_dashboard` uses (`ledgerlib.outputs`), for the reason it
    uses it: a typo'd `--out` must not consume a file that had nothing to do
    with this tool. The write is the ledger's own: a temporary file in the
    same directory, then `os.replace`, so a failure leaves the previous
    lockfile whole and no temporary file behind.
    """
    guard_output(
        out,
        force=force,
        recognizes=looks_like_lock,
        artifact="a lockfile (no top-level lock_version)",
    )
    _write_atomically(out, text, "\n")


def lock_command(
    *,
    ledger: Path,
    baseline_id: str | None,
    check: Path | None,
    out: Path | None,
    force: bool,
    adapter: Path | None = None,
    user_config: Path | None = None,
    project: Path | None = None,
) -> int:
    """`lock` as a command. Exit `0` identical or written, `1` differences, `2` tool error."""
    # Imported here rather than at module scope: `adapters` imports nothing
    # from this module, and keeping the dependency at the call site makes that
    # one-way relationship obvious.
    from ledgerlib.adapters import select_adapter_detail
    from ledgerlib.scan import BUNDLED_ADAPTERS

    try:
        document = load_json(ledger)
        client = document.get("client")
        selection = select_adapter_detail(
            client=None,
            ledger_client=client if adapter is None else None,
            adapter=adapter,
            user_config=user_config,
            bundled=BUNDLED_ADAPTERS,
            environ={},
            project=Path.cwd() if project is None else project,
        )
        lockable = lockable_kinds(selection["document"])
        unpinned = unpinned_patterns(selection["document"])

        if check is not None:
            locked = load_json(check)
            rows, code = check_lock(
                locked, document, lockable=lockable, unpinned=unpinned
            )
            for row in rows:
                print(
                    f"{row['difference']}: {row.get('kind')} {row.get('anchor')}",
                    file=sys.stderr,
                )
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return code

        built = build_lock(
            document, baseline_id=baseline_id, lockable=lockable, unpinned=unpinned
        )
        text = render_lock(built)
        if out is None:
            print(text, end="")
            return 0
        try:
            _write_lock(text, out, force=force)
        except OSError as exc:
            raise LedgerError(f"cannot write {str(out)!r}: {exc}") from exc
        print(f"wrote {out}", file=sys.stderr)
        # Printed so `lock --from ... --out ...` still yields the document on
        # stdout for a caller that pipes it, exactly as `scan` does.
        print(canonical_text({"wrote": str(out), "entries": len(built["entries"])}))
        return 0
    except LedgerError as exc:
        print(exc, file=sys.stderr)
        return 2
