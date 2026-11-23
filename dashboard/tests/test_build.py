"""Tests for `ledgerlib.build`: the escaping serializer and payload assembly.

The suite loads `dashboard.py` by file path exactly the way `test_drift.py`
and `test_rollback.py` do, for the same side effect: `dashboard.py` inserts
its own directory at the front of `sys.path` before importing `ledgerlib`, so
the imports below resolve to the bundle's copy rather than to anything
installed.

`serialize_payload` is tested first and separately, because it is the
security core (design spec `docs/specs/2026-07-31-dashboard-build.md`
section 1.1): the property under test is global -- `assertNotIn("<",
serialized)` -- not a search for particular tag names, so one ledger value
containing a raw `</script><script>` payload is enough to exercise it.

`build_payload`'s fixtures are schema-valid ledgers, following
`RollbackCliTestCase` in test_rollback.py rather than the minimal documents
`test_drift.py` uses for classification-only fixtures: `build_payload`
validates the ledger it is given (`validate_ledger`, reused rather than
reimplemented, exactly as `drift_command` and `rollback_preview_command`
do), so every fixture here must be a document the validator accepts whole.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    REPO_ROOT
    / "skills"
    / "plugin-reviewer"
    / "assets"
    / "scripts"
    / "dashboard.py"
)
SPEC = importlib.util.spec_from_file_location("dashboard", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
dashboard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard)

from ledgerlib import drift as drift_module  # noqa: E402
from ledgerlib import rollback as rollback_module  # noqa: E402
from ledgerlib.build import (  # noqa: E402
    TEMPLATE_PATH,
    _ISLAND_MARKER,
    build_command,
    build_payload,
    inject_payload,
    serialize_payload,
    write_dashboard,
)
from ledgerlib.constants import TOOL_VERSION  # noqa: E402
from ledgerlib.errors import LedgerError  # noqa: E402


def extract_island(html: str) -> str:
    """Pull the `aio-payload` island's text content out of a built dashboard.

    Written independently of `inject_payload`'s own splice logic -- same two
    searches, but never a call into the code under test -- so a round-trip
    test proves the *output* is correct rather than proving the
    implementation agrees with itself.
    """
    marker_at = html.index(_ISLAND_MARKER)
    tag_end = html.index(">", marker_at) + 1
    content_end = html.index("</script", tag_end)
    return html[tag_end:content_end]


class SerializePayloadTests(unittest.TestCase):
    """Design spec section 1.1's escaping contract, one property per test."""

    def test_no_literal_less_than_survives_serialization(self) -> None:
        payload = {"title": "</script><script>alert(1)</script>"}
        serialized = serialize_payload(payload)
        self.assertNotIn("<", serialized)

    def test_the_escaped_form_round_trips_through_json_loads(self) -> None:
        original = "</script><script>alert(1)</script>"
        serialized = serialize_payload({"title": original})
        restored = json.loads(serialized)
        self.assertEqual(restored["title"], original)

    def test_line_and_paragraph_separators_are_escaped(self) -> None:
        value = "line" + chr(0x2028) + "break" + chr(0x2029) + "end"
        serialized = serialize_payload({"title": value})
        self.assertNotIn(chr(0x2028), serialized)
        self.assertNotIn(chr(0x2029), serialized)
        self.assertIn("\\u2028", serialized)
        self.assertIn("\\u2029", serialized)
        restored = json.loads(serialized)
        self.assertEqual(restored["title"], value)

    def test_output_is_deterministic_across_two_calls(self) -> None:
        payload = {"b": 1, "a": {"z": 1, "y": 2}, "c": [3, 2, 1]}
        first = serialize_payload(payload)
        second = serialize_payload(payload)
        self.assertEqual(first, second)

    def test_output_uses_sorted_keys_and_compact_separators(self) -> None:
        serialized = serialize_payload({"b": 1, "a": 2})
        self.assertEqual(serialized, '{"a":2,"b":1}')

    def test_a_lone_surrogate_survives_serialization_as_utf8(self) -> None:
        ledger_value = json.loads('{"t": "\\ud800"}')["t"]
        serialized = serialize_payload({"title": ledger_value})
        # The whole point of the fix: this must not raise UnicodeEncodeError.
        serialized.encode("utf-8")
        self.assertNotIn("<", serialized)
        restored = json.loads(serialized)
        self.assertEqual(restored["title"], ledger_value)

    def test_backslash_then_less_than_has_no_literal_less_than_and_round_trips(
        self,
    ) -> None:
        value = chr(92) + "<"
        serialized = serialize_payload({"title": value})
        self.assertNotIn("<", serialized)
        restored = json.loads(serialized)
        self.assertEqual(restored["title"], value)


class BuildTestCase(unittest.TestCase):
    """A real temporary tree and schema-valid-ledger fixture builders.

    Follows `RollbackCliTestCase` in test_rollback.py: `full_run` and
    `known_project` produce documents `validate_ledger` accepts whole, not
    the minimal fixtures `test_drift.py`'s `DriftReportTestCase` builds for
    classification-only tests.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.user_config = self.tmp / "user_config"
        self.user_config.mkdir(parents=True)
        self.adapter_path = self.tmp / "adapter.json"
        self.adapter_path.write_text(
            json.dumps(self.adapter_document()), encoding="utf-8"
        )

    def adapter_document(self) -> dict:
        return {
            "adapter_version": 1,
            "client": "testclient",
            "expires_on": "2099-01-01",
            "anchors": {"$USER_CONFIG": [str(self.user_config)]},
            "probes": [
                {
                    "kind": "instruction-file",
                    "scope": "user",
                    "path": "$USER_CONFIG/CLAUDE.md",
                }
            ],
            "sensitive_key_patterns": [],
        }

    def write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def digest_of(self, path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def bare_ledger(self, *, language: str = "en") -> dict:
        return {
            "schema_version": "1.0",
            "ledger_id": "l-build",
            "scope": "global",
            "language": language,
            "client": "testclient",
            "adapter_version": 1,
            "created": "2026-07-29",
            "updated": "2026-07-30",
            "id_authority": True,
            "sequences": {"MAT": 1, "PROP": 1, "RUN": 1, "ADR": 0, "BASE": 0},
            "known_projects": [],
            "records": [],
            "baselines": [],
            "backlog": [],
        }

    def valid_ledger(
        self,
        *,
        records: list | None = None,
        known_projects: list | None = None,
        language: str = "en",
    ) -> dict:
        ledger = self.bare_ledger(language=language)
        if records is not None:
            ledger["records"] = records
        if known_projects is not None:
            ledger["known_projects"] = known_projects
        return ledger

    def target(self, **overrides: object) -> dict:
        base: dict = {
            "anchor": "$USER_CONFIG/settings.json",
            "kind": "mcp-server",
            "before_digest": "sha256:" + "0" * 64,
            "after_digest": "sha256:" + "1" * 64,
            "reversible": True,
            "residual_effect": None,
        }
        base.update(overrides)
        return base

    def full_run(
        self,
        targets: list,
        backup: object,
        *,
        run_id: str = "RUN-2026-000",
        evidence: list | None = None,
    ) -> dict:
        """A RUN record `validate_ledger` accepts whole."""
        return {
            "id": run_id,
            "type": "RUN",
            "title": "a validated run",
            "status": "VALIDATED",
            "classification": "ADOPT LOCALLY",
            "scope": "project",
            "created": "2026-07-30",
            "updated": "2026-07-30",
            "file": f"records/{run_id}.md",
            "links": {"materials": [], "runs": [], "adrs": []},
            "evidence": evidence if evidence is not None else [],
            "proposal": "PROP-2026-000",
            "authorization": {
                "quote": "Implement proposal PROP-2026-000",
                "recorded_on": "2026-07-30",
            },
            "result": "VALIDATED",
            "targets": targets,
            "backup": backup,
            "rollback": {"tested": "NOT_TESTED"},
            "self_reported": ["targets"],
        }

    def full_material(
        self,
        *,
        material_id: str = "MAT-2026-000",
        evidence: list | None = None,
        title: str = "a material",
    ) -> dict:
        """A MATERIAL record `validate_ledger` accepts whole."""
        return {
            "id": material_id,
            "type": "MATERIAL",
            "title": title,
            "status": "ANALYZED",
            "classification": "MONITOR",
            "scope": "project",
            "created": "2026-07-30",
            "updated": "2026-07-30",
            "file": f"records/{material_id}.md",
            "links": {"materials": [], "runs": [], "adrs": []},
            "evidence": evidence if evidence is not None else [],
        }

    def backlog_entry(
        self,
        *,
        entry_id: str = "MAT-2026-000",
        classification: str = "MONITOR",
        reason: str = "flagged for review",
        revisit_trigger: str | None = "next audit",
        revisit_after: str | None = None,
    ) -> dict:
        """A backlog entry `validate_ledger` accepts, referencing `entry_id`.

        `validate_collection`'s cross-check requires `id` to name a record
        declared elsewhere in the same ledger (`ledgerlib/validate.py`), so
        every caller must also include a record with a matching id.
        """
        return {
            "id": entry_id,
            "classification": classification,
            "reason": reason,
            "revisit_trigger": revisit_trigger,
            "revisit_after": revisit_after,
        }

    def write_ledger(self, document: dict, *, name: str = "ledger.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def known_project(self, *, project_root: str, status: str = "OK") -> dict:
        return {
            "project_root": project_root,
            "ledger_path": str(Path(project_root) / "ledger.json"),
            "last_seen": "2026-07-30",
            "last_digest": "sha256:" + "a" * 64,
            "status": status,
        }

    def verified_backup(self, run_id: str = "RUN-2026-000") -> dict:
        backup_file = self.write(
            self.user_config / "backups" / f"{run_id}.bak", "backup bytes\n"
        )
        return {
            "path": f"$USER_CONFIG/backups/{run_id}.bak",
            "digest": self.digest_of(backup_file),
            "verified": True,
        }

    def build(self, ledger: dict, **overrides: object):
        overrides.setdefault("adapter", self.adapter_path)
        overrides.setdefault("project", self.tmp)
        overrides.setdefault("lang", None)
        return build_payload(ledger, ledger_source="ledger.json", **overrides)


class BuildPayloadEnvelopeTests(BuildTestCase):
    def test_payload_schema_mode_and_ledger_are_set(self) -> None:
        ledger = self.valid_ledger()
        ledger_before = copy.deepcopy(ledger)
        payload, _ = self.build(ledger)
        self.assertEqual(payload["payload_schema"], 1)
        self.assertEqual(payload["mode"], "built")
        self.assertEqual(payload["ledger"], ledger)
        self.assertEqual(payload["tool_version"], TOOL_VERSION)
        # `build_payload` may hold the same ledger object rather than a copy;
        # this pins that it never mutates it along the way.
        self.assertEqual(ledger, ledger_before)


class BuildPayloadDriftReuseTests(BuildTestCase):
    def test_computed_drift_is_exactly_drift_reports_report(self) -> None:
        sentinel_report = {"sentinel": True}
        with mock.patch.object(
            drift_module,
            "drift_report",
            return_value=(sentinel_report, [], 0),
        ) as spy:
            payload, _ = self.build(self.valid_ledger(), today="2026-07-31")
        spy.assert_called_once()
        self.assertIs(payload["computed"]["drift"], sentinel_report)

    def test_a_drift_ledger_error_lands_as_computed_drift_error(self) -> None:
        with mock.patch.object(
            drift_module,
            "drift_report",
            side_effect=LedgerError("no adapter for client 'testclient'"),
        ):
            payload, _ = self.build(self.valid_ledger())
        self.assertEqual(
            payload["computed"]["drift"],
            {"error": "no adapter for client 'testclient'"},
        )
        self.assertEqual(payload["mode"], "built")


class BuildPayloadPreviewsTests(BuildTestCase):
    def test_previews_holds_one_entry_per_run_naming_a_backup(self) -> None:
        settings = self.write(self.user_config / "settings.json", "after\n")
        run_with_backup = self.full_run(
            [self.target(after_digest=self.digest_of(settings))],
            self.verified_backup(),
        )
        run_without_backup = self.full_run(
            [self.target()], None, run_id="RUN-2026-001"
        )
        ledger = self.valid_ledger(records=[run_with_backup, run_without_backup])
        payload, _ = self.build(ledger)
        self.assertIn("RUN-2026-000", payload["computed"]["previews"])
        self.assertNotIn("RUN-2026-001", payload["computed"]["previews"])
        self.assertEqual(
            payload["computed"]["previews"]["RUN-2026-000"]["run"], "RUN-2026-000"
        )

    def test_a_preview_ledger_error_lands_as_error_and_build_continues(self) -> None:
        run = self.full_run([self.target()], self.verified_backup())
        ledger = self.valid_ledger(records=[run])
        with mock.patch.object(
            rollback_module,
            "rollback_preview",
            side_effect=LedgerError("no record with id 'RUN-2026-000' exists"),
        ):
            payload, _ = self.build(ledger)
        self.assertEqual(
            payload["computed"]["previews"]["RUN-2026-000"],
            {"error": "no record with id 'RUN-2026-000' exists"},
        )
        self.assertEqual(payload["mode"], "built")


class BuildPayloadExpiredEvidenceTests(BuildTestCase):
    def test_expired_evidence_lists_entries_with_expires_on_before_today(
        self,
    ) -> None:
        material = self.full_material(
            evidence=[
                {
                    "source": "https://example.com/old",
                    "kind": "article",
                    "verified_on": "2026-01-01",
                    "time_sensitive": True,
                    "expires_on": "2026-06-01",
                },
                {
                    "source": "https://example.com/fresh",
                    "kind": "article",
                    "verified_on": "2026-07-01",
                    "time_sensitive": True,
                    "expires_on": "2099-01-01",
                },
            ]
        )
        ledger = self.valid_ledger(records=[material])
        payload, _ = self.build(ledger, today="2026-07-31")
        self.assertEqual(
            payload["computed"]["expired_evidence"],
            [
                {
                    "record": "MAT-2026-000",
                    "source": "https://example.com/old",
                    "expires_on": "2026-06-01",
                }
            ],
        )


class BuildPayloadUnreachableProjectsTests(BuildTestCase):
    def test_unreachable_projects_lists_roots_that_no_longer_exist(self) -> None:
        present = self.tmp / "present-project"
        present.mkdir()
        gone = self.tmp / "gone-project"
        known_projects = [
            self.known_project(project_root=str(present)),
            self.known_project(project_root=str(gone)),
        ]
        ledger = self.valid_ledger(known_projects=known_projects)
        payload, _ = self.build(ledger)
        self.assertEqual(
            payload["computed"]["unreachable_projects"], [str(gone)]
        )


class BuildPayloadValidationTests(BuildTestCase):
    def test_a_schema_invalid_ledger_raises_naming_the_first_finding(self) -> None:
        ledger = self.valid_ledger()
        del ledger["sequences"]
        with self.assertRaises(LedgerError) as ctx:
            self.build(ledger)
        self.assertIn("sequences", str(ctx.exception))

    def test_nothing_is_computed_for_an_invalid_ledger(self) -> None:
        ledger = self.valid_ledger()
        del ledger["sequences"]
        with mock.patch.object(drift_module, "drift_report") as spy:
            with self.assertRaises(LedgerError):
                self.build(ledger)
        spy.assert_not_called()


class BuildPayloadLanguageTests(BuildTestCase):
    def test_lang_lands_verbatim_when_given(self) -> None:
        payload, messages = self.build(self.valid_ledger(), lang="pt-BR")
        self.assertEqual(payload["lang"], "pt-BR")
        self.assertFalse(any("unsupported language" in m for m in messages))

    def test_lang_falls_back_to_ledger_language_when_not_given(self) -> None:
        payload, _ = self.build(self.valid_ledger(language="pt-BR"))
        self.assertEqual(payload["lang"], "pt-BR")

    def test_an_unknown_lang_argument_falls_back_to_en_with_a_message(self) -> None:
        payload, messages = self.build(self.valid_ledger(), lang="fr")
        self.assertEqual(payload["lang"], "en")
        self.assertTrue(
            any("fr" in message and "en" in message for message in messages),
            messages,
        )

    def test_an_unknown_ledger_language_falls_back_to_en_with_a_message(
        self,
    ) -> None:
        payload, messages = self.build(self.valid_ledger(language="fr"))
        self.assertEqual(payload["lang"], "en")
        self.assertTrue(
            any("fr" in message and "en" in message for message in messages),
            messages,
        )


class BuildPayloadGeneratedAtTests(BuildTestCase):
    def test_generated_at_is_iso8601_utc_pinned_to_today(self) -> None:
        payload, _ = self.build(self.valid_ledger(), today="2026-07-31")
        generated_at = payload["generated_at"]
        self.assertTrue(generated_at.startswith("2026-07-31T"), generated_at)
        self.assertTrue(generated_at.endswith("Z"), generated_at)

    def test_an_unparseable_today_raises_ledger_error(self) -> None:
        with self.assertRaises(LedgerError) as ctx:
            self.build(self.valid_ledger(), today="garbage")
        self.assertEqual(
            str(ctx.exception), "--today must be YYYY-MM-DD: 'garbage'"
        )


class BuildPayloadMessageDedupeTests(BuildTestCase):
    def test_repeated_adapter_selection_notes_appear_once(self) -> None:
        settings = self.write(self.user_config / "settings.json", "after\n")
        run_one = self.full_run(
            [self.target(after_digest=self.digest_of(settings))],
            self.verified_backup("RUN-2026-000"),
            run_id="RUN-2026-000",
        )
        run_two = self.full_run(
            [self.target(after_digest=self.digest_of(settings))],
            self.verified_backup("RUN-2026-001"),
            run_id="RUN-2026-001",
        )
        ledger = self.valid_ledger(records=[run_one, run_two])
        _, messages = self.build(ledger)
        expected_note = (
            f"selected adapter {self.adapter_path} for client 'testclient': "
            "named by --adapter"
        )
        # drift_report plus two rollback_preview calls would each surface
        # this exact note without dedupe -- it must survive only once.
        self.assertEqual(messages.count(expected_note), 1, messages)


STATIC_ISLAND_DEFAULT = (
    '{"payload_schema":1,"mode":"static","generated_at":null,'
    '"tool_version":null,"lang":null,"ledger":null,"computed":null}'
)


class InjectPayloadTests(unittest.TestCase):
    """`inject_payload` splices by locating two marker tags, never a regex."""

    def real_template(self) -> str:
        return TEMPLATE_PATH.read_text(encoding="utf-8")

    def test_the_static_default_is_gone_and_the_serialized_text_is_present(
        self,
    ) -> None:
        result = inject_payload(self.real_template(), '{"payload_schema":1,"mode":"built"}')
        self.assertNotIn(STATIC_ISLAND_DEFAULT, result)
        self.assertIn(
            'id="aio-payload">{"payload_schema":1,"mode":"built"}</script', result
        )

    def test_everything_outside_the_island_is_byte_identical(self) -> None:
        template = self.real_template()
        before, _, after = template.partition(STATIC_ISLAND_DEFAULT)
        result = inject_payload(template, '{"a":1}')
        self.assertTrue(result.startswith(before), "prefix changed")
        self.assertTrue(result.endswith(after), "suffix changed")
        self.assertEqual(len(result), len(before) + len('{"a":1}') + len(after))

    def test_the_island_marker_still_occurs_exactly_once_after_injection(
        self,
    ) -> None:
        result = inject_payload(self.real_template(), '{"a":1}')
        self.assertEqual(result.count(_ISLAND_MARKER), 1)

    def test_zero_islands_raises_ledger_error(self) -> None:
        template = "<html><body>no island here</body></html>"
        with self.assertRaises(LedgerError):
            inject_payload(template, "{}")

    def test_two_islands_raises_ledger_error(self) -> None:
        island = '<script type="application/json" id="aio-payload">{}</script>'
        template = f"<html>{island}{island}</html>"
        with self.assertRaises(LedgerError):
            inject_payload(template, "{}")

    def test_a_serialized_literal_less_than_is_refused(self) -> None:
        """M8: belt and braces, independent of `serialize_payload`.

        `serialize_payload` is the control that is supposed to keep a
        literal `<` out of `serialized` before it ever reaches this
        function (module docstring, design spec section 1.1), but
        `inject_payload` does not trust that guarantee blindly -- a
        malicious or malformed `serialized` string containing a raw `<` is
        refused here too, rather than spliced verbatim into the document.
        """
        malicious = '{"title":"</script><script>alert(1)</script>"}'
        with self.assertRaises(LedgerError) as ctx:
            inject_payload(self.real_template(), malicious)
        self.assertIn("literal '<'", str(ctx.exception))


class WriteDashboardTests(BuildTestCase):
    """The overwrite guard and the atomic write, in isolation from `build_command`."""

    def test_writes_the_given_html_verbatim(self) -> None:
        out = self.tmp / "dashboard.html"
        write_dashboard("<html>hi</html>", out, force=False)
        self.assertEqual(out.read_text(encoding="utf-8"), "<html>hi</html>")

    def test_refuses_to_overwrite_a_file_without_the_marker(self) -> None:
        out = self.tmp / "dashboard.html"
        out.write_text("not a dashboard", encoding="utf-8")
        with self.assertRaises(LedgerError) as ctx:
            write_dashboard("<html>new</html>", out, force=False)
        self.assertIn(repr(str(out)), str(ctx.exception))
        self.assertEqual(out.read_text(encoding="utf-8"), "not a dashboard")

    def test_overwrites_a_file_that_already_contains_the_marker(self) -> None:
        out = self.tmp / "dashboard.html"
        out.write_text(
            '<script type="application/json" id="aio-payload">'
            '{"payload_schema":1,"mode":"built"}</script>',
            encoding="utf-8",
        )
        write_dashboard("<html>new</html>", out, force=False)
        self.assertEqual(out.read_text(encoding="utf-8"), "<html>new</html>")

    def test_force_overrides_the_refusal(self) -> None:
        out = self.tmp / "dashboard.html"
        out.write_text("not a dashboard", encoding="utf-8")
        write_dashboard("<html>new</html>", out, force=True)
        self.assertEqual(out.read_text(encoding="utf-8"), "<html>new</html>")

    def test_a_failed_replace_leaves_the_prior_content_and_no_temp_file(
        self,
    ) -> None:
        out = self.tmp / "dashboard.html"
        out.write_text("prior content", encoding="utf-8")
        before = {entry.name for entry in self.tmp.iterdir()}
        with mock.patch("os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                write_dashboard("<html>new</html>", out, force=True)
        self.assertEqual(out.read_text(encoding="utf-8"), "prior content")
        after = {entry.name for entry in self.tmp.iterdir()}
        self.assertEqual(before, after, "a temp file was left behind")

    def test_never_creates_the_output_directory(self) -> None:
        out = self.tmp / "missing-dir" / "dashboard.html"
        with self.assertRaises(OSError):
            write_dashboard("<html>new</html>", out, force=False)
        self.assertFalse(out.parent.exists())

    def test_a_binary_existing_file_refuses_without_crashing(self) -> None:
        """I2: the overwrite guard reads bytes, not text.

        An existing `out` that happens to hold raw, non-UTF-8 bytes -- a
        stray binary file at that path, which is exactly the kind of file
        this guard exists to protect -- must be refused with `LedgerError`,
        not crash the guard itself with a `UnicodeDecodeError`.
        """
        out = self.tmp / "dashboard.html"
        raw = b"\xff\xfe\x00photo"
        out.write_bytes(raw)
        with self.assertRaises(LedgerError):
            write_dashboard("<html>new</html>", out, force=False)
        self.assertEqual(out.read_bytes(), raw)


class OutputGuardIdentityTests(BuildTestCase):
    """The guard recognizes a dashboard, not a string (finding 12, 2026-11-20).

    Before 0.15.0 any file holding the text `id="aio-payload"` passed as a
    generated dashboard, so a document that only describes the format was
    consumed by a typo'd `--out`.
    """

    DOCUMENT = (
        "# Notes on the dashboard\n\n"
        "The generated file's payload island is:\n\n"
        "```html\n"
        '<script type="application/json" id="aio-payload">{...}</script>\n'
        "```\n"
    ).encode("utf-8")

    def test_output_guard_preserves_unrelated_document(self) -> None:
        out = self.tmp / "notes.md"
        out.write_bytes(self.DOCUMENT)
        with self.assertRaises(LedgerError) as ctx:
            write_dashboard("<html>new</html>", out, force=False)
        self.assertIn("--force", str(ctx.exception))
        self.assertEqual(out.read_bytes(), self.DOCUMENT)

    def test_build_refuses_an_unrelated_document_as_out(self) -> None:
        ledger_path = self.tmp / "ledger.json"
        ledger_path.write_text(json.dumps(self.valid_ledger()), encoding="utf-8")
        out = self.tmp / "notes.md"
        out.write_bytes(self.DOCUMENT)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = build_command(ledger_path, out, None, False)
        self.assertEqual(code, 1)
        self.assertEqual(out.read_bytes(), self.DOCUMENT)
        self.assertIn("refusing to overwrite", err.getvalue())

    def test_output_guard_accepts_the_shipped_template_and_a_built_page(self) -> None:
        out = self.tmp / "dashboard.html"
        out.write_text(TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        write_dashboard("<html>first</html>", out, force=False)
        self.assertEqual(out.read_text(encoding="utf-8"), "<html>first</html>")

    def test_output_guard_refuses_an_island_without_a_payload(self) -> None:
        """Valid JSON is not enough: it must be a payload document."""
        out = self.tmp / "dashboard.html"
        text = '<script type="application/json" id="aio-payload">{"a":1}</script>'
        out.write_text(text, encoding="utf-8")
        with self.assertRaises(LedgerError):
            write_dashboard("<html>new</html>", out, force=False)
        self.assertEqual(out.read_text(encoding="utf-8"), text)

    def test_output_guard_refuses_a_reported_link(self) -> None:
        """A link at `--out` is refused before anything reads through it."""
        out = self.tmp / "dashboard.html"
        out.write_text(TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        before = out.read_bytes()
        with mock.patch("pathlib.Path.is_symlink", return_value=True):
            with self.assertRaises(LedgerError) as ctx:
                write_dashboard("<html>new</html>", out, force=False)
        self.assertIn("link", str(ctx.exception))
        self.assertEqual(out.read_bytes(), before)

    def _link_to_a_dashboard(self) -> tuple[Path, Path]:
        target = self.tmp / "elsewhere.html"
        target.write_text(TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        link = self.tmp / "dashboard.html"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symbolic links unavailable here: {exc}")
        return link, target

    def test_output_guard_refuses_a_real_link(self) -> None:
        link, target = self._link_to_a_dashboard()
        before = target.read_bytes()
        with self.assertRaises(LedgerError):
            write_dashboard("<html>new</html>", link, force=False)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), before)

    def test_force_replaces_the_link_and_never_its_target(self) -> None:
        link, target = self._link_to_a_dashboard()
        before = target.read_bytes()
        write_dashboard("<html>new</html>", link, force=True)
        self.assertFalse(link.is_symlink())
        self.assertEqual(link.read_text(encoding="utf-8"), "<html>new</html>")
        self.assertEqual(target.read_bytes(), before)


class BuildCommandTestCase(BuildTestCase):
    """`build_command` driven directly, the way `dashboard.py build` calls it."""

    def run_build(
        self, ledger_path: Path, out: Path | None, *, lang: str | None = None,
        force: bool = False,
    ) -> int:
        # `build_command` prints `wrote <path>` on success (dashboard.py's
        # module docstring lists `build` as the one command that writes a
        # file); `run_cli` below redirects that to a buffer for the same
        # reason -- a passing test suite should not spray "wrote ..." lines
        # into the runner's own stdout.
        with contextlib.redirect_stdout(io.StringIO()):
            return build_command(
                ledger_path,
                out,
                lang,
                force,
                adapter=self.adapter_path,
                project=self.tmp,
            )


class BuildCommandOutPathTests(BuildCommandTestCase):
    def test_default_out_is_dashboard_html_beside_the_ledger(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        code = self.run_build(ledger_path, None)
        self.assertEqual(code, 0)
        self.assertTrue((ledger_path.parent / "dashboard.html").exists())

    def test_the_out_flag_is_honored(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        custom_out = self.tmp / "custom-name.html"
        code = self.run_build(ledger_path, custom_out)
        self.assertEqual(code, 0)
        self.assertTrue(custom_out.exists())
        self.assertFalse((ledger_path.parent / "dashboard.html").exists())


class BuildCommandExitCodeTests(BuildCommandTestCase):
    def test_exit_0_on_a_valid_ledger_even_when_drift_finds_problems(self) -> None:
        # A run whose target anchor points at a file that was never written:
        # `drift_report`/target classification will not find it IN_PLACE, so
        # the payload's `computed` sections carry problems -- and the build
        # still succeeds, because rendering those problems is the point.
        run = self.full_run([self.target()], None)
        ledger = self.valid_ledger(records=[run])
        ledger_path = self.write_ledger(ledger)
        out = self.tmp / "dashboard.html"
        code = self.run_build(ledger_path, out)
        self.assertEqual(code, 0)
        self.assertTrue(out.exists())

    def test_exit_1_on_an_unreadable_ledger(self) -> None:
        missing = self.tmp / "does-not-exist.json"
        code = self.run_build(missing, None)
        self.assertEqual(code, 1)
        self.assertFalse((self.tmp / "dashboard.html").exists())

    def test_exit_1_on_overwrite_refusal_and_the_file_is_untouched(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        out.write_text("not a dashboard", encoding="utf-8")
        code = self.run_build(ledger_path, out)
        self.assertEqual(code, 1)
        self.assertEqual(out.read_text(encoding="utf-8"), "not a dashboard")

    def test_force_overrides_overwrite_refusal(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        out.write_text("not a dashboard", encoding="utf-8")
        code = self.run_build(ledger_path, out, force=True)
        self.assertEqual(code, 0)
        self.assertIn(_ISLAND_MARKER, out.read_text(encoding="utf-8"))

    def test_exit_2_on_a_schema_invalid_ledger_and_nothing_is_written(self) -> None:
        ledger = self.valid_ledger()
        del ledger["sequences"]
        ledger_path = self.write_ledger(ledger)
        out = self.tmp / "dashboard.html"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code = self.run_build(ledger_path, out)
        self.assertEqual(code, 2)
        self.assertFalse(out.exists())
        self.assertIn("sequences", buf.getvalue())

    def test_a_verify_only_finding_also_fails_the_build_at_two(self) -> None:
        # duplicate record ids are a `validate_collection` finding, not a
        # `validate_ledger` one -- this is the ADJUDICATED spec point: build
        # must run both checks, exactly as `verify` does for one document.
        material = self.full_material()
        duplicate = self.full_material()
        ledger = self.valid_ledger(records=[material, duplicate])
        ledger_path = self.write_ledger(ledger)
        out = self.tmp / "dashboard.html"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code = self.run_build(ledger_path, out)
        self.assertEqual(code, 2)
        self.assertFalse(out.exists())
        self.assertIn("Duplicate record id", buf.getvalue())


class BuildCommandTemplateGuardTests(BuildCommandTestCase):
    """I1: `build_command` guards the template read and the injection step.

    Before this fix, `TEMPLATE_PATH.read_text` and `inject_payload` in
    `build_command` ran outside any `try`/`except`: an unreadable template
    (moved, deleted, permissions) raised an uncaught `OSError`, and a
    template that lost its island raised an uncaught `LedgerError` -- both
    would have crashed the CLI with a traceback instead of a clean exit
    code and a stderr message.
    """

    def test_a_missing_template_path_exits_1_with_a_message_and_writes_nothing(
        self,
    ) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        missing_template = self.tmp / "no-such-template.html"
        buf = io.StringIO()
        with mock.patch("ledgerlib.build.TEMPLATE_PATH", missing_template):
            with contextlib.redirect_stderr(buf):
                code = self.run_build(ledger_path, out)
        self.assertEqual(code, 1)
        self.assertIn(repr(str(missing_template)), buf.getvalue())
        self.assertFalse(out.exists())

    def test_a_template_with_no_island_exits_1_with_the_count_guard_message(
        self,
    ) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        bad_template = self.write(
            self.tmp / "bad-template.html", "<html><body>no island</body></html>"
        )
        buf = io.StringIO()
        with mock.patch("ledgerlib.build.TEMPLATE_PATH", bad_template):
            with contextlib.redirect_stderr(buf):
                code = self.run_build(ledger_path, out)
        self.assertEqual(code, 1)
        self.assertIn("found 0", buf.getvalue())
        self.assertFalse(out.exists())


class BuildCommandLanguageTests(BuildCommandTestCase):
    def test_lang_xx_warns_on_stderr_and_builds_with_en(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code = self.run_build(ledger_path, out, lang="xx")
        self.assertEqual(code, 0)
        self.assertIn("xx", buf.getvalue())
        self.assertIn("en", buf.getvalue())
        payload = json.loads(extract_island(out.read_text(encoding="utf-8")))
        self.assertEqual(payload["lang"], "en")

    def test_lang_pt_br_lands_in_the_payload(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        code = self.run_build(ledger_path, out, lang="pt-BR")
        self.assertEqual(code, 0)
        payload = json.loads(extract_island(out.read_text(encoding="utf-8")))
        self.assertEqual(payload["lang"], "pt-BR")


class BuildCommandSecurityTests(BuildCommandTestCase):
    """Design spec section 1.1's stored-XSS control, exercised end to end."""

    def test_a_script_payload_in_ledger_content_contributes_no_angle_bracket(
        self,
    ) -> None:
        template_script_opens = TEMPLATE_PATH.read_text(encoding="utf-8").count(
            "<script"
        )
        template_script_closes = TEMPLATE_PATH.read_text(encoding="utf-8").count(
            "</script"
        )
        material = self.full_material(title="</script><script>alert(1)</script>")
        entry = self.backlog_entry(
            reason="flagged for review <!-- suspicious --> pending"
        )
        ledger = self.valid_ledger(records=[material])
        ledger["backlog"] = [entry]
        ledger_path = self.write_ledger(ledger)
        out = self.tmp / "dashboard.html"
        code = self.run_build(ledger_path, out)
        self.assertEqual(code, 0)

        html = out.read_text(encoding="utf-8")
        self.assertEqual(html.count("<script"), template_script_opens)
        self.assertEqual(html.count("</script"), template_script_closes)

        island = extract_island(html)
        self.assertNotIn("<", island)
        # And the escaping is lossless: the dangerous text survives intact
        # once JSON-parsed.
        payload = json.loads(island)
        material_out = next(
            record
            for record in payload["ledger"]["records"]
            if record["id"] == "MAT-2026-000"
        )
        self.assertEqual(
            material_out["title"], "</script><script>alert(1)</script>"
        )
        self.assertEqual(
            payload["ledger"]["backlog"][0]["reason"],
            "flagged for review <!-- suspicious --> pending",
        )


class BuildCommandRoundTripTests(BuildCommandTestCase):
    def test_the_generated_islands_ledger_matches_the_input_ledger(self) -> None:
        ledger = self.valid_ledger()
        ledger_path = self.write_ledger(ledger)
        out = self.tmp / "dashboard.html"
        code = self.run_build(ledger_path, out)
        self.assertEqual(code, 0)
        payload = json.loads(extract_island(out.read_text(encoding="utf-8")))
        self.assertEqual(payload["ledger"], ledger)


class BuildCommandWriteIsolationTests(BuildCommandTestCase):
    def test_build_writes_exactly_one_path(self) -> None:
        workspace = self.tmp / "workspace"
        workspace.mkdir()
        ledger = self.valid_ledger()
        ledger_path = workspace / "ledger.json"
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        out = workspace / "dashboard.html"

        before = {p.relative_to(workspace) for p in workspace.rglob("*")}
        code = self.run_build(ledger_path, out)
        after = {p.relative_to(workspace) for p in workspace.rglob("*")}

        self.assertEqual(code, 0)
        self.assertEqual(after - before, {out.relative_to(workspace)})
        self.assertEqual(ledger_path.read_text(encoding="utf-8"), json.dumps(ledger))


class BuildCliTestCase(BuildCommandTestCase):
    """`dashboard.main` driven the way a shell would, per `DriftCliTestCase`."""

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = dashboard.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def build_arguments(self, ledger_path: Path, out: Path) -> list[str]:
        return [
            "build",
            str(ledger_path),
            "--out",
            str(out),
            "--adapter",
            str(self.adapter_path),
            "--project",
            str(self.tmp),
        ]


class BuildCliTests(BuildCliTestCase):
    def test_the_subcommand_is_wired_into_main(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        code, _, _ = self.run_cli(*self.build_arguments(ledger_path, out))
        self.assertEqual(code, 0)
        self.assertTrue(out.exists())

    def test_the_subcommand_reaches_build_payload_through_main(self) -> None:
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        with mock.patch(
            "ledgerlib.build.build_payload", wraps=build_payload
        ) as spy:
            code, _, _ = self.run_cli(*self.build_arguments(ledger_path, out))
        self.assertEqual(code, 0)
        spy.assert_called_once()

    def test_user_config_flag_reaches_build_payload(self) -> None:
        """M10: `--user-config` is wired all the way from argv to the call.

        `build_arguments` never passes `--user-config`, so a spy that only
        `wraps` `build_payload` (as the test above does) would not notice
        this flag being dropped anywhere along the way. This test adds the
        flag explicitly and inspects the actual keyword arguments
        `build_payload` was called with.
        """
        ledger_path = self.write_ledger(self.valid_ledger())
        out = self.tmp / "dashboard.html"
        with mock.patch(
            "ledgerlib.build.build_payload", wraps=build_payload
        ) as spy:
            code, _, _ = self.run_cli(
                "build",
                str(ledger_path),
                "--out",
                str(out),
                "--adapter",
                str(self.adapter_path),
                "--project",
                str(self.tmp),
                "--user-config",
                str(self.user_config),
            )
        self.assertEqual(code, 0)
        spy.assert_called_once()
        self.assertEqual(spy.call_args.kwargs["user_config"], self.user_config)


class BuildPayloadResolvedPathTests(BuildTestCase):
    """0.5.0: the payload's computed rows carry the paths the shell opens.

    No new plumbing is under test -- `build_payload` embeds `drift_report`'s
    and `rollback_preview`'s reports verbatim, and those reports now carry
    `path` -- but the promise the shell relies on is a property of the
    payload, so it is pinned here where the payload is built.
    """

    def test_drift_and_preview_rows_reach_the_payload_with_paths(self) -> None:
        settings = self.write(self.user_config / "settings.json", "after\n")
        run = self.full_run(
            # A file the run created: any verified backup proves its recovery
            # (0.13.0), so the row lands in `will_be_restored`.
            [self.target(before_digest=None, after_digest=self.digest_of(settings))],
            self.verified_backup(),
        )
        payload, _ = self.build(self.valid_ledger(records=[run]))
        drift_row = payload["computed"]["drift"]["runs"][0]["targets"][0]
        self.assertEqual(drift_row["path"], str(settings.resolve()))
        preview = payload["computed"]["previews"]["RUN-2026-000"]
        self.assertEqual(
            preview["will_be_restored"][0]["path"], str(settings.resolve())
        )
        self.assertEqual(
            preview["backup"]["path"],
            str(self.user_config / "backups" / "RUN-2026-000.bak"),
        )


if __name__ == "__main__":
    unittest.main()


import subprocess  # noqa: E402

from ledgerlib import scan as scan_module  # noqa: E402


def _strict_json(text: str) -> object:
    """`json.loads` refusing what `JSON.parse` refuses: NaN and infinities."""

    def refuse(constant: str) -> object:
        raise ValueError(f"{constant} is not JSON")

    return json.loads(text, parse_constant=refuse)


class NonFiniteNumberTests(unittest.TestCase):
    """A NaN or an infinity in a configuration file reaches the HTML as JSON.

    Finding 15 of the 2026-11-20 review: `threshold = nan` in a TOML file was
    copied as a float, `json.dumps` wrote the bare token `NaN`, and the
    dashboard's `JSON.parse` refused the data island although `build` exited
    `0`. Captured through `update ledger` and rendered through `build`, both
    via `dashboard.main`; the island is read by a strict parser and, where
    Node is installed, by `JSON.parse` itself.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.user_config = self.tmp / "user_config"
        self.user_config.mkdir()

    def adapter(self, fmt: str) -> Path:
        name = "config.toml" if fmt == "toml" else "config.json"
        path = self.tmp / f"adapter-{fmt}.json"
        path.write_text(
            json.dumps(
                {
                    "adapter_version": 1,
                    "client": "testclient",
                    "expires_on": "2099-01-01",
                    "anchors": {"$USER_CONFIG": [str(self.user_config)]},
                    "probes": [
                        {
                            "kind": "mcp-server",
                            "scope": "user",
                            "path": f"$USER_CONFIG/{name}",
                            "parse": fmt,
                            "pointer": "/mcp_servers",
                        }
                    ],
                    "sensitive_key_patterns": ["*token*"],
                }
            ),
            encoding="utf-8",
        )
        return path

    def ledger(self) -> Path:
        path = self.tmp / "ledger.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "ledger_id": "l-nonfinite",
                    "scope": "global",
                    "language": "en",
                    "client": "testclient",
                    "adapter_version": 1,
                    "created": "2026-11-23",
                    "updated": "2026-11-23",
                    "id_authority": True,
                    "sequences": {"MAT": 0, "PROP": 0, "RUN": 0, "ADR": 0, "BASE": 0},
                    "known_projects": [],
                    "records": [],
                    "baselines": [],
                    "backlog": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def main(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = dashboard.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def capture_and_build(self, fmt: str) -> tuple[Path, str]:
        ledger = self.ledger()
        code, _out, err = self.main(
            "update", str(ledger), "ledger", "--adapter", str(self.adapter(fmt)),
            "--project", str(self.tmp),
        )
        self.assertEqual(code, 0, err)
        code, _out, err = self.build(ledger, fmt)
        self.assertEqual(code, 0, err)
        return ledger, extract_island(self.out.read_text(encoding="utf-8"))

    @property
    def out(self) -> Path:
        return self.tmp / "dashboard.html"

    def build(self, ledger: Path, fmt: str) -> tuple[int, str, str]:
        # The adapter and project are named so the build's drift pass reads
        # the temporary tree and never this machine's configuration.
        return self.main(
            "build", str(ledger), "--out", str(self.out), "--force",
            "--adapter", str(self.adapter(fmt)), "--project", str(self.tmp),
        )

    def server_values(self, ledger: Path) -> dict:
        try:
            document = _strict_json(ledger.read_text(encoding="utf-8"))
        except ValueError as exc:
            self.fail(f"the ledger is not strict JSON: {exc}")
        return {
            item["name"]: item["attributes"]["value"]
            for item in document["baselines"][0]["items"]
        }

    def assert_browser_reads(self, island: str) -> None:
        try:
            _strict_json(island)
        except ValueError as exc:
            self.fail(f"the data island is not strict JSON: {exc}")
        node = shutil.which("node")
        if node is None:
            return
        script = (
            "let s='';process.stdin.on('data',d=>s+=d);"
            "process.stdin.on('end',()=>{JSON.parse(s);console.log('ok')});"
        )
        result = subprocess.run(
            [node, "-e", script], input=island.encode("utf-8"),
            capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stdout.decode().strip(), "ok")

    @unittest.skipIf(
        scan_module.tomllib is None, "tomllib is absent below Python 3.11"
    )
    def test_nonfinite_toml_produces_browser_readable_json(self) -> None:
        (self.user_config / "config.toml").write_text(
            "[mcp_servers.alpha]\nthreshold = nan\nceiling = inf\nfloor = -inf\n"
            "[mcp_servers.beta]\nthreshold = 0.5\n",
            encoding="utf-8",
        )
        ledger, island = self.capture_and_build("toml")
        self.assert_browser_reads(island)
        values = self.server_values(ledger)
        self.assertEqual(
            values["alpha"], {"threshold": "nan", "ceiling": "inf", "floor": "-inf"}
        )
        # A finite number is the control: it stays a number.
        self.assertEqual(values["beta"], {"threshold": 0.5})

    def test_nonfinite_json_produces_browser_readable_json(self) -> None:
        (self.user_config / "config.json").write_text(
            '{"mcp_servers": {"alpha": {"threshold": NaN, "ceiling": Infinity,'
            ' "floor": -Infinity}, "beta": {"threshold": 0.5}}}',
            encoding="utf-8",
        )
        ledger, island = self.capture_and_build("json")
        self.assert_browser_reads(island)
        values = self.server_values(ledger)
        self.assertEqual(
            values["alpha"], {"threshold": "nan", "ceiling": "inf", "floor": "-inf"}
        )
        self.assertEqual(values["beta"], {"threshold": 0.5})

    def test_two_captures_of_one_nonfinite_file_are_identical(self) -> None:
        (self.user_config / "config.json").write_text(
            '{"mcp_servers": {"alpha": {"threshold": NaN}}}', encoding="utf-8"
        )
        first, _ = self.capture_and_build("json")
        values = self.server_values(first)
        second, _ = self.capture_and_build("json")
        self.assertEqual(values, self.server_values(second))

    def test_an_older_ledger_holding_nan_still_builds_readable_json(self) -> None:
        (self.user_config / "config.json").write_text(
            '{"mcp_servers": {"alpha": {"threshold": 1.0}}}', encoding="utf-8"
        )
        ledger, _ = self.capture_and_build("json")
        # A ledger written before 0.14.0 held the bare float.
        text = ledger.read_text(encoding="utf-8").replace('"threshold": 1.0', '"threshold": NaN')
        self.assertIn("NaN", text)
        ledger.write_text(text, encoding="utf-8")
        before = ledger.read_bytes()
        code, _out, err = self.build(ledger, "json")
        self.assertEqual(code, 0, err)
        self.assertIn("non-finite", err)
        self.assertEqual(ledger.read_bytes(), before)
        self.assert_browser_reads(extract_island(self.out.read_text(encoding="utf-8")))
