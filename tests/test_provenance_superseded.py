"""Provenance signature: which superseded postgresql.conf lines may be ignored.

The rows mirror a live capture (PostgreSQL 17, postgres:17-bookworm): the image
writes listen_addresses = '*' at postgresql.conf line 60, the source then runs
ALTER SYSTEM SET listen_addresses = '*', and reconstruction appends the source's
postgresql.conf line at the end of the sandbox's postgresql.conf (line 853).

Only an earlier, error-free, unapplied line repeated with the SAME value later in
the SAME file is ignored. Anything that changes the effective value, the winning
file or the value a file falls back to on ALTER SYSTEM RESET must still differ.
"""
import pytest

from services.sandbox_poc.provenance import FILES, _shadowed_duplicate, reconstruction_plan, signature
from services.sandbox_poc.shared import ContractError

CONF, AUTO = FILES
NAME = "listen_addresses"


def line(setting, sourcefile, sourceline, applied, error=None, name=NAME):
    return {"name": name, "setting": setting, "sourcefile": sourcefile,
            "sourceline": sourceline, "applied": applied, "error": error}


def snap(file_settings, setting="*", sourcefile=AUTO):
    row = {"name": NAME, "setting": setting, "source": "configuration file", "sourcefile": sourcefile,
           "context": "postmaster", "pending_restart": False}
    return {"baseline": {"settings": [row], "file_settings": file_settings, "gaps": []}}


def sig(snapshot):
    return signature(snapshot, [NAME])


# Source: ALTER SYSTEM on top of the image's postgresql.conf line.
SOURCE = snap([line("*", AUTO, 3, True), line("*", CONF, 60, False)])


def test_auto_conf_source_matches_sandbox_with_image_and_reconstructed_lines():
    sandbox = snap([line("*", AUTO, 3, True), line("*", CONF, 60, False), line("*", CONF, 853, False)])
    assert sig(sandbox) == sig(SOURCE)
    # Exactly one copy of the superseded postgresql.conf line is kept, so the
    # fallback value for ALTER SYSTEM RESET is still part of the signature.
    assert [r["sourcefile"] for r in sig(sandbox)["file_settings"]] == [AUTO, CONF]


def test_existing_applied_duplicate_rule_is_kept():
    source = snap([line("*", CONF, 60, True)], sourcefile=CONF)
    sandbox = snap([line("*", CONF, 60, False), line("*", CONF, 853, True)], sourcefile=CONF)
    assert sig(sandbox) == sig(source)


def test_superseded_line_with_different_value_changes_reset_fallback():
    # Source falls back to 'localhost' on ALTER SYSTEM RESET; this sandbox to '*'.
    source = snap([line("*", AUTO, 3, True), line("localhost", CONF, 853, False)])
    sandbox = snap([line("*", AUTO, 3, True), line("*", CONF, 60, False)])
    assert sig(sandbox) != sig(source)


def test_earlier_line_with_different_value_still_counts():
    # Conservative: a different-valued earlier line is never treated as an artefact.
    source = snap([line("*", AUTO, 3, True), line("localhost", CONF, 60, False)])
    sandbox = snap([line("*", AUTO, 3, True), line("0.0.0.0", CONF, 60, False),
                    line("localhost", CONF, 853, False)])
    assert sig(sandbox) != sig(source)


def test_line_superseded_only_by_another_file_is_never_dropped():
    # Source has no postgresql.conf line: RESET falls back to the built-in default.
    # A sandbox whose image line would become effective on RESET must differ.
    source = snap([line("*", AUTO, 3, True)])
    sandbox = snap([line("*", AUTO, 3, True), line("*", CONF, 60, False)])
    assert sig(sandbox) != sig(source)
    # And the reverse: losing the source's superseded postgresql.conf line differs too.
    assert sig(source) != sig(SOURCE)


def test_winning_file_change_differs():
    moved = snap([line("*", CONF, 60, True)], sourcefile=CONF)
    assert sig(moved) != sig(SOURCE)


@pytest.mark.parametrize("first,second", [
    ({"error": "setting could not be applied"}, {}),   # an error line is never dropped
    ({}, {"error": "setting could not be applied"}),   # an error line never shadows
    ({"sourceline": None}, {}),                         # order not provable
    ({}, {"sourceline": None}),
])
def test_unprovable_or_invalid_duplicates_still_count(first, second):
    rows = [{**line("*", CONF, 60, False), **first}, {**line("*", CONF, 853, False), **second}]
    assert sig(snap([line("*", AUTO, 3, True), *rows])) != sig(SOURCE)


def test_only_the_earlier_copy_is_dropped():
    sandbox = snap([line("*", AUTO, 3, True), line("*", CONF, 900, False), line("*", CONF, 853, False)])
    kept = [r for r in sandbox["baseline"]["file_settings"]
            if r["sourcefile"] == CONF and r["sourceline"] == 900]
    assert not _shadowed_duplicate(kept[0], sandbox["baseline"]["file_settings"])
    assert sig(sandbox) == sig(SOURCE)


def test_source_duplicates_are_still_rejected_before_signature():
    source = snap([line("*", AUTO, 3, True), line("*", CONF, 60, False), line("*", CONF, 853, False)])
    with pytest.raises(ContractError, match="duplicate"):
        reconstruction_plan(source, [{"check": {"setting_name": NAME}}])
