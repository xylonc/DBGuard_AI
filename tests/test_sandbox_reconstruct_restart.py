"""Reconstruction restarts the sandbox once to re-source an unchanged restart setting.

A postmaster setting is re-sourced only at server start. When the source holds
logging_collector='off' in postgresql.auto.conf (source 'configuration file') the
sandbox writes the same line, reload sees no pending restart and pg_settings keeps
source 'default'. reconstruct() restarts only for RESTART_SETTINGS, and only when the
live source/sourcefile still differs from the plan.
"""
from __future__ import annotations

import pytest

from services.sandbox_poc.provenance import (
    FILES, RESTART_SETTINGS, _live_sources, reconstruct, restart_candidates, restart_needed)
from services.sandbox_poc.runtime import DisposablePostgres
from services.sandbox_poc.shared import ContractError

AUTO = FILES[1]


def _plan(rows: dict[str, tuple[str, str, str | None]]) -> dict:
    """rows: name -> (setting, source, sourcefile). A sourcefile means a written file line."""
    return {
        "names": list(rows),
        "entries": [{"name": n, "setting": v, "sourcefile": f}
                    for n, (v, _, f) in rows.items() if f is not None],
        "expected": {n: v for n, (v, _, _) in rows.items()},
        "signature": {"settings": {n: {"setting": v, "source": s, "sourcefile": f,
                                       "context": "postmaster", "pending_restart": False}
                                   for n, (v, s, f) in rows.items()},
                      "file_settings": []},
    }


class RecordingRuntime:
    def __init__(self, live: dict, after_restart: dict | None = None):
        self.live = live
        self.after_restart = after_restart if after_restart is not None else live
        self.calls: list = []

    def write_config(self, filename, content):
        self.calls.append(("write", filename))

    def activate(self, expected):
        self.calls.append(("activate", dict(expected)))

    def restart(self):
        self.calls.append(("restart",))
        self.live = self.after_restart

    def setting_sources(self, names):
        self.calls.append(("sources", list(names)))
        return {n: self.live[n] for n in names if n in self.live}

    def sql(self, script):  # reconstruct never sends SQL of its own
        raise AssertionError("unexpected SQL from reconstruct")


def test_restart_allowlist_is_the_reviewed_pair():
    assert RESTART_SETTINGS == frozenset({"logging_collector", "listen_addresses"})


def test_unchanged_auto_conf_postmaster_value_needs_restart():
    plan = _plan({"logging_collector": ("off", "configuration file", AUTO)})
    live = {"logging_collector": {"source": "default", "sourcefile": None}}
    assert restart_candidates(plan) == ["logging_collector"]
    assert restart_needed(plan, live) == ["logging_collector"]


def test_matching_provenance_needs_no_restart():
    plan = _plan({"logging_collector": ("off", "configuration file", AUTO)})
    live = {"logging_collector": {"source": "configuration file", "sourcefile": AUTO}}
    assert restart_needed(plan, live) == []


def test_sourcefile_mismatch_alone_needs_restart():
    plan = _plan({"listen_addresses": ("localhost", "configuration file", AUTO)})
    live = {"listen_addresses": {"source": "configuration file", "sourcefile": FILES[0]}}
    assert restart_needed(plan, live) == ["listen_addresses"]


def test_default_source_writes_no_line_so_no_candidate():
    plan = _plan({"logging_collector": ("off", "default", None)})
    assert restart_candidates(plan) == []
    assert restart_needed(plan, {"logging_collector": {"source": "default", "sourcefile": None}}) == []


def test_settings_outside_the_restart_allowlist_never_qualify():
    plan = _plan({"log_connections": ("off", "configuration file", AUTO),
                  "shared_buffers": ("16384", "configuration file", AUTO)})
    live = {n: {"source": "default", "sourcefile": None} for n in plan["names"]}
    assert restart_candidates(plan) == []
    assert restart_needed(plan, live) == []


def test_reconstruct_restarts_once_then_reactivates():
    plan = _plan({"logging_collector": ("off", "configuration file", AUTO),
                  "log_connections": ("off", "configuration file", AUTO)})
    fixed = {"logging_collector": {"source": "configuration file", "sourcefile": AUTO}}
    runtime = RecordingRuntime({"logging_collector": {"source": "default", "sourcefile": None}},
                               after_restart=fixed)
    reconstruct(runtime, plan)
    kinds = [c[0] for c in runtime.calls]
    assert kinds == ["write", "write", "activate", "sources", "restart", "activate"]
    assert kinds.count("restart") == 1
    # The provenance query names only the allowlisted candidate, never other settings.
    assert ("sources", ["logging_collector"]) in runtime.calls
    assert runtime.calls[-1] == ("activate", plan["expected"])


def test_reconstruct_restarts_at_most_once_even_if_still_mismatched():
    """A remaining mismatch is left to the caller's signature check, which fails closed."""
    plan = _plan({"logging_collector": ("off", "configuration file", AUTO)})
    stale = {"logging_collector": {"source": "default", "sourcefile": None}}
    runtime = RecordingRuntime(stale, after_restart=stale)
    reconstruct(runtime, plan)
    assert [c[0] for c in runtime.calls].count("restart") == 1


def test_reconstruct_skips_restart_when_provenance_already_matches():
    plan = _plan({"logging_collector": ("on", "configuration file", AUTO)})
    runtime = RecordingRuntime({"logging_collector": {"source": "configuration file", "sourcefile": AUTO}})
    reconstruct(runtime, plan)
    assert "restart" not in [c[0] for c in runtime.calls]


def test_reconstruct_issues_no_query_without_restart_candidates():
    """Non-restart and default-sourced plans keep the original write/activate path."""
    plan = _plan({"log_connections": ("off", "configuration file", AUTO),
                  "logging_collector": ("off", "default", None)})
    runtime = RecordingRuntime({})
    reconstruct(runtime, plan)
    assert [c[0] for c in runtime.calls] == ["write", "write", "activate"]


def test_live_source_query_rejects_names_outside_the_allowlist():
    runtime = RecordingRuntime({})
    with pytest.raises(ContractError):
        _live_sources(runtime, ["shared_buffers"])
    with pytest.raises(ContractError):
        _live_sources(runtime, ["logging_collector'); DROP TABLE x; --"])
    assert runtime.calls == []


def test_runtime_source_query_rejects_unsafe_names_before_any_docker_call():
    runtime = DisposablePostgres()  # never started: any docker access would also fail
    with pytest.raises(ContractError):
        runtime.setting_sources(["logging_collector') OR true; --"])


def test_runtime_restart_refuses_an_unowned_container():
    with pytest.raises(RuntimeError, match="not owned"):
        DisposablePostgres().restart()
