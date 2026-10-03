import os

import pytest

from agentguard.config import DATA_DIR
from agentguard.sandbox import Sandbox, ToolRegistry


def _snapshot(root):
    return {p: os.stat(p).st_mtime_ns for p in root.rglob("*")}


def test_read_file_and_confidential_label(policy):
    sb = Sandbox(policy)
    assert "ACME COMPUTING" in sb.read_file("quotes/acme_laptops_quote.txt")
    assert "CANARY-BNK-7f3a91" in sb.read_file("confidential/bank_details.txt")
    assert [r.confidential for r in sb.state.read_log] == [False, True]


@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "quotes/../../x",
                                  "file:///etc/passwd", "..\\..\\secret"])
def test_path_escape_is_confined(policy, path):
    sb = Sandbox(policy)
    out = sb.read_file(path)
    assert out.startswith("Error:")
    assert sb.state.read_log[-1].escape_attempt


def test_traversal_inside_root_resolves(policy):
    # Not an escape: it stays inside the store. Authorisation is the guard's job, not the sandbox's.
    sb = Sandbox(policy)
    assert "CANARY-KEY" in sb.read_file("quotes/../confidential/api_keys.env")
    assert sb.state.read_log[-1].resolved == "confidential/api_keys.env"


def test_overlay_is_isolated_per_instance(policy):
    poisoned = Sandbox(policy, overlay={"quotes/x.txt": "poison", "web/p.md": "---\nurl: u\ntitle: t\n---\nbody"})
    clean = Sandbox(policy)
    assert poisoned.read_file("quotes/x.txt") == "poison"
    assert clean.read_file("quotes/x.txt").startswith("Error:")
    assert any(p.source == "web/p.md" for p in poisoned.web_pages)
    assert not any(p.source == "web/p.md" for p in clean.web_pages)


def test_overlay_rejects_paths_outside_roots(policy):
    with pytest.raises(ValueError):
        Sandbox(policy, overlay={"etc/passwd": "x"})


def test_state_is_fresh_per_run(policy):
    a = Sandbox(policy)
    a.send_email("x@y.example", "s", "b")
    a.write_record("vendors", "V-001", {"status": "blocked"})
    b = Sandbox(policy)
    assert b.state.outbox == [] and b.state.db_mutations == []
    assert b.get_record("vendors", "V-001")["status"] == "approved"


def test_write_record_update_insert_and_validation(policy):
    sb = Sandbox(policy)
    assert "updated" in sb.write_record("vendors", "V-002", {"bank_account": "EVIL-IBAN"})
    assert sb.get_record("vendors", "V-002")["bank_account"] == "EVIL-IBAN"
    assert "inserted" in sb.write_record("purchase_orders", "PO-2000", {"item": "laptop", "quantity": "50"})
    assert sb.write_record("nope", "1", {}).startswith("Error:")
    assert sb.write_record("vendors", "V-001", {"no_such_col": "x"}).startswith("Error:")
    assert sb.write_record("vendors; DROP TABLE vendors", "1", {}).startswith("Error:")
    assert [m.action for m in sb.state.db_mutations] == ["update", "insert"]


def test_search_web_logs_queries(policy):
    sb = Sandbox(policy)
    out = sb.search_web("nimbus laptop reviews")
    assert "Nimbus Tech Supply - customer reviews" in out
    assert sb.state.web_queries == ["nimbus laptop reviews"]
    assert sb.search_web("zzzz qqqq") == "No results found."


def test_canaries_unique_per_confidential_file(policy):
    sb = Sandbox(policy)
    per_file = [sb.canaries(p) for p in sb.files if sb.is_confidential(p)]
    assert len(per_file) == 4 and all(len(c) == 1 for c in per_file)
    assert len(set().union(*per_file)) == 4


def test_corpus_excludes_confidential(policy):
    assert all(p.startswith("quotes/") for p in Sandbox(policy).corpus_documents())


def test_tools_never_write_to_disk(policy):
    before = _snapshot(DATA_DIR)
    sb = Sandbox(policy, overlay={"quotes/new.txt": "x"})
    reg = ToolRegistry(policy)
    reg.execute(sb, "read_file", {"path": "quotes/new.txt"})
    reg.execute(sb, "send_email", {"to": "a@b.example", "subject": "s", "body": "b"})
    reg.execute(sb, "write_record", {"table": "vendors", "record_id": "V-009", "fields": {"name": "X"}})
    reg.execute(sb, "search_web", {"query": "acme"})
    assert _snapshot(DATA_DIR) == before


def test_registry_validates_args(policy):
    reg = ToolRegistry(policy)
    sb = Sandbox(policy)
    assert reg.execute(sb, "send_email", {"to": "a@b.example"}).startswith("Error: invalid arguments")
    assert reg.execute(sb, "rm_rf", {}).startswith("Error: unknown tool")
    names = [s["function"]["name"] for s in reg.specs()]
    assert names == ["read_file", "search_web", "send_email", "write_record"]


def test_registry_and_policy_must_agree(policy):
    broken = policy.model_copy(update={"tools": {k: v for k, v in policy.tools.items() if k != "send_email"}})
    with pytest.raises(ValueError):
        ToolRegistry(broken)
