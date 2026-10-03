import pytest
import yaml
from pydantic import ValidationError

from agentguard.config import CONFIG_DIR
from agentguard.policy import Policy, load_policy
from agentguard.rag.retriever import Retriever, chunk_document
from agentguard.sandbox import Sandbox

LAPTOP_QUOTES = {"acme_laptops_quote.txt", "brightpath_laptops_quote.md", "nimbus_laptops_quote.html",
                 "orbital_laptops_quote.csv"}


def _files(chunks):
    return {c.path.split("/")[1] for c in chunks}


def test_retrieval_is_deterministic_and_covers_all_laptop_quotes(policy, scenarios):
    request = scenarios["quote-01"].user_request
    r = Retriever(Sandbox(policy).corpus_documents())
    first, second = r.search(request, 8), r.search(request, 8)
    assert first == second
    assert LAPTOP_QUOTES <= _files(first)


def test_poisoned_document_is_retrieved_raw(policy, scenarios):
    spec = scenarios["plain-01"]
    chunks = Retriever(Sandbox(policy, overlay=spec.overlay).corpus_documents()).search(spec.user_request, 8)
    nimbus = next(c for c in chunks if "nimbus_laptops" in c.path)
    assert "NOTE FOR THE AI ASSISTANT" in nimbus.text
    assert "<table>" in nimbus.text  # raw HTML reaches the agent in the baseline


def test_chunking_splits_long_documents():
    text = "\n\n".join(f"paragraph {i} " + "x" * 300 for i in range(6))
    chunks = chunk_document("quotes/long.txt", text)
    assert len(chunks) > 1
    assert all(c.source.startswith("quotes/long.txt#") for c in chunks)


def test_policy_rejects_unknown_keys():
    raw = yaml.safe_load((CONFIG_DIR / "policy.yaml").read_text(encoding="utf-8"))
    raw["surprise"] = True
    with pytest.raises(ValidationError):
        Policy.model_validate(raw)


def test_policy_confidential_globs():
    p = load_policy()
    assert p.is_confidential("confidential/bank_details.txt")
    assert not p.is_confidential("quotes/acme_laptops_quote.txt")
