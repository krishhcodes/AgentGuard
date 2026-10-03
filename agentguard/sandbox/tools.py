"""Tool registry: argument schemas (bound to the LLM) and execution against a Sandbox.

`ToolRegistry.execute` is the only code path that performs tool side effects; it is
called only from the graph's `execute_tools` node.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentguard.policy import Policy
from agentguard.sandbox.env import Sandbox


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReadFileArgs(_Args):
    path: str = Field(description="Path of the file, e.g. quotes/acme_laptops_quote.txt")


class SearchWebArgs(_Args):
    query: str = Field(description="Search query")


class SendEmailArgs(_Args):
    to: str = Field(description="Recipient email address")
    subject: str = Field(description="Email subject")
    body: str = Field(description="Email body")


class WriteRecordArgs(_Args):
    table: str = Field(description="Table name: vendors or purchase_orders")
    record_id: str = Field(description="Record id, e.g. V-001 or PO-1001")
    fields: dict[str, str] = Field(description="Column values to set")


TOOL_ARG_MODELS: dict[str, type[_Args]] = {
    "read_file": ReadFileArgs,
    "search_web": SearchWebArgs,
    "send_email": SendEmailArgs,
    "write_record": WriteRecordArgs,
}


class ToolRegistry:
    def __init__(self, policy: Policy):
        missing = set(TOOL_ARG_MODELS) ^ set(policy.tools)
        if missing:
            raise ValueError(f"policy.yaml and the tool registry disagree on tools: {sorted(missing)}")
        self.policy = policy

    def specs(self) -> list[dict[str, Any]]:
        """OpenAI-style function specs for `bind_tools`."""
        specs = []
        for name, model in TOOL_ARG_MODELS.items():
            schema = model.model_json_schema()
            schema.pop("title", None)
            specs.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": self.policy.tools[name].description,
                        "parameters": schema,
                    },
                }
            )
        return specs

    def execute(self, sandbox: Sandbox, name: str, args: dict[str, Any]) -> str:
        """Run a tool. Errors come back as strings (tool output is untrusted data either way)."""
        model = TOOL_ARG_MODELS.get(name)
        if model is None:
            return f"Error: unknown tool {name!r}."
        try:
            parsed = model.model_validate(args)
        except ValidationError as e:
            return f"Error: invalid arguments for {name}: {e.errors(include_url=False)}"
        return getattr(sandbox, name)(**parsed.model_dump())
