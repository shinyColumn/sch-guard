import json
import os
import subprocess
import tempfile

DEFAULT_MODEL = "claude-sonnet-5"
EFFORT = "low"
NEUTRAL_CWD = os.path.join(tempfile.gettempdir(), "sch_guard_cwd")
os.makedirs(NEUTRAL_CWD, exist_ok=True)


def call_llm(system_prompt: str, user_text: str, schema: dict, model: str = DEFAULT_MODEL,
             backend: str = "auto") -> dict:
    if backend == "auto":
        backend = "api" if os.environ.get("ANTHROPIC_API_KEY") else "cli"
    if backend == "api":
        return _call_api(system_prompt, user_text, schema, model)
    return _call_cli(system_prompt, user_text, schema, model)


def _call_api(system_prompt: str, user_text: str, schema: dict, model: str) -> dict:
    import anthropic

    client = anthropic.Anthropic()
    tool = {"name": "submit_verdict", "description": "Submit the structured verdict.", "input_schema": schema}
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system_prompt,
        tools=[tool],
        tool_choice={"type": "tool", "name": "submit_verdict"},
        messages=[{"role": "user", "content": user_text}],
    )
    tool_use = next(b for b in resp.content if b.type == "tool_use")
    return {"parsed": tool_use.input, "cost_usd": None}


def _call_cli(system_prompt: str, user_text: str, schema: dict, model: str) -> dict:
    cmd = [
        "claude", "-p", user_text,
        "--model", model,
        "--effort", EFFORT,
        "--tools", "none",
        "--output-format", "json",
        "--system-prompt", system_prompt,
        "--json-schema", json.dumps(schema),
    ]
    proc = subprocess.run(cmd, cwd=NEUTRAL_CWD, capture_output=True, text=True, timeout=120)
    outer = json.loads(proc.stdout)
    if outer.get("is_error"):
        raise RuntimeError(f"claude CLI error: {outer.get('result')}")
    return {"parsed": json.loads(outer["result"]), "cost_usd": outer.get("total_cost_usd", 0.0)}
