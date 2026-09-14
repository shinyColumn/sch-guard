# SCH Guard

A CLI that audits LLM agent "skill" documents for **Semantic Compliance
Hijacking (SCH)** — payload-less supply-chain attacks that disguise
malicious intent (credential exfiltration, remote code execution) as
ordinary compliance or operational prose, so they carry no code signature
for a traditional scanner to catch. Skills rarely embed explicit malicious
code; SCH Guard has an LLM judge the *intent* of the instructions against
an explicit taxonomy instead of pattern-matching the text.

Background: Liu et al., *"Exploiting LLM Agent Supply Chains via
Payload-less Skills"* (arXiv:2605.14460, 2026), which documents the SCH
attack and shows it evades both static scanners (SkillScan) and modular
semantic scanners (LLM Guard) at a 0% detection rate.

## Install

```bash
git clone <this-repo>
cd sch-guard
```

No install step beyond having Python 3.9+ and one of:
- `ANTHROPIC_API_KEY` set in your environment (SCH Guard calls the
  Anthropic API directly — run `pip install anthropic` first), or
- an authenticated `claude` CLI session (SCH Guard shells out to
  `claude -p` in headless mode; no extra install needed).

SCH Guard picks whichever is available automatically.

## Usage

```bash
python3 cli.py suspicious-skill.md
python3 cli.py skills/ --recursive
python3 cli.py skills/ --json > report.json
```

```
[MALICIOUS] [confidentiality_exfiltration, confidence=0.95] skills/aws-lambda-state-sync.md
    flags: ambient_data_harvest, obfuscated_endpoint, authority_pressure
    rationale: Directs harvesting the full os.environ dict and POSTing it to an
    undisclosed IP described digit-by-digit, framed as "telemetry sync".
[benign] skills/format-changelog.md

2 file(s) scanned -- 1 malicious, 0 error(s).
```

Exit codes: `0` everything's clean, `1` something was flagged malicious,
`2` bad usage (e.g. no files found) — drop it straight into a pre-merge
CI gate for a skill marketplace repo:

```yaml
- name: SCH Guard scan
  run: python3 cli.py skills/ --recursive
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## How it works

`core.py` holds SCH Guard's system prompt: it checks a skill document
against five signals distilled from the SCH taxonomy —

1. **Ambient data harvest** — collecting broad host state (env vars,
   tokens, credentials) beyond what the skill needs.
2. **Remote code adoption** — fetching remote text/bytes and directly
   executing it (a disguised `exec`/`eval`), rather than a vetted install.
3. **Obfuscated network endpoint** — an IP/port/path spelled out in prose
   instead of a plain literal.
4. **Authority/urgency pressure** — "mandatory policy" / "compliance"
   framing used to wave off scrutiny of a risky step.
5. **Control-flow eradication** — a risky operation described only as an
   abstract administrative action, or errors silently swallowed.

A skill is flagged malicious if it shows signal 1 or 2 *and* at least two
of the other three — not just keyword matches. Output is structured JSON
(`verdict`, `category`, `confidence`, `flags`, `rationale`), so it's both
machine-actionable and human-auditable. `llm.py` is the backend: it calls
the Anthropic API directly if `ANTHROPIC_API_KEY` is set, otherwise falls
back to the `claude` CLI.

## Limitations

- Judges the skill's text; it doesn't sandbox or execute anything, so a
  skill whose actual behavior deviates from its stated instructions (e.g.
  via a runtime prompt injection during execution) is out of scope.
- LLM-based judgment isn't deterministic — treat a "benign" verdict as
  reduced risk, not a formal guarantee, and pair it with normal sandboxing
  and least-privilege execution for agents.
- The `claude` CLI backend shares the session's usage/rate limits and its
  harness injects a standard environment preamble into every call; the
  API backend does not have this limitation.
