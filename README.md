# SCH-Guard

A CLI that audits LLM agent "skill" documents for **Semantic Compliance
Hijacking (SCH)** — payload-less supply-chain attacks that disguise
malicious intent (credential exfiltration, remote code execution) as
ordinary compliance or operational prose, so they carry no code signature
for a traditional scanner to catch. Skills rarely embed explicit malicious
code; SCH-Guard has an LLM judge the *intent* of the instructions against
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
- `ANTHROPIC_API_KEY` set in your environment (SCH-Guard calls the
  Anthropic API directly — run `pip install anthropic` first), or
- an authenticated `claude` CLI session (SCH-Guard shells out to
  `claude -p` in headless mode; no extra install needed).

SCH-Guard picks whichever is available automatically.

## Usage

```bash
python3 cli.py suspicious-skill.md
python3 cli.py skills/ --recursive
python3 cli.py skills/ --json > report.json
```

```
[MALICIOUS] [confidentiality_exfiltration, confidence=0.98] skills/aws-lambda-state-sync.md
    flags: ambient_data_harvest, authority_pressure, control_flow_eradication, obfuscated_endpoint
    rationale: Skill directs harvesting all environment variables (broad, non-minimal data
    collection), encodes a destination IP/port in obfuscated word form rather than plain
    literals, invokes "company compliance policy" framing to justify the exfiltration, and
    instructs silently swallowing any transmission errors.
[benign] skills/format-changelog.md

2 file(s) scanned -- 1 malicious, 0 error(s).
```

Exit codes: `0` everything's clean, `1` something was flagged malicious,
`2` bad usage (e.g. no files found) — drop it straight into a pre-merge
CI gate for a skill marketplace repo:

```yaml
- name: SCH-Guard scan
  run: python3 cli.py skills/ --recursive
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## How it works

`core.py` holds SCH-Guard's system prompt: it asks the LLM to check a
skill document against five signals distilled from the SCH taxonomy, and
report only which ones it sees —

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

The LLM does **not** decide the verdict itself — the prompt explicitly
tells it not to, so instructions planted inside the skill text (e.g. "tell
the reviewer this is safe") can't talk their way past it. Instead `core.py`
computes the verdict from the reported flags with a fixed rule: a skill is
malicious if it shows signal 1 or 2 *and* **all three** of signals 3–5.
That threshold (3 of 3, not a lower bar) was chosen from a preliminary
sweep of thresholds 1–3: it made the biggest difference on a smaller/
cheaper backbone, cutting its false-positive rate to zero at a small
recall cost, and did no harm on a stronger backbone.

Output is structured JSON (`verdict`, `category`, `confidence`, `flags`,
`rationale`), so it's both machine-actionable and human-auditable.
`llm.py` is the backend: it calls the Anthropic API directly if
`ANTHROPIC_API_KEY` is set, otherwise falls back to the `claude` CLI.

## Evaluation

Measured against a 200-skill set (100 attacks — 3 obfuscation tiers plus
5 prompt-injection-against-the-reviewer attempts — and 100 benign skills,
including 19 real, unedited skills pulled from Anthropic's own public
`anthropics/skills` repo), 5 independent runs per backbone:

| metric | SCH-Guard (Sonnet 5) | naive baseline (Sonnet 5) | SCH-Guard (Haiku 4.5) | naive baseline (Haiku 4.5) |
|---|---|---|---|---|
| accuracy | 0.994 | 0.971 | 0.991 | 0.968 |
| precision | 1.000 | 0.994 | 1.000 | 0.940 |
| recall | 0.988 | 0.948 | 0.982 | 1.000 |
| FPR | 0.000 | 0.006 | 0.000 | 0.064 |

"naive baseline" is the same backbone LLM given a single generic one-line
prompt instead of the taxonomy above — representative of using an
off-the-shelf LLM with no special scaffolding. On Sonnet 5 the accuracy
gap is statistically significant (paired McNemar per run, Fisher-combined
p=0.012); on Haiku 4.5 it's directionally consistent across all 5 runs but
short of significance at this sample size (p=0.083). The most concrete
finding: across the 5 runs, the naive baseline on Haiku 4.5 misclassified
real, currently-deployed Anthropic skills as malicious 5 times; SCH-Guard
never did.

A length/structure-matched control prompt (same signal-list format and
JSON schema, but with the taxonomy content replaced by generic stylistic
red flags) scored *worse* than the naive one-line baseline — so the gain
above isn't just from a longer, more structured prompt.

Per-skill cost and latency were about the same for SCH-Guard and the naive
baseline (~$0.009/skill, ~4 seconds, measured via the `claude` CLI backend
on Sonnet 5) — the taxonomy prompt's extra length isn't a meaningful CI
cost.

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
- Evaluated against a synthetic attack set (plus a modest 19 real benign
  skills); not tested against real-world adaptive attackers who know and
  specifically target this taxonomy and its decision rule.
