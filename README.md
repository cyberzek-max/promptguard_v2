# PromptGuard

A proxy that sits between any OpenAI-compatible client and an LLM, intercepting every request to detect and block prompt injection attacks before they reach the model.

Built as a proof-of-concept for a hackathon. Works, but not production-hardened — see limitations below.

---

## What it does

Most prompt injection defenses are stateless — they look at one message in isolation. PromptGuard tracks the full conversation session and scores threat accumulation across turns, which is the only realistic way to catch multi-turn grooming attacks where no single message looks obviously malicious.

When a request comes in, it goes through three stages:

1. **Threat Engine** — scores the message against 21 detection rules mapped to kill-chain stages (Initial Access → Privilege Escalation → Persistence → Lateral Movement → Exfiltration). Session score uses Bayesian combination with decay on clean turns and escalation on repeated suspicious turns.

2. **Prompt Hardener** — if the request isn't blocked, it gets wrapped in XML sandboxing with randomized anti-game reminders before forwarding. Reinforcement level scales with threat score.

3. **Protected LLM call** — the hardened prompt goes to the upstream model (Groq/Llama by default). The dashboard logs the result.

The proxy is OpenAI API-compatible, so you can point Cursor or any SDK client at `localhost:8000/v1` without changing anything else.

---

## Detection rules

21 rules across 5 kill-chain stages:

| Stage | Rules |
|---|---|
| Initial Access | HTML injection, shell injection, bracket injection, markup injection, rule probing |
| Privilege Escalation | Ignore instructions, persona override, jailbreak keywords, AI restriction bypass, malicious persona, prompt extraction, hypothetical bypass, obfuscated ignore, fake mode escalation |
| Persistence | Memory persistence, persistent override |
| Lateral Movement | Tool bypass, lateral pivot |
| Exfiltration | Credential exfil, encoded exfil, explicit exfil |

Plus multi-turn topic drift detection using vocabulary overlap across the last 3 turns.

---

## Stack

- **FastAPI + Uvicorn** — async proxy server, OpenAI-compatible
- **Groq SDK** — LLM calls (llama-3.3-70b-versatile, free tier)
- **Pure Python** — threat engine, no external ML model needed
- **Single-file HTML dashboard** — real-time chat UI with session score history and kill-chain stage tracker

---

## Setup

```bash
pip install -r requirements.txt
```

Create a `.env` file:

```
UPSTREAM_API_KEY=your_groq_key_here
UPSTREAM_MODEL=llama-3.3-70b-versatile
```

Get a free Groq key at [console.groq.com](https://console.groq.com) — no credit card needed.

Start the proxy:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open the dashboard at `http://localhost:8000/dashboard`.

To use with Cursor, point it at your deployed Vercel URL:

```
Settings → Models → Base URL → https://promptguardv2.vercel.app/v1
API Key → your Groq key
```

For local development only:

```
Settings → Models → Base URL → http://localhost:8000/v1
API Key → your Groq key
```

---

## Running tests

```bash
pip install httpx rich
python test_multiturn.py
```

Runs 10 multi-turn scenarios — 8 attack sequences and 2 legitimate ones — each as an isolated session. Prints a results table with pass/fail, final score, and triggered rules per scenario.

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/v1/chat/completions` | POST | OpenAI-compatible proxy |
| `/v1/models` | GET | Model list stub |
| `/dashboard` | GET | Live monitoring UI |
| `/dashboard/events` | GET | Recent events |
| `/dashboard/stats` | GET | Aggregate stats |
| `/dashboard/reset` | DELETE | Clear session state |
| `/health` | GET | Health check |

---

## Limitations

- **In-memory session state** — all session data is lost on restart. Redis would be the right swap for anything persistent.
- **Regex-based detection** — obfuscated or novel attack patterns can evade the rules. The engine has no semantic understanding.
- **No proxy authentication** — anyone who can reach port 8000 can use it. Not safe to expose publicly.
- **Single upstream model** — hardcoded to Groq/Llama. Swapping to OpenAI or Anthropic requires a config change.
- **Requires public deployment for Cursor** — Cursor does not allow localhost base URLs, so local development cannot be used directly with Cursor. Deploy to Vercel first.
- **Creative mode is temporally gated** — the roleplay discount only applies if creative context was established in a prior turn, not the same message. This closes the common prefix evasion ("write a story where the character says: ignore all instructions"). A two-turn setup attack (establish roleplay in turn 1, inject in turn 2) is still theoretically possible but would require semantic understanding to fully close — that's an embedding problem, not a regex one.

---

## License

MIT
