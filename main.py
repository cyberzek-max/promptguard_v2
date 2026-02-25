"""
KillChain Guardian - Main Proxy Server
========================================
OpenAI-compatible proxy that intercepts LLM requests, runs threat analysis,
and returns protected responses to the client and dashboard.

Compatible with:
  - Cursor base URL override → http://localhost:8000
  - Any OpenAI SDK client
  - Direct HTTP calls

Usage:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import time
import uuid
from pathlib import Path
from collections import deque

from dotenv import load_dotenv
load_dotenv()  # Must run before any os.getenv() calls

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from groq import AsyncGroq

import re
from threat_engine import ThreatEngine, ThreatResult, _USE_REDIS
from hardener import harden_prompt

# ---------------------------------------------------------------------------
# Response analysis
# ---------------------------------------------------------------------------

# Patterns that indicate the AI output contains harmful content that slipped through
RESPONSE_HARMFUL_PATTERNS = [
    (r"bash\s+-i\s+>&|/dev/tcp|nc\s+-[elp]+\s+\S+|python\s+-c.*socket", "RESPONSE_ATTACK_CODE", 0.90),
    (r"(api[_\s]?key|secret|token|password)\s*[=:]\s*\S{8,}", "RESPONSE_CREDENTIAL_LEAK", 0.85),
    (r"(my\s+instructions?\s+are|my\s+system\s+prompt\s+is|i\s+was\s+instructed\s+to)", "RESPONSE_PROMPT_LEAK", 0.75),
    (r"as\s+DAN|DAN\s*mode|in\s+developer\s+mode|as\s+an\s+unrestricted", "RESPONSE_JAILBREAK_COMPLIANCE", 0.95),
    (r"here\s+is\s+how\s+to\s+(make|build|create|synthesize)\s+(a\s+)?(bomb|weapon|explosive|drug|malware)", "RESPONSE_HARMFUL_INSTRUCTIONS", 0.90),
]

# Patterns that indicate the AI refused — used to bump session threat score
RESPONSE_REFUSAL_PATTERNS = [
    r"i\s+(can.t|cannot|won.t|will\s+not|am\s+not\s+able\s+to)\s+(help|assist|provide|give|tell)",
    r"(that.s|this\s+is)\s+(not\s+something\s+i|something\s+i\s+can.t)",
    r"i\s+must\s+(decline|refuse|clarify)",
    r"(harmful|illegal|unethical|dangerous)\s+(request|activity|content|instructions)",
    r"against\s+my\s+(guidelines|values|policy|principles)",
]

REFUSAL_SESSION_BUMP = 0.15  # how much to add to session score on AI refusal


def analyze_response(text: str) -> dict:
    """Scan AI output for signs of harmful content or compliance with attacks."""
    triggered = []
    max_score = 0.0
    for pattern, rule_name, score in RESPONSE_HARMFUL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            triggered.append(rule_name)
            max_score = max(max_score, score)
    return {"triggered": triggered, "score": max_score, "is_harmful": max_score >= 0.7}


def is_refusal(text: str) -> bool:
    """Detect if the AI refused the request — signals the input was harmful even if proxy missed it."""
    return any(re.search(p, text, re.IGNORECASE) for p in REFUSAL_PATTERNS)

REFUSAL_PATTERNS = RESPONSE_REFUSAL_PATTERNS


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UPSTREAM_API_KEY: str = os.getenv("UPSTREAM_API_KEY", "")
UPSTREAM_MODEL: str = os.getenv("UPSTREAM_MODEL", "llama-3.3-70b-versatile")
MAX_DASHBOARD_EVENTS: int = int(os.getenv("MAX_DASHBOARD_EVENTS", "100"))
MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "8192"))

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="KillChain Guardian",
    description="Defense-in-depth LLM proxy with kill-chain threat detection",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatEngine()

# Use a deque so the 100-event cap is enforced automatically — no manual pop(0)
dashboard_events: deque[dict] = deque(maxlen=MAX_DASHBOARD_EVENTS)


# ---------------------------------------------------------------------------
# LLM client (single shared instance, not recreated per request)
# ---------------------------------------------------------------------------

def _get_groq_client(api_key: str) -> AsyncGroq:
    """Return a Groq async client. Uses provided key or falls back to env."""
    return AsyncGroq(api_key=api_key or UPSTREAM_API_KEY)


async def call_llm(messages: list[dict], api_key: str) -> dict:
    """Forward a chat request to the upstream LLM and return a normalised response dict."""
    client = _get_groq_client(api_key)

    completion = await client.chat.completions.create(
        model=UPSTREAM_MODEL,
        messages=messages,
        temperature=1,
        max_tokens=MAX_TOKENS,
        top_p=1,
        stream=True,
        stop=None,
    )

    chunks: list[str] = []
    async for chunk in completion:
        if (
            chunk.choices
            and chunk.choices[0].delta
            and chunk.choices[0].delta.content
        ):
            chunks.append(chunk.choices[0].delta.content)

    full_text = "".join(chunks)
    return {
        "choices": [{"message": {"role": "assistant", "content": full_text}}]
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_api_key(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    return auth_header.removeprefix("Bearer ").strip() or UPSTREAM_API_KEY


def _extract_session_id(request: Request, body: dict) -> str:
    """
    Derive a session ID from headers or body.
    Avoids collapsing all anonymous traffic into a single 'default' session,
    which would corrupt multi-turn grooming detection.
    """
    return (
        request.headers.get("x-session-id")
        or body.get("user")
        or request.client.host  # IP-based fallback — better than 'default'
        or "anonymous"
    )


def _extract_last_user_message(messages: list[dict]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            content = m.get("content", "")
            return content if isinstance(content, str) else str(content)
    return ""


def _serialize_threat(t: ThreatResult) -> dict:
    return {
        "score": t.score,
        "stage": t.stage,
        "stage_index": t.stage_index,
        "verdict": t.verdict,
        "triggered_rules": t.triggered_rules,
        "block_reason": t.block_reason,
        "creative_mode": t.creative_mode,
        "session_id": t.session_id,
    }


def _record_event(
    event_id: str,
    timestamp: float,
    session_id: str,
    last_user_msg: str,
    threat: ThreatResult,
    ai_response: str,
    call_ms: int,
) -> None:
    dashboard_events.append({
        "id": event_id,
        "timestamp": timestamp,
        "session_id": session_id,
        "user_message": last_user_msg,
        "threat": _serialize_threat(threat),
        "ai_response": ai_response,
        "call_ms": call_ms,
    })


def _blocked_response() -> dict:
    return {
        "id": "chatcmpl-blocked",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "killchain-guardian",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "🛡️ Blocked by KillChain Guardian.",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


# ---------------------------------------------------------------------------
# Main proxy endpoint — OpenAI /v1/chat/completions compatible
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def proxy_completions(request: Request):
    body = await request.json()

    api_key = _extract_api_key(request)
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="No API key provided. Set the Authorization header or UPSTREAM_API_KEY env var.",
        )

    messages: list[dict] = body.get("messages", [])
    session_id = _extract_session_id(request, body)
    last_user_msg = _extract_last_user_message(messages)

    threat = engine.analyze(session_id, messages)

    event_id = str(uuid.uuid4())[:8]
    timestamp = time.time()

    if threat.verdict == "BLOCK":
        _record_event(event_id, timestamp, session_id, last_user_msg, threat, "BLOCKED", 0)
        return JSONResponse(_blocked_response())

    hardened_messages = harden_prompt(messages, threat)

    t0 = time.time()
    try:
        llm_response = await call_llm(hardened_messages, api_key)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Upstream LLM error: {exc}") from exc

    call_ms = int((time.time() - t0) * 1000)
    ai_text = llm_response["choices"][0]["message"].get("content", "")

    # ── Response analysis ─────────────────────────────────────────────────
    response_analysis = analyze_response(ai_text)

    # If response contains harmful content, override verdict and block
    if response_analysis["is_harmful"]:
        threat.verdict = "BLOCK"
        threat.triggered_rules.extend(response_analysis["triggered"])
        threat.block_reason = f"Harmful content detected in AI response: {response_analysis['triggered']}"
        _record_event(event_id, timestamp, session_id, last_user_msg, threat, "BLOCKED_RESPONSE", call_ms)
        return JSONResponse(_blocked_response())

    # If AI refused, bump session score — input was likely harmful even if proxy missed it
    if is_refusal(ai_text) and threat.verdict == "ALLOW":
        engine.bump_session_score(session_id, REFUSAL_SESSION_BUMP)

    _record_event(event_id, timestamp, session_id, last_user_msg, threat, ai_text, call_ms)
    return JSONResponse(llm_response)


# ---------------------------------------------------------------------------
# Dashboard endpoints
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    # Check multiple locations — works both locally and on Vercel
    candidates = [
        Path(__file__).parent / "index.html",
        Path("index.html"),
    ]
    for path in candidates:
        if path.exists():
            return HTMLResponse(content=path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


@app.get("/dashboard/events")
async def get_events(limit: int = 50):
    events = list(dashboard_events)
    return list(reversed(events[-limit:]))


@app.get("/dashboard/events/latest")
async def get_latest_event():
    return dashboard_events[-1] if dashboard_events else {}


@app.get("/dashboard/stats")
async def get_stats():
    events = list(dashboard_events)
    total = len(events)
    verdicts = [e["threat"]["verdict"] for e in events]
    blocked = verdicts.count("BLOCK")
    quarantined = verdicts.count("QUARANTINE")
    allowed = verdicts.count("ALLOW")
    sessions = len({e["session_id"] for e in events})
    return {
        "total_requests": total,
        "blocked": blocked,
        "quarantined": quarantined,
        "allowed": allowed,
        "active_sessions": sessions,
        "block_rate": round(blocked / total * 100, 1) if total else 0.0,
    }


@app.delete("/dashboard/reset")
async def reset_dashboard():
    dashboard_events.clear()
    if not _USE_REDIS:
        engine.sessions.clear()
    # For Redis: sessions expire automatically via TTL — no bulk clear needed
    # (Upstash free tier has no FLUSHDB, and we don't want to nuke other keys)
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# Utility endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/models")
async def list_models():
    """Stub model list so Cursor doesn't complain."""
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
            {"id": "gpt-4-turbo", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
        ],
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.1.0",
        "events": len(dashboard_events),
        "active_sessions": len(engine.sessions),
    }
