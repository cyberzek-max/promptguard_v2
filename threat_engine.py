"""
PromptGuard - Threat Engine
===================================
Multi-turn session threat scoring, kill-chain stage detection,
and detailed block reason generation.

Kill Chain Stages (adapted from Promptware Kill Chain):
  0. CLEAN              - No threat detected
  1. INITIAL_ACCESS     - First injection attempt / probing
  2. PRIVILEGE_ESC      - Trying to override system prompt / claim admin
  3. PERSISTENCE        - Trying to store malicious instructions in memory/RAG
  4. LATERAL_MOVEMENT   - Trying to pivot to other tools / agents
  5. EXFILTRATION       - Trying to extract data / credentials / secrets
"""

import re
import os
import json
import math
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import deque

# ---------------------------------------------------------------------------
# Redis session store (Upstash) — falls back to in-memory for local dev
# ---------------------------------------------------------------------------

_USE_REDIS = bool(os.getenv("UPSTASH_REDIS_REST_URL"))

if _USE_REDIS:
    from upstash_redis import Redis as _UpstashRedis
    _redis = _UpstashRedis(
        url=os.getenv("UPSTASH_REDIS_REST_URL"),
        token=os.getenv("UPSTASH_REDIS_REST_TOKEN"),
    )

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))  # 30 min default


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KILL_CHAIN_STAGES = [
    "CLEAN",
    "INITIAL_ACCESS",
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
]

# Score thresholds
BLOCK_THRESHOLD = 0.55
QUARANTINE_THRESHOLD = 0.25
HIGH_CONFIDENCE_BLOCK = 0.60  # Any single rule at or above this forces a BLOCK

# Session decay and escalation
CLEAN_TURN_DECAY = 0.75
ESCALATION_PER_SUSPICIOUS_TURN = 0.08
MAX_ESCALATION = 1.0

# Topic drift
DRIFT_TURN_MINIMUM = 3       # Don't flag drift until Nth turn
DRIFT_SCORE_THRESHOLD = 0.7
DRIFT_SCORE_WEIGHT = 0.25

# Creative mode reduces score by this multiplier
CREATIVE_MODE_SCORE_MULTIPLIER = 0.4

# Late-session attack bonus — attack after N clean turns gets escalated harder
LATE_ATTACK_CLEAN_TURN_MINIMUM = 2       # how many clean turns before bonus kicks in
LATE_ATTACK_BONUS_PER_CLEAN_TURN = 0.06  # bonus added per clean turn in history
LATE_ATTACK_BONUS_MAX = 0.25             # cap so it can't dominate the score

# Dynamic block threshold — lowered when first attack hits an otherwise clean session
BLOCK_THRESHOLD_DYNAMIC = 0.38  # used when turn_count >= 3 and no prior suspicious turns


# ---------------------------------------------------------------------------
# Rule definitions
# (pattern, score_increment, stage_index, rule_name, description)
# ---------------------------------------------------------------------------

RULES: list[tuple[str, float, int, str, str]] = [

    # ── Privilege Escalation ──────────────────────────────────────────────

    (
        r"\bignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|guidelines?|prompt)\b",
        0.45, 2, "IGNORE_INSTRUCTIONS",
        "Attempted to override system instructions via 'ignore previous instructions' pattern",
    ),
    (
        r"\byou\s+are\s+now\s+(a\s+)?(different|new|another|evil|unfiltered|jailbroken|DAN)\b",
        0.40, 2, "PERSONA_OVERRIDE",
        "Attempted persona replacement — classic jailbreak vector to bypass safety guidelines",
    ),
    (
        r"\b(do\s+anything\s+now|DAN|jailbreak|no\s+restrictions?|no\s+limits?|unrestricted\s+mode)\b",
        0.55, 2, "JAILBREAK_KEYWORD",
        "Explicit jailbreak trigger word detected (DAN, 'do anything now', etc.)",
    ),
    (
        r"\b(as\s+an?\s+AI|you\s+are\s+an?\s+AI).{0,40}(don't|do\s+not|cannot|can't)\s+have\s+restrictions?\b",
        0.35, 2, "AI_RESTRICTION_BYPASS",
        "Social engineering argument that AI should have no restrictions",
    ),
    (
        r"\b(pretend|act\s+as|roleplay\s+as|simulate|you\s+are)\s+(a\s+)?(hacker|malware|virus|exploit|ransomware|weapon)\b",
        0.50, 2, "MALICIOUS_PERSONA",
        "Requested AI to adopt a malicious technical persona (hacker, malware, etc.)",
    ),
    (
        r"\b(system\s+prompt|hidden\s+instructions?|secret\s+instructions?)\b.{0,60}(reveal|show|print|display|repeat|tell\s+me)\b",
        0.45, 2, "PROMPT_EXTRACTION",
        "Attempted to extract hidden system prompt or internal instructions",
    ),

    # NEW — catches "pretend you have no guidelines / act as if you were trained differently"
    (
        r"\b(pretend|imagine|act\s+as\s+if)\s+you\s+(have\s+no|were\s+(not|never)\s+trained|don'?t\s+have)\s+(guidelines?|rules?|restrictions?|ethics?)\b",
        0.45, 2, "HYPOTHETICAL_BYPASS",
        "Attempted to bypass restrictions via hypothetical framing ('pretend you have no guidelines')",
    ),

    # NEW — token smuggling / obfuscation (e.g. "ign0re", "igno​re" with zero-width chars)
    (
        r"ign[o0○@]r[e3€].{0,20}(instruct|rule|prompt|guideline)",
        0.40, 2, "OBFUSCATED_IGNORE",
        "Obfuscated 'ignore instructions' detected — possible evasion via character substitution",
    ),

    # ── Initial Access / Probing ──────────────────────────────────────────

    (
        r"\b(what\s+are\s+your\s+(rules|instructions?|guidelines?|constraints?)|what\s+can\s+(you|u)\s+not\s+do)\b",
        0.15, 1, "PROBE_RULES",
        "Probing the model's constraints — common first step in multi-turn attacks",
    ),
    (
        r"(<\s*script|javascript:|data:text/html|onerror\s*=|onload\s*=)",
        0.60, 1, "HTML_INJECTION",
        "HTML/JavaScript injection payload detected in prompt",
    ),
    (
        r"\[\[.*?(inject|override|system|admin).*?\]\]",
        0.40, 1, "BRACKET_INJECTION",
        "Bracket-style indirect injection pattern detected",
    ),
    (
        r"(\|\||&&|;|\$\(|`[^`]+`)\s*(cat|ls|wget|curl|bash|sh|python|nc|nmap)",
        0.65, 1, "SHELL_INJECTION",
        "Shell command injection sequence detected in input",
    ),

    # NEW — markdown / XML injection (common in RAG document attacks)
    (
        r"(</?(system|instruction|context|override|admin|root)>|\[SYSTEM\]|\[INST\])",
        0.45, 1, "MARKUP_INJECTION",
        "Markup-style injection tag detected — possible indirect prompt injection from document",
    ),

    # NEW — "as a developer / in developer mode / maintenance mode" escalation
    (
        r"\b(developer\s+mode|maintenance\s+mode|god\s+mode|sudo\s+mode|admin\s+mode|privileged\s+mode)\b",
        0.50, 2, "FAKE_MODE_ESCALATION",
        "Fake privilege escalation via invented 'mode' (developer mode, god mode, etc.)",
    ),

    # ── Persistence ───────────────────────────────────────────────────────

    (
        r"\b(remember\s+this\s+for\s+(next\s+time|future|always)|store\s+this\s+instruction|save\s+to\s+memory)\b",
        0.35, 3, "MEMORY_PERSISTENCE",
        "Attempted to persist malicious instructions across sessions via memory/RAG",
    ),
    (
        r"\b(every\s+time\s+you\s+respond|from\s+now\s+on\s+always|in\s+all\s+future\s+responses?)\b",
        0.30, 3, "PERSISTENT_OVERRIDE",
        "Attempted to install a persistent behavioral override for all future turns",
    ),

    # ── Lateral Movement ─────────────────────────────────────────────────

    (
        r"\b(call|invoke|execute|run)\s+(the\s+)?(tool|function|api|plugin|agent|webhook)\b.{0,60}(without|bypass|skip)\b",
        0.45, 4, "TOOL_BYPASS",
        "Attempted to invoke tools/agents while bypassing authorization checks",
    ),
    (
        r"\b(send|forward|relay|pass)\s+.{0,40}(to\s+)?(another\s+)?(agent|model|llm|api|endpoint|server)\b",
        0.35, 4, "LATERAL_PIVOT",
        "Attempted to relay instructions to another AI agent or system",
    ),

    # ── Exfiltration ──────────────────────────────────────────────────────

    (
        r"\b(api[_\s]?keys?|secret[_\s]?keys?|passwords?|credentials?|tokens?|bearer|auth)\b.{0,60}(send|email|post|log|print|reveal)\b",
        0.70, 5, "CREDENTIAL_EXFIL",
        "Attempted to exfiltrate credentials or secrets via model output",
    ),
    # Reverse direction — verb before credential keyword, wider window
    (
        r"\b(send|post|forward|print|output|reveal|email)\b.{0,120}(api[_\s]?keys?|secret[_\s]?keys?|passwords?|credentials?|tokens?|bearer)\b",
        0.70, 5, "CREDENTIAL_EXFIL_REVERSE",
        "Attempted credential exfiltration — verb precedes credential keyword",
    ),
    # Credential noun + known exfil destination in same sentence (no \b after dest — handles subdomains)
    (
        r"\b(api[_\s]?keys?|secrets?|credentials?|tokens?|passwords?)\b.{0,200}(webhook|pastebin|ngrok|requestbin|burp|exfil|attacker|evil)",
        0.75, 5, "CREDENTIAL_EXFIL_DESTINATION",
        "Credential keyword combined with known exfiltration destination",
    ),
    # Catch-all: credential + any URL in same message
    (
        r"\b(api[_\s]?keys?|secrets?|credentials?|tokens?|passwords?)\b.{0,300}(https?://|[\w-]+\.(site|io|com|net|xyz|dev))",
        0.70, 5, "CREDENTIAL_EXFIL_URL",
        "Credential keyword combined with external URL — likely exfiltration attempt",
    ),
    (
        r"\b(encode|base64|hex|rot13|caesar)\s+.{0,40}(and\s+)?(send|output|print|return)\b",
        0.45, 5, "ENCODED_EXFIL",
        "Attempted data exfiltration via encoding — common covert channel technique",
    ),
    (
        r"\b(exfiltrate|leak|steal|extract)\s+.{0,60}(data|information|files?|credentials?|keys?)\b",
        0.65, 5, "EXPLICIT_EXFIL",
        "Explicit exfiltration intent stated in prompt",
    ),
]

# Compile all patterns once at import time for performance
_COMPILED_RULES: list[tuple[re.Pattern, float, int, str, str]] = [
    (re.compile(pattern, re.IGNORECASE), score, stage_idx, name, desc)
    for pattern, score, stage_idx, name, desc in RULES
]

# Creative / fiction signals — reduce score when legitimate RP is detected
_CREATIVE_SIGNALS = [
    r"\b(write\s+a\s+story|fiction|fictional|novel|narrative|roleplay|let'?s\s+play|tabletop|d&d|dnd|game\s+master|gm)\b",
    r"\b(as\s+a\s+character|in\s+character|my\s+character|your\s+character|protagonist|antagonist)\b",
    r"\b(fantasy|sci-?fi|science\s+fiction|horror\s+story|thriller\s+plot|screenplay|fanfic)\b",
]
CREATIVE_PATTERN = re.compile("|".join(_CREATIVE_SIGNALS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatResult:
    score: float                    # 0.0 – 1.0
    stage: str                      # Kill-chain stage name
    stage_index: int                # 0–5
    verdict: str                    # ALLOW / QUARANTINE / BLOCK
    triggered_rules: list[str]      # Rule names that fired
    block_reason: Optional[str]     # Human-readable explanation for dashboard
    creative_mode: bool             # True if legitimate RP/fiction context detected
    session_id: str


@dataclass
class SessionState:
    session_id: str
    turn_count: int = 0
    threat_score: float = 0.0
    creative_mode: bool = False
    creative_declared: bool = False
    creative_declared_turn: int = 0   # which turn creative context was first established
    last_topics: deque = field(default_factory=lambda: deque(maxlen=6))
    suspicious_turns: int = 0
    last_updated: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Threat Engine
# ---------------------------------------------------------------------------

class ThreatEngine:

    def __init__(self):
        # In-memory fallback for local dev (no Redis env vars set)
        self._local_sessions: dict[str, SessionState] = {}

    # ── Session management ────────────────────────────────────────────────

    def _session_to_dict(self, session: SessionState) -> dict:
        return {
            "session_id":            session.session_id,
            "turn_count":            session.turn_count,
            "threat_score":          session.threat_score,
            "creative_mode":         session.creative_mode,
            "creative_declared":     session.creative_declared,
            "creative_declared_turn": session.creative_declared_turn,
            "last_topics":           list(session.last_topics),
            "suspicious_turns":      session.suspicious_turns,
            "last_updated":          session.last_updated,
        }

    def _session_from_dict(self, data: dict) -> SessionState:
        s = SessionState(session_id=data["session_id"])
        s.turn_count            = data.get("turn_count", 0)
        s.threat_score          = data.get("threat_score", 0.0)
        s.creative_mode         = data.get("creative_mode", False)
        s.creative_declared     = data.get("creative_declared", False)
        s.creative_declared_turn = data.get("creative_declared_turn", 0)
        s.suspicious_turns      = data.get("suspicious_turns", 0)
        s.last_updated          = data.get("last_updated", time.time())
        topics = data.get("last_topics", [])
        s.last_topics = deque(topics, maxlen=6)
        return s

    def _get_session(self, session_id: str) -> SessionState:
        if _USE_REDIS:
            raw = _redis.get(f"session:{session_id}")
            if raw:
                return self._session_from_dict(json.loads(raw))
            return SessionState(session_id=session_id)
        # Local fallback
        if session_id not in self._local_sessions:
            self._local_sessions[session_id] = SessionState(session_id=session_id)
        return self._local_sessions[session_id]

    def _save_session(self, session: SessionState) -> None:
        if _USE_REDIS:
            _redis.set(
                f"session:{session.session_id}",
                json.dumps(self._session_to_dict(session)),
                ex=SESSION_TTL_SECONDS,
            )
        else:
            self._local_sessions[session.session_id] = session

    def bump_session_score(self, session_id: str, amount: float) -> None:
        """Retroactively bump session threat score when AI refusal signals a missed threat."""
        session = self._get_session(session_id)
        session.threat_score = min(1.0, session.threat_score + amount)
        session.suspicious_turns += 1
        self._save_session(session)

    def reset_session(self, session_id: str) -> None:
        if _USE_REDIS:
            _redis.delete(f"session:{session_id}")
        else:
            self._local_sessions.pop(session_id, None)

    @property
    def sessions(self):
        """Compatibility shim — returns local sessions dict for dashboard reset."""
        return self._local_sessions

    # ── Text extraction ───────────────────────────────────────────────────

    @staticmethod
    def _extract_last_user_message(messages: list[dict]) -> str:
        """Return the text of the most recent user message."""
        for msg in reversed(messages):
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if isinstance(content, list):
                # Multimodal: join text parts only
                return " ".join(
                    part.get("text", "")
                    for part in content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
            return str(content)
        return ""

    @staticmethod
    def _build_full_text(messages: list[dict]) -> str:
        """Concatenate all string message contents for creative-signal scanning."""
        parts = []
        for m in messages:
            content = m.get("content", "")
            if isinstance(content, str):
                parts.append(content)
        return " ".join(parts)

    # ── Scoring helpers ───────────────────────────────────────────────────

    @staticmethod
    def _combine_scores(scores: list[float]) -> float:
        """Bayesian combination: 1 - ∏(1 - sᵢ).  Returns 0 for empty list."""
        if not scores:
            return 0.0
        return 1.0 - math.prod(1.0 - s for s in scores)

    @staticmethod
    def _compute_topic_drift(session: SessionState, current_text: str) -> float:
        """
        Vocabulary-overlap drift between the current turn and recent turns.
        High drift over many turns is a signal of multi-turn grooming.
        Returns a drift score in [0, 1].
        """
        if len(session.last_topics) < 2:
            return 0.0

        current_words = set(current_text.lower().split())
        recent_words: set[str] = set()
        for topic in list(session.last_topics)[-3:]:
            recent_words.update(topic.lower().split())

        if not recent_words or not current_words:
            return 0.0

        overlap = len(current_words & recent_words) / len(current_words)
        return max(0.0, 1.0 - overlap - 0.2)  # subtract 0.2 to reduce noise

    @staticmethod
    def _build_block_reason(
        block_reasons: list[str],
        triggered_rules: list[str],
    ) -> Optional[str]:
        if not block_reasons:
            return None
        primary = block_reasons[0]
        if len(block_reasons) > 1:
            extras = ", ".join(triggered_rules[1:])
            primary += f" [+{len(block_reasons) - 1} additional signal(s): {extras}]"
        return primary

    # ── Main analysis ─────────────────────────────────────────────────────

    def analyze(self, session_id: str, messages: list[dict]) -> ThreatResult:
        session = self._get_session(session_id)
        session.turn_count += 1
        session.last_updated = time.time()

        text = self._extract_last_user_message(messages)
        full_text = self._build_full_text(messages)

        triggered_rules: list[str] = []
        rule_scores: list[float] = []
        block_reasons: list[str] = []
        highest_stage = 0

        # ── Pattern matching ──────────────────────────────────────────────
        for compiled_pattern, score, stage_idx, rule_name, description in _COMPILED_RULES:
            if compiled_pattern.search(text):
                triggered_rules.append(rule_name)
                rule_scores.append(score)
                block_reasons.append(description)
                highest_stage = max(highest_stage, stage_idx)

        # ── Creative mode detection ───────────────────────────────────────
        if CREATIVE_PATTERN.search(full_text) and not session.creative_declared:
            session.creative_mode = True
            session.creative_declared = True
            session.creative_declared_turn = session.turn_count  # record WHEN

        # ── Topic drift / grooming detection ─────────────────────────────
        if session.turn_count > DRIFT_TURN_MINIMUM:
            drift = self._compute_topic_drift(session, text)
            if drift > DRIFT_SCORE_THRESHOLD:
                drift_contribution = drift * DRIFT_SCORE_WEIGHT
                rule_scores.append(drift_contribution)
                triggered_rules.append("TOPIC_DRIFT_GROOMING")
                block_reasons.append(
                    f"Significant topic drift across turns (drift={drift:.2f}) — "
                    "possible multi-turn grooming building toward a later-stage payload"
                )
                highest_stage = max(highest_stage, 1)

        # ── Session threat score update ───────────────────────────────────
        base_score = self._combine_scores(rule_scores)

        # Late-session attack bonus applied FIRST — before any discount.
        # A patient attacker who waits 3 clean turns before injecting deserves
        # more scrutiny, not the same as turn 1. Apply this before creative
        # discount so the discount can't fully erase the grooming signal.
        if triggered_rules:
            clean_turns_so_far = session.turn_count - session.suspicious_turns
            if clean_turns_so_far >= LATE_ATTACK_CLEAN_TURN_MINIMUM:
                late_bonus = min(
                    LATE_ATTACK_BONUS_MAX,
                    clean_turns_so_far * LATE_ATTACK_BONUS_PER_CLEAN_TURN
                )
                base_score = min(1.0, base_score + late_bonus)

        # Creative mode discount — only applies if:
        # 1. Creative context was established in a PRIOR turn (not same message)
        # 2. No malicious persona rule fired
        # 3. Stage is below lateral movement / exfil
        # 4. No HIGH-severity individual rule fired (score >= 0.45)
        #    — if someone fires IGNORE_INSTRUCTIONS or JAILBREAK inside a story,
        #    the creative framing doesn't make it less dangerous
        high_severity_fired = any(s >= 0.45 for s in rule_scores)
        creative_discount_eligible = (
            session.creative_mode
            and session.creative_declared_turn < session.turn_count
            and "MALICIOUS_PERSONA" not in triggered_rules
            and highest_stage < 4
            and not high_severity_fired
        )
        if creative_discount_eligible:
            base_score *= CREATIVE_MODE_SCORE_MULTIPLIER

        if not triggered_rules:
            # Clean turn: decay existing session score
            session.threat_score = max(0.0, session.threat_score * CLEAN_TURN_DECAY)
        else:
            session.suspicious_turns += 1
            escalation = min(MAX_ESCALATION, session.suspicious_turns * ESCALATION_PER_SUSPICIOUS_TURN)
            session.threat_score = min(1.0, base_score + escalation)

        session.last_topics.append(text[:200])
        self._save_session(session)

        # ── Verdict ───────────────────────────────────────────────────────
        score = session.threat_score

        # Dynamic block threshold: lower the bar on first attack after a clean session.
        # If someone behaves normally for 3+ turns then suddenly attacks, that context
        # makes the attack MORE suspicious — so we block at a lower score.
        effective_threshold = (
            BLOCK_THRESHOLD_DYNAMIC
            if session.turn_count >= 3 and session.suspicious_turns <= 1
            else BLOCK_THRESHOLD
        )

        verdict = self._compute_verdict(score, creative_discount_eligible, highest_stage, rule_scores, effective_threshold)

        return ThreatResult(
            score=round(score, 3),
            stage=KILL_CHAIN_STAGES[highest_stage],
            stage_index=highest_stage,
            verdict=verdict,
            triggered_rules=triggered_rules,
            block_reason=self._build_block_reason(block_reasons, triggered_rules),
            creative_mode=session.creative_mode,
            session_id=session_id,
        )

    @staticmethod
    def _compute_verdict(
        score: float,
        creative_discount_eligible: bool,
        highest_stage: int,
        rule_scores: list[float],
        effective_threshold: float = BLOCK_THRESHOLD,
    ) -> str:
        # High-confidence individual signal always blocks regardless of session score
        if any(s >= HIGH_CONFIDENCE_BLOCK for s in rule_scores):
            return "BLOCK"

        # Persistence/lateral/exfil stages in creative mode still block
        if score >= effective_threshold and creative_discount_eligible and highest_stage >= 3:
            return "BLOCK"

        if score >= effective_threshold and not creative_discount_eligible:
            return "BLOCK"

        if score >= QUARANTINE_THRESHOLD:
            return "QUARANTINE"

        return "ALLOW"
