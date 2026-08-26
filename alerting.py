"""slave-failure alerting — pure logic (no network / no Couchbase).

collector.py does the I/O (Jenkins console fetch, Ollama POST, Slack POST,
Couchbase read/write) and calls these helpers. Keeping the logic pure makes it
easy to reason about and test in isolation.

Flow it supports, per agent, per cycle:
  find_incident  -> is the agent's last-K run all FAILURE across >=N distinct jobs?
  extract_signal -> pull just stack traces + infra-error lines from a console log
  redact         -> scrub secrets from that snippet BEFORE it leaves the box
  ollama_messages/parse -> build the chat prompt / read the reply
  workflow_payload -> flat string vars for the Slack workflow webhook
  decide         -> fire / refire / resolve / noop given the previous alert state
"""
import re

FAILURE = "FAILURE"


# ── detection ─────────────────────────────────────────────────────────────────
def find_incident(ring, k, min_distinct):
    """Return an incident dict if the last `k` builds on this agent are ALL
    FAILURE and span at least `min_distinct` distinct jobs, else None.

    The distinct-jobs guard is the key false-positive filter: a single broken
    suite that happens to land on this agent k times looks like a bad slave but
    isn't — requiring >=2 distinct jobs means it's the agent, not one test.
    """
    ring = ring or []
    if k <= 0 or len(ring) < k:
        return None
    last = ring[-k:]
    if not all((b.get("result") == FAILURE) for b in last):
        return None
    jobs_in_order = []
    for b in last:
        j = b.get("job")
        if j and j not in jobs_in_order:
            jobs_in_order.append(j)
    if len(jobs_in_order) < min_distinct:
        return None
    return {
        "streak": k,
        "jobs": jobs_in_order,
        "builds": [{"job": b.get("job"), "num": b.get("num"), "ts": b.get("ts")} for b in last],
    }


# ── console-log signal extraction ──────────────────────────────────────────────
_TRACEBACK = "Traceback (most recent call last):"

# Infra / environment failure markers common in QE (Python TAF + Jenkins) logs.
_INFRA_RE = re.compile(
    r"(?i)("
    r"no space left on device|read-only file system|disk full|quota exceeded|"
    r"cannot contact|went offline|channel is already closed|hudson\.remoting|"
    r"connection refused|connection reset|connection timed out|no route to host|host is down|"
    r"unable to connect|failed to connect|could not resolve host|name or service not known|"
    r"sshexception|paramiko|permission denied \(publickey|authentication failed|"
    r"out of memory|oom[- ]?killer|cannot allocate memory|"
    r"rebalance (?:failed|exited)|memcached|"
    r"java\.io\.ioexception|java\.lang\.[a-za-z.]*error|"
    r"\bfatal\b|\berror\b|\bexception\b|assertionerror|"
    r"marked build as failure|finished: failure"
    r")"
)


def extract_signal(text, max_lines=30):
    """Pull only the high-signal lines from a console log: Python traceback
    blocks and infra-error lines (+/- a line of context). Falls back to the
    last `max_lines` non-empty lines if nothing matched. Caps at `max_lines`,
    keeping the LAST matches (the final failure is the actionable one) and
    marking dropped gaps with an ellipsis.
    """
    if not text:
        return ""
    lines = text.splitlines()
    n = len(lines)
    keep = set()

    def add_range(a, b):
        for i in range(max(0, a), min(n, b)):
            keep.add(i)

    i = 0
    while i < n:
        line = lines[i]
        if _TRACEBACK in line:
            # capture header + indented frames + the first following non-indented
            # line (the exception message), which is the useful bit.
            j = i + 1
            while j < n and (lines[j].startswith((" ", "\t")) or lines[j].strip() == ""):
                j += 1
            add_range(i, j + 1)
            i = j + 1
            continue
        if _INFRA_RE.search(line):
            add_range(i - 1, i + 2)
        i += 1

    idx = sorted(keep)
    if not idx:
        tail = [l for l in lines if l.strip()][-max_lines:]
        return "\n".join(l.rstrip() for l in tail)

    if len(idx) > max_lines:
        idx = idx[-max_lines:]

    out, prev = [], None
    for k in idx:
        if prev is not None and k != prev + 1:
            out.append("   ...")
        out.append(lines[k].rstrip())
        prev = k
    return "\n".join(out)


# ── redaction (runs on the small snippet right before it leaves the box) ───────
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)
_URL_CREDS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s:/@]+:[^\s:/@]+@")
_AUTH_HDR = re.compile(r"(?i)(authorization\s*:\s*)(basic|bearer|token)\s+[A-Za-z0-9+/=._\-]+")
_KV = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key)\b(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|\S+)"
)
_CLI_PW = re.compile(r"(?i)(--?p(?:assword|w|wd)?[ =])(\S+)")
_AWS_AKID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def redact(text, literals=(), redact_ips=False):
    """Scrub credential-like content. Order matters: broad structural patterns
    first, then keyword=value, then known literal secrets, then (optional) IPs.
    Errs toward over-masking — a masked token still leaves the error type/message
    intact, which is what the triage actually needs.
    """
    if not text:
        return text
    text = _PEM.sub("[REDACTED-PRIVATE-KEY]", text)
    text = _URL_CREDS.sub(r"\1[REDACTED]@", text)
    text = _AUTH_HDR.sub(r"\1\2 [REDACTED]", text)
    text = _KV.sub(r"\1\2[REDACTED]", text)
    text = _CLI_PW.sub(r"\1[REDACTED]", text)
    text = _AWS_AKID.sub("[REDACTED-AWS-KEY]", text)
    for lit in literals:
        if lit:
            text = re.sub(re.escape(lit), "[REDACTED]", text, flags=re.IGNORECASE)
    if redact_ips:
        text = _IP.sub("[IP]", text)
    return text


# ── Ollama prompt / reply ──────────────────────────────────────────────────────
def ollama_messages(agent_name, master, incident, snippet):
    system = (
        "You are an SRE assistant triaging why a Jenkins CI agent (build slave) keeps failing. "
        "You get the tail of console logs (stack traces / infra errors) from its most recent failed builds. "
        "Decide whether the failures come from the AGENT/INFRASTRUCTURE (disk full, agent offline, network, "
        "environment, missing deps) or from the TESTS/PRODUCT (assertion failures, product bugs), or if it is UNCLEAR. "
        "Be concise and specific, and cite the concrete errors you see. "
        "Never recommend automated actions — a human decides whether to take the agent offline.\n\n"
        "Respond in EXACTLY this format. For VERDICT and CONFIDENCE, output the ONE word you chose "
        "(do NOT repeat the list of options):\n"
        "VERDICT: <infra|test|unclear>\n"
        "CONFIDENCE: <low|medium|high>\n"
        "REASONING: 2-3 sentences citing the concrete errors.\n"
        "RECOMMENDATION: what a human should check or do next."
    )
    jobs = ", ".join(incident.get("jobs", []))
    user = (
        "Agent: %s  (Jenkins master: %s)\n"
        "Signal: %s consecutive FAILURE builds across jobs: %s\n\n"
        "Console log excerpts (secrets already redacted):\n"
        "----------\n%s\n----------" % (agent_name, master, incident.get("streak"), jobs, snippet)
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def parse_ollama(resp_json):
    """Read the assistant text out of an Ollama /api/chat response."""
    if not isinstance(resp_json, dict):
        return None
    msg = resp_json.get("message") or {}
    content = msg.get("content")
    return content.strip() if isinstance(content, str) and content.strip() else None


# ── Slack workflow payload (flat string vars) ──────────────────────────────────
# severity emoji by verdict; ⚠️ when we couldn't classify the model reply
_SEVERITY = {"infra": "🔴", "test": "🧪", "unclear": "❓"}
_ANALYSIS_LINE = re.compile(r"(?i)^\s*(VERDICT|CONFIDENCE|REASONING|RECOMMENDATION)\s*:\s*(.*)$")


def _parse_analysis(raw):
    """Pull VERDICT/CONFIDENCE/REASONING/RECOMMENDATION out of the model reply.
    Continuation lines fold into the current field. Missing fields -> ''."""
    out = {"VERDICT": "", "CONFIDENCE": "", "REASONING": "", "RECOMMENDATION": ""}
    if not raw:
        return out
    current = None
    for line in raw.splitlines():
        m = _ANALYSIS_LINE.match(line)
        if m:
            current = m.group(1).upper()
            out[current] = m.group(2).strip()
        elif current and line.strip():
            out[current] = (out[current] + " " + line.strip()).strip()
    return out


def severity_emoji(analysis):
    return _SEVERITY.get(_parse_analysis(analysis).get("VERDICT", "").lower(), "⚠️")


def format_analysis(analysis):
    """Turn the raw model reply into a compact, emoji-anchored block for Slack.
    Slack renders workflow-variable values as PLAIN TEXT, so we lean on emoji +
    structure (markdown would show literally). Falls back to the raw text if the
    reply didn't follow the expected VERDICT/CONFIDENCE/… shape."""
    if not analysis or not analysis.strip():
        return "AI triage unavailable."
    f = _parse_analysis(analysis)
    if not any(f.values()):
        return analysis.strip()[:2800]
    verdict = (f["VERDICT"] or "unclear").lower()
    head = _SEVERITY.get(verdict, "⚠️") + "  " + verdict
    if f["CONFIDENCE"]:
        head += "  ·  confidence: " + f["CONFIDENCE"].lower()
    lines = [head]
    if f["REASONING"]:
        lines.append("Why:  " + f["REASONING"])
    if f["RECOMMENDATION"]:
        lines.append("Do:   " + f["RECOMMENDATION"])
    return "\n".join(lines)[:2800]


def workflow_payload(master, agent, incident, analysis, agent_url):
    jobs = ", ".join(incident.get("jobs", []))
    summary = ("%s Build slave %s on %s — %s consecutive failures across %s. Consider taking it offline."
               % (severity_emoji(analysis), agent, master, incident.get("streak"), jobs))
    return {
        "slave": str(agent),
        "master": str(master),
        "streak": str(incident.get("streak", "")),
        "jobs": jobs,
        "url": agent_url or "",
        "summary": summary,
        "analysis": format_analysis(analysis),
    }


def recover_payload(master, agent, agent_url):
    return {
        "slave": str(agent),
        "master": str(master),
        "streak": "0",
        "jobs": "",
        "url": agent_url or "",
        "summary": "Build slave `%s` on %s recovered — a build has passed again." % (agent, master),
        "analysis": "",
    }


# ── alert-state transition ─────────────────────────────────────────────────────
def decide(prev, incident, now_ms, refire_sec):
    """Given the previous persisted alert doc and whether an incident exists now,
    return one of: 'fire' | 'refire' | 'resolve' | 'noop'.

    Edge-triggered: fire once on entering 'firing'; don't spam every cycle. If
    refire_sec > 0, re-remind while still firing after that interval. Resolve
    only when a previously-firing alert no longer has an incident.
    """
    firing_now = bool(incident)
    prev_status = (prev or {}).get("status")
    if firing_now:
        if prev_status != "firing":
            return "fire"
        if refire_sec and (now_ms - (prev or {}).get("lastAlertTs", 0)) >= refire_sec * 1000:
            return "refire"
        return "noop"
    return "resolve" if prev_status == "firing" else "noop"
