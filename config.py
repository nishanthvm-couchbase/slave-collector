"""slaves-collector configuration.

Polls Jenkins masters and persists agent/fleet state + trend samples into the
Couchbase `slaves` bucket (key-prefixed in _default). greenboard-v2 reads from
there — so the Jenkins tokens live ONLY here, never on the greenboard host.

Tokens are read from files (default: alongside this file), overridable by env.
Never commit token VALUES.
"""
import os

# ── Jenkins masters ────────────────────────────────────────────────────────
# token_file: path to a file containing just the API token (per-master).
#   env override: JENKINS_<KEY>_TOKEN wins over the file.
_HERE = os.path.dirname(os.path.abspath(__file__))

MASTERS = [
    {
        "key":        "qe",
        "label":      "qe-jenkins1",
        "base":       os.environ.get("JENKINS_QE_BASE", "http://qe-jenkins1.sc.couchbase.com"),
        "user":       os.environ.get("JENKINS_QE_USER", "nishanth-vm"),
        "token_env":  "JENKINS_QE_TOKEN",
        "token_file": os.environ.get("JENKINS_QE_TOKEN_FILE", os.path.join(_HERE, "qe_token.txt")),
    },
    {
        "key":        "qa",
        "label":      "qa.sc",
        "base":       os.environ.get("JENKINS_QA_BASE", "http://qa.sc.couchbase.com"),
        "user":       os.environ.get("JENKINS_QA_USER", "nishanth"),
        "token_env":  "JENKINS_QA_TOKEN",
        "token_file": os.environ.get("JENKINS_QA_TOKEN_FILE", os.path.join(_HERE, "qa_token.txt")),
    },
]

def token_for(master):
    """Resolve a master's token: env var first, then token_file."""
    v = os.environ.get(master["token_env"])
    if v:
        return v.strip()
    try:
        with open(master["token_file"], "r") as f:
            return f.read().strip()
    except Exception:
        return None


def readsecret(env_key, file_env_key):
    """Generic secret resolver: env var first, then a file path in <file_env_key>.
    Returns "" when neither is set (never commit the value itself)."""
    v = os.environ.get(env_key)
    if v:
        return v.strip()
    f = os.environ.get(file_env_key)
    if f:
        try:
            with open(f) as fh:
                return fh.read().strip()
        except Exception:
            return ""
    return ""

# ── Couchbase (new-gb cluster) ──────────────────────────────────────────────
# Namespaced env vars (SLAVES_CB_*) so a global CB_PASS/CB_USER in the shell
# profile can't silently override them. The password has NO default on purpose —
# it is never committed to source; set SLAVES_CB_PASS in the launch environment.
CB_HOST   = os.environ.get("SLAVES_CB_HOST", "172.23.105.219")
CB_USER   = os.environ.get("SLAVES_CB_USER", "Administrator")
CB_PASS   = os.environ.get("SLAVES_CB_PASS", "")
CB_BUCKET = os.environ.get("SLAVES_CB_BUCKET", "slaves")

# ── cadence & retention ─────────────────────────────────────────────────────
STATE_POLL_SEC   = int(os.environ.get("SLAVES_POLL_SEC", "60"))    # state + build-history cycle
SAMPLE_EVERY_SEC = int(os.environ.get("SLAVES_SAMPLE_SEC", "300")) # write trend samples every 5 min
SAMPLE_TTL_DAYS  = int(os.environ.get("SLAVES_SAMPLE_TTL_DAYS", "30"))
BUILD_RING       = int(os.environ.get("SLAVES_BUILD_RING", "20"))  # last-N builds kept per agent
HTTP_TIMEOUT     = int(os.environ.get("SLAVES_HTTP_TIMEOUT", "45"))

# health thresholds
DISK_FREE_RED_GB   = 10
DISK_FREE_AMBER_GB = 25
MEM_USED_RED_PCT   = 92
MEM_USED_AMBER_PCT = 82
RESP_AMBER_MS      = 1500
FAILS_FAILING      = 3   # >= this many fails in the last-8 builds → failing

# ── slave-failure alerting (detect a bad agent → Slack heads-up + AI triage) ──
# When an agent's last K builds are ALL failures, post a Slack notice and attach
# an Ollama "why is it failing / what to do" note. It NEVER takes an agent
# offline — a human decides. Fully OFF until SLAVES_ALERTS_ENABLED=true AND the
# endpoints below are set. Nothing here (URLs/tokens) is committed.
ALERTS_ENABLED       = os.environ.get("SLAVES_ALERTS_ENABLED", "false").lower() == "true"
ALERT_K              = int(os.environ.get("SLAVES_ALERT_K", "5"))            # consecutive FAILUREs to trip
ALERT_MIN_DISTINCT   = int(os.environ.get("SLAVES_ALERT_MIN_DISTINCT", "2"))  # span >=N distinct jobs (kills "one broken suite" false-positive)
ALERT_MAX_PER_CYCLE  = int(os.environ.get("SLAVES_ALERT_MAX_PER_CYCLE", "2"))  # cap heavy (log-fetch+Ollama) work per poll
ALERT_FLEET_SUPPRESS = int(os.environ.get("SLAVES_ALERT_FLEET_SUPPRESS", "5")) # if >N agents trip at once → likely systemic, not per-slave → skip
ALERT_REFIRE_SEC     = int(os.environ.get("SLAVES_ALERT_REFIRE_SEC", "0"))     # 0 = alert once until it recovers; >0 = remind every N sec while still firing
ALERT_NOTIFY_RECOVER = os.environ.get("SLAVES_ALERT_NOTIFY_RECOVER", "true").lower() == "true"

# console-log signal (kept tiny on purpose: stack traces + infra markers only)
LOG_TAIL_BYTES = int(os.environ.get("SLAVES_LOG_TAIL_BYTES", "262144"))  # fetch only the last 256 KB of console
LOG_MAX_LINES  = int(os.environ.get("SLAVES_LOG_MAX_LINES", "30"))       # cap extracted lines per build
LOG_BUILDS     = int(os.environ.get("SLAVES_LOG_BUILDS", "2"))           # analyze the last N failing builds

# secrets scrubbed from every snippet BEFORE it leaves this box. No default (so no
# secret sits in source) — set SLAVES_REDACT_LITERALS to your cluster password(s),
# comma-separated. Pattern-based scrubbing (password=, -p, basic-auth, url creds,
# keys) applies regardless; these literals catch bare occurrences.
REDACT_LITERALS = [s.strip() for s in os.environ.get("SLAVES_REDACT_LITERALS", "").split(",") if s.strip()]
REDACT_IPS      = os.environ.get("SLAVES_REDACT_IPS", "false").lower() == "true"  # internal 172.23.* kept by default (useful, not secret)

# ── Ollama (self-hosted CPU box; analysis only) ──────────────────────────────
OLLAMA_URL         = os.environ.get("OLLAMA_URL", "http://172.23.217.9:11434")
OLLAMA_MODEL       = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
# CPU inference of a 7B is slow, and a COLD call (model not resident) also pays a
# one-time model-load. Measured ~140s cold on the 12GB/8-core box, so the timeout
# is generous — it runs on a background worker, so a long wait costs nothing.
OLLAMA_TIMEOUT     = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "400"))
# keep the model resident between (rare) alerts so clustered incidents stay fast.
# "-1" = never unload (costs ~6GB RAM permanently on the dedicated Ollama box).
OLLAMA_KEEP_ALIVE  = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")

# ── Slack (Workflow Builder "webhook" trigger; analysis only) ─────────────────
# Only secret is the workflow webhook URL. Channel/recipients + message layout
# are configured inside Slack — we just POST a flat JSON of string variables:
#   slave, master, streak, jobs, url, summary, analysis
SLACK_WORKFLOW_URL = readsecret("SLACK_WORKFLOW_URL", "SLACK_WORKFLOW_URL_FILE")
