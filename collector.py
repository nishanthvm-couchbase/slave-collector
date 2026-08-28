#!/usr/bin/env python3
"""slaves-collector — poll Jenkins masters, persist agent/fleet state + trends
into the Couchbase `slaves` bucket. greenboard-v2 reads from there.

Docs written (key-prefixed in _default):
  agent::<master>::<name>   current state + last-N builds ring   (upsert ~60s)
  trend::<master>::<name>   rolling per-agent metric samples     (upsert ~5m)
  trend::fleet::<master>    rolling fleet KPI samples            (upsert ~5m)
  jobcursor::<master>       last-seen build number per job       (collector state)

Only this service holds the Jenkins tokens. Read-only against Jenkins; writes
only to the `slaves` bucket.
"""
import re
import sys
import time
import json
import queue
import base64
import getpass
import logging
import threading
import urllib.request
import urllib.parse
from datetime import timedelta

from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions, ClusterTimeoutOptions
from couchbase.auth import PasswordAuthenticator
from couchbase.exceptions import DocumentNotFoundException

import config as C
import alerting as A

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("slaves")
# The Couchbase SDK emits verbose slow-operation ("threshold") reports at INFO;
# quiet them so our own cycle logs stay readable (harmless — just latency noise).
logging.getLogger("couchbase").setLevel(logging.WARNING)

# monitorData class keys
MD = "hudson.node_monitors."
K_SWAP, K_DISK, K_TMP = MD + "SwapSpaceMonitor", MD + "DiskSpaceMonitor", MD + "TemporarySpaceMonitor"
K_RESP, K_ARCH, K_CLK = MD + "ResponseTimeMonitor", MD + "ArchitectureMonitor", MD + "ClockMonitor"

COMPUTER_TREE = (
    "busyExecutors,totalExecutors,computer[displayName,offline,temporarilyOffline,"
    "idle,numExecutors,offlineCauseReason,assignedLabels[name],monitorData[*],"
    "executors[idle,progress,likelyStuck,currentExecutable[fullDisplayName,url,number]]]"
)
LASTBUILD_TREE = "jobs[name,lastBuild[number,result,timestamp,builtOn]]"
JOBBUILDS_TREE = "builds[number,result,timestamp,builtOn,fullDisplayName]{0,%d}"

TREND_CAP    = 2016    # 7 days @ 5-min samples
BACKFILL_BUDGET = 30   # jobs to seed-backfill per cycle (spreads the first fill)
GAP_FETCH_MAX   = 30   # cap builds fetched when a job jumped many builds between cycles

# ── in-memory collector state (seeded from CB on start) ─────────────────────
job_last  = {m["key"]: {} for m in C.MASTERS}   # master -> {job: last recorded build number}
rings     = {m["key"]: {} for m in C.MASTERS}   # master -> {agent: [ {num,result,ts,job}, ... ]}
_auth_hdr = {}   # master key -> "Basic ..."
_cluster  = None
_coll     = None
_last_sample_at = 0
firing    = {m["key"]: set() for m in C.MASTERS}   # master -> set(agent names currently in a firing alert)
# alerting runs its slow work (log fetch + Ollama, ~140s cold) on a background
# worker so it never stalls the poll loop. _inflight guards against re-queuing an
# incident that's still being processed; _alert_lock guards `firing` + `_inflight`.
_alert_q        = queue.Queue()
_inflight       = {m["key"]: set() for m in C.MASTERS}
_alert_lock     = threading.Lock()
_worker_started = False


# ── Jenkins auth ────────────────────────────────────────────────────────────
# Token resolution order: env var → token file → interactive prompt. The prompt
# path keeps the secret in memory only (nothing on disk) — see resolve_tokens().
def resolve_tokens():
    for m in C.MASTERS:
        tok = C.token_for(m)   # env, then file
        src = "env/file"
        if not tok:
            if not sys.stdin.isatty():
                raise SystemExit(
                    "no token for %s and no TTY to prompt — set %s, create %s, or start attached in a screen"
                    % (m["key"], m["token_env"], m["token_file"]))
            tok = getpass.getpass("Jenkins API token for %s (user %s): " % (m["label"], m["user"])).strip()
            src = "prompt"
        if not tok:
            raise SystemExit("empty token for %s" % m["key"])
        _auth_hdr[m["key"]] = "Basic " + base64.b64encode(("%s:%s" % (m["user"], tok)).encode()).decode()
        log.info("[%s] token loaded (%s)", m["key"], src)


def _auth(master):
    return _auth_hdr[master["key"]]


def jfetch(master, path, tree=None):
    url = master["base"].rstrip("/") + path
    if tree:
        url += "?" + urllib.parse.urlencode({"tree": tree})
    req = urllib.request.Request(url, headers={"Authorization": _auth(master), "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=C.HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_job_builds(master, job, n):
    try:
        j = jfetch(master, "/job/%s/api/json" % urllib.parse.quote(job), JOBBUILDS_TREE % n)
        return j.get("builds") or []
    except Exception as e:
        log.warning("[%s] fetch builds for %s failed: %s", master["key"], job, e)
        return []


def jget_raw(master, path, query=None):
    """Authenticated GET returning (bytes, headers) — for non-JSON endpoints
    like console logs. headers.get() is case-insensitive."""
    url = master["base"].rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"Authorization": _auth(master)})
    with urllib.request.urlopen(req, timeout=C.HTTP_TIMEOUT) as r:
        return r.read(), r.headers


def fetch_console_tail(master, job, num, tail_bytes):
    """Fetch only the TAIL of a build's console via Jenkins progressiveText, so
    we never pull a multi-MB log into memory. First probe the total size (a start
    past the end returns an empty body with an X-Text-Size header), then fetch
    from (size - tail_bytes)."""
    path = "/job/%s/%s/logText/progressiveText" % (urllib.parse.quote(job), num)
    try:
        _, hdrs = jget_raw(master, path, {"start": 10 ** 12})
        size = int(hdrs.get("X-Text-Size") or 0)
    except Exception:
        size = 0
    start = max(0, size - tail_bytes) if size else 0
    body, _ = jget_raw(master, path, {"start": start})
    return body.decode("utf-8", "replace")


# ── Couchbase ───────────────────────────────────────────────────────────────
def coll():
    global _cluster, _coll
    if _coll is not None:
        return _coll
    to = ClusterTimeoutOptions(connect_timeout=timedelta(seconds=20), kv_timeout=timedelta(seconds=15),
                               query_timeout=timedelta(seconds=60))
    _cluster = Cluster("couchbase://%s" % C.CB_HOST,
                       ClusterOptions(PasswordAuthenticator(C.CB_USER, C.CB_PASS), timeout_options=to))
    _cluster.wait_until_ready(timedelta(seconds=25))
    _coll = _cluster.bucket(C.CB_BUCKET).default_collection()
    return _coll


def cb_get(key):
    try:
        return coll().get(key).content_as[dict]
    except DocumentNotFoundException:
        return None
    except Exception as e:
        log.warning("cb_get %s: %s", key, e)
        return None


def cb_upsert(key, doc):
    coll().upsert(key, doc)


# ── seed state from CB so a restart resumes cleanly ─────────────────────────
def seed_from_cb():
    """Resume cleanly after a restart: job cursors + per-agent build rings from
    the persisted docs. Best-effort — if the N1QL index isn't there yet, rings
    just refill from live builds over the next cycles."""
    for m in C.MASTERS:
        mk = m["key"]
        cur = cb_get("jobcursor::%s" % mk)
        if cur and isinstance(cur.get("jobLast"), dict):
            job_last[mk] = {k: int(v) for k, v in cur["jobLast"].items()}
            log.info("[%s] seeded %d job cursors", mk, len(job_last[mk]))
        try:
            res = _cluster.query(
                "SELECT s.name, s.builds FROM `%s` s WHERE s.type='agent' AND s.master='%s'" % (C.CB_BUCKET, mk))
            n = 0
            for row in res:
                if row.get("builds"):
                    rings[mk][row["name"]] = list(row["builds"])
                    n += 1
            log.info("[%s] seeded rings for %d agents", mk, n)
        except Exception as e:
            log.info("[%s] ring seed skipped (%s) — rings refill from live builds", mk, e)
        try:
            res = _cluster.query(
                "SELECT RAW s.name FROM `%s` s WHERE s.type='slavealert' AND s.status='firing' AND s.master='%s'"
                % (C.CB_BUCKET, mk))
            for nm in res:
                firing[mk].add(nm)
            if firing[mk]:
                log.info("[%s] seeded %d firing alert(s)", mk, len(firing[mk]))
        except Exception as e:
            log.info("[%s] firing-alert seed skipped (%s)", mk, e)


# ── build-history rings ─────────────────────────────────────────────────────
PASS, UNSTABLE, FAIL, ABORT = "SUCCESS", "UNSTABLE", "FAILURE", "ABORTED"


def _append_build(mk, job, b):
    agent = b.get("builtOn")
    res = b.get("result")
    if not agent or not res:          # skip running (null result) or unattributed builds
        return
    ring = rings[mk].setdefault(agent, [])
    num = b.get("number")
    if any(x.get("num") == num and x.get("job") == job for x in ring[-6:]):
        return
    ring.append({"num": num, "result": res, "ts": b.get("timestamp"), "job": job})
    ring.sort(key=lambda x: x.get("ts") or 0)
    if len(ring) > C.BUILD_RING:
        del ring[:len(ring) - C.BUILD_RING]


def update_rings(master, lastbuilds):
    mk = master["key"]
    jl = job_last[mk]
    backfill_left = BACKFILL_BUDGET
    # seed unseen jobs busiest-first so active agents fill quickly
    jobs = [(name, lb) for name, lb in lastbuilds.items() if lb and lb.get("number") is not None]
    unseen = [x for x in jobs if x[0] not in jl]
    unseen.sort(key=lambda x: (x[1].get("timestamp") or 0), reverse=True)
    seen = [x for x in jobs if x[0] in jl]

    for name, lb in unseen:
        num = lb["number"]
        if backfill_left > 0:
            backfill_left -= 1
            for b in sorted(fetch_job_builds(master, name, C.BUILD_RING), key=lambda b: b.get("number") or 0):
                _append_build(mk, name, b)
            # record cursor at the highest FINISHED build (leave running latest to refire)
            jl[name] = num if lb.get("result") else max(num - 1, 0)
        else:
            # no backfill budget this cycle: just record the latest finished one
            if lb.get("result"):
                _append_build(mk, name, lb)
                jl[name] = num

    for name, lb in seen:
        num = lb["number"]
        prev = jl[name]
        if num <= prev:
            continue
        if num - prev == 1:
            if lb.get("result"):
                _append_build(mk, name, lb)
                jl[name] = num
            # else running — hold cursor, catch it once finished
        else:
            fetched = fetch_job_builds(master, name, min(num - prev, GAP_FETCH_MAX))
            maxfin = prev
            for b in sorted(fetched, key=lambda b: b.get("number") or 0):
                if (b.get("number") or 0) > prev and b.get("result"):
                    _append_build(mk, name, b)
                    maxfin = max(maxfin, b["number"])
            jl[name] = max(maxfin, num - 1) if not lb.get("result") else num


# ── normalization + health ──────────────────────────────────────────────────
def _gb(v):
    return round(v / 1e9, 1) if isinstance(v, (int, float)) else None


def success_of(ring):
    considered = [b for b in ring if b["result"] in (PASS, UNSTABLE, FAIL)]
    if not considered:
        return None, 0, 0
    passes = sum(1 for b in considered if b["result"] == PASS)
    return round(passes / len(considered) * 100), passes, len(considered)


def health_of(agent):
    if agent["offline"]:
        return "offline"
    ring = agent["builds"]
    recent = ring[-8:]
    fails = sum(1 for b in recent if b["result"] == FAIL)
    if fails >= C.FAILS_FAILING:
        return "failing"
    disk = agent.get("diskFreeGB")
    mem = agent.get("memPct")
    resp = agent.get("responseMs")
    degraded = (
        fails >= 1
        or (disk is not None and disk < C.DISK_FREE_AMBER_GB)
        or (mem is not None and mem > C.MEM_USED_AMBER_PCT)
        or (resp is not None and resp > C.RESP_AMBER_MS)
    )
    return "degraded" if degraded else "healthy"


def norm_agent(mk, c, now_ms):
    name = c.get("displayName") or ""
    md = c.get("monitorData") or {}
    swap = md.get(K_SWAP) or {}
    disk = md.get(K_DISK) or {}
    tmp = md.get(K_TMP) or {}
    resp = md.get(K_RESP) or {}
    clk = md.get(K_CLK) or {}
    mem_total, mem_avail = swap.get("totalPhysicalMemory"), swap.get("availablePhysicalMemory")
    mem_used = (mem_total - mem_avail) if (isinstance(mem_total, (int, float)) and isinstance(mem_avail, (int, float))) else None
    mem_pct = round(mem_used / mem_total * 100, 1) if (mem_used and mem_total) else None

    running, busy = [], 0
    for e in (c.get("executors") or []):
        ce = e.get("currentExecutable")
        if ce:
            busy += 1
            running.append({"job": ce.get("fullDisplayName"), "url": ce.get("url"),
                            "number": ce.get("number"), "progress": e.get("progress"),
                            "stuck": bool(e.get("likelyStuck"))})
    total = c.get("numExecutors") or len(c.get("executors") or [])
    labels = [l.get("name") for l in (c.get("assignedLabels") or []) if l.get("name") and l.get("name") != name]
    ring = rings[mk].get(name, [])
    spct, spass, stot = success_of(ring)

    agent = {
        "type": "agent", "master": mk, "name": name,
        "labels": labels,
        "offline": bool(c.get("offline")), "temporarilyOffline": bool(c.get("temporarilyOffline")),
        "offlineCause": c.get("offlineCauseReason") or "",
        "numExecutors": total, "busy": busy, "idle": busy == 0, "running": running,
        "arch": md.get(K_ARCH), "memUsedGB": _gb(mem_used), "memTotalGB": _gb(mem_total), "memPct": mem_pct,
        "diskFreeGB": _gb(disk.get("size")), "tmpFreeGB": _gb(tmp.get("size")),
        "responseMs": resp.get("average"), "clockDiffMs": clk.get("diff"),
        "builds": ring, "successPct": spct, "passCount": spass, "buildSample": stot,
        "ts": now_ms,
    }
    agent["health"] = health_of(agent)
    return agent


# ── trend rolling append ────────────────────────────────────────────────────
def append_trend(key, sample):
    doc = cb_get(key) or {"type": "trend", "samples": []}
    doc["samples"].append(sample)
    if len(doc["samples"]) > TREND_CAP:
        doc["samples"] = doc["samples"][-TREND_CAP:]
    cb_upsert(key, doc)


# ── slave-failure alerting (detect → notify → AI-triage; never acts) ─────────
def ollama_chat(messages):
    """POST a chat to Ollama; return the assistant text or None. Analysis only."""
    if not C.OLLAMA_URL:
        return None
    payload = json.dumps({
        "model": C.OLLAMA_MODEL, "messages": messages, "stream": False,
        "keep_alive": C.OLLAMA_KEEP_ALIVE,
        "options": {"temperature": 0.2, "num_predict": C.OLLAMA_NUM_PREDICT},
    }).encode("utf-8")
    req = urllib.request.Request(C.OLLAMA_URL.rstrip("/") + "/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=C.OLLAMA_TIMEOUT) as r:
            return A.parse_ollama(json.loads(r.read().decode("utf-8")))
    except Exception as e:
        log.warning("ollama analyze failed: %s", e)
        return None


def ollama_warm():
    """Load / keep the triage model resident. A CPU cold-load + full generation
    can push a triage past the timeout; a resident model keeps each alert warm
    (~1 min). Best-effort — a tiny 1-token /api/generate just to pin it in RAM."""
    if not C.OLLAMA_URL:
        return False
    payload = json.dumps({
        "model": C.OLLAMA_MODEL, "prompt": "ok", "stream": False,
        "keep_alive": C.OLLAMA_KEEP_ALIVE, "options": {"num_predict": 1},
    }).encode("utf-8")
    req = urllib.request.Request(C.OLLAMA_URL.rstrip("/") + "/api/generate", data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=C.OLLAMA_TIMEOUT) as r:
            r.read()
        return True
    except Exception as e:
        log.warning("ollama warm failed: %s", e)
        return False


def _warmer_loop():
    """Warm on startup, then re-warm every OLLAMA_WARM_SEC (< keep_alive) so the
    model never unloads between the hours-apart alerts."""
    warm = False
    while True:
        ok = ollama_warm()
        if ok and not warm:
            log.info("ollama model warmed & resident (%s)", C.OLLAMA_MODEL)
        warm = ok
        time.sleep(max(60, C.OLLAMA_WARM_SEC))


def slack_workflow(payload):
    """POST a flat JSON of string vars to the Slack Workflow webhook. The
    workflow (built in Slack) owns channel/recipients/message layout."""
    if not C.SLACK_WORKFLOW_URL:
        log.info("SLACK_WORKFLOW_URL not set — skipping Slack notify")
        return False
    req = urllib.request.Request(C.SLACK_WORKFLOW_URL, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        return True
    except Exception as e:
        log.warning("slack notify failed: %s", e)
        return False


def _agent_url(master, name):
    return "%s/computer/%s/" % (master["base"].rstrip("/"), urllib.parse.quote(name))


def _build_snippet(master, agent):
    """Fetch → extract → redact the console signal for the agent's last N failing
    builds. Returns a compact, secret-scrubbed string safe to send off-box."""
    mk = master["key"]
    fails = [b for b in (agent.get("builds") or []) if b.get("result") == "FAILURE"][-C.LOG_BUILDS:]
    chunks = []
    for b in fails:
        try:
            raw = fetch_console_tail(master, b["job"], b["num"], C.LOG_TAIL_BYTES)
        except Exception as e:
            log.warning("[%s] console fetch %s#%s failed: %s", mk, b.get("job"), b.get("num"), e)
            continue
        sig = A.redact(A.extract_signal(raw, C.LOG_MAX_LINES), C.REDACT_LITERALS, C.REDACT_IPS)
        if sig.strip():
            chunks.append("### %s #%s\n%s" % (b["job"], b["num"], sig))
    return "\n\n".join(chunks) if chunks else "(no stack trace / infra markers extracted)"


def _fire_alert(master, agent, incident, key, prev, now_ms):
    mk, name = master["key"], agent["name"]
    snippet = _build_snippet(master, agent)
    analysis = ollama_chat(A.ollama_messages(name, mk, incident, snippet)) if C.OLLAMA_URL else None
    notified = slack_workflow(A.workflow_payload(mk, name, incident, analysis, _agent_url(master, name)))
    cb_upsert(key, {
        "type": "slavealert", "master": mk, "name": name, "status": "firing",
        "streak": incident["streak"], "jobs": incident["jobs"], "builds": incident["builds"],
        "snippet": snippet, "analysis": analysis or "", "notified": bool(notified),
        "firstDetectedTs": (prev or {}).get("firstDetectedTs") or now_ms,
        "lastAlertTs": now_ms, "ts": now_ms,
    })
    with _alert_lock:
        firing[mk].add(name)
    log.warning("[%s] ALERT slave=%s streak=%d jobs=%s notified=%s ai=%s",
                mk, name, incident["streak"], ",".join(incident["jobs"]), notified, bool(analysis))


def _resolve_alert(master, name, now_ms):
    mk = master["key"]
    with _alert_lock:
        firing[mk].discard(name)
    key = "alert::%s::%s" % (mk, name)
    prev = cb_get(key)
    if not prev:
        return
    prev.update({"status": "resolved", "resolvedTs": now_ms, "ts": now_ms})
    cb_upsert(key, prev)
    if C.ALERT_NOTIFY_RECOVER:
        slack_workflow(A.recover_payload(mk, name, _agent_url(master, name)))
    log.info("[%s] RESOLVED slave=%s", mk, name)


def _alert_worker():
    """Single background worker: processes fire jobs serially so the slow Ollama
    calls never block the poll loop and never run concurrently (which would OOM
    the small box). One worker is enough — incidents are rare."""
    while True:
        item = _alert_q.get()
        try:
            master, agent, incident, key, prev, now_ms = item
            _fire_alert(master, agent, incident, key, prev, now_ms)
        except Exception as e:
            log.exception("alert worker error: %s", e)
        finally:
            try:
                mk, name = item[0]["key"], item[1]["name"]
                with _alert_lock:
                    _inflight[mk].discard(name)
            except Exception:
                pass
            _alert_q.task_done()


def _ensure_worker():
    global _worker_started
    if not _worker_started:
        threading.Thread(target=_alert_worker, name="alert-worker", daemon=True).start()
        _worker_started = True


def handle_alerts(master, agents, now_ms):
    """Per-cycle: enqueue fire jobs for newly-bad agents (processed off-thread so
    the poll loop never stalls), resolve recovered ones inline (fast). Edge-
    triggered + in-flight-guarded so it can't spam or double-process. The caller
    wraps this so it can never break ingestion."""
    if not C.ALERTS_ENABLED:
        return
    mk = master["key"]
    # only online agents — an offline agent has a stale ring and is already visible
    incidents = []
    for a in agents:
        if a.get("offline"):
            continue
        inc = A.find_incident(a.get("builds") or [], C.ALERT_K, C.ALERT_MIN_DISTINCT)
        if inc:
            incidents.append((a, inc))

    # systemic-outage guard: many agents failing at once is almost never per-slave
    # (it's a bad build / infra-wide blip). Skip entirely — including resolves —
    # so we neither spam nor mass-resolve during a wobble.
    if len(incidents) > C.ALERT_FLEET_SUPPRESS:
        log.warning("[%s] %d agents tripped at once (> %d) — likely systemic; suppressing per-slave alerts",
                    mk, len(incidents), C.ALERT_FLEET_SUPPRESS)
        return

    incident_names = {a["name"] for a, _ in incidents}
    for a, inc in incidents:
        name = a["name"]
        with _alert_lock:
            if name in _inflight[mk]:
                continue                       # already queued / being processed
            saturated = len(_inflight[mk]) >= C.ALERT_MAX_PER_CYCLE
        if saturated:
            log.info("[%s] alert worker saturated (%d in flight); deferring %s", mk, C.ALERT_MAX_PER_CYCLE, name)
            continue
        key = "alert::%s::%s" % (mk, name)
        prev = cb_get(key)
        if A.decide(prev, inc, now_ms, C.ALERT_REFIRE_SEC) in ("fire", "refire"):
            with _alert_lock:
                _inflight[mk].add(name)
            _ensure_worker()
            _alert_q.put((master, a, inc, key, prev, now_ms))

    # resolve (inline, cheap): anything we thought was firing that no longer has an incident
    with _alert_lock:
        recovered = list(firing[mk] - incident_names - _inflight[mk])
    for name in recovered:
        _resolve_alert(master, name, now_ms)


# ── one master cycle ─────────────────────────────────────────────────────────
def cycle_master(master, now_ms, write_samples):
    mk = master["key"]
    comp = jfetch(master, "/computer/api/json", COMPUTER_TREE)
    try:
        queue = len(jfetch(master, "/queue/api/json", "items[id]").get("items") or [])
    except Exception:
        queue = None
    lastbuilds = {j["name"]: j.get("lastBuild") for j in (jfetch(master, "/api/json", LASTBUILD_TREE).get("jobs") or []) if j.get("name")}

    update_rings(master, lastbuilds)

    agents = [norm_agent(mk, c, now_ms) for c in (comp.get("computer") or [])]
    for a in agents:
        cb_upsert("agent::%s::%s" % (mk, a["name"]), a)

    # fleet rollup
    counts = {"healthy": 0, "degraded": 0, "failing": 0, "offline": 0}
    for a in agents:
        counts[a["health"]] = counts.get(a["health"], 0) + 1
    all_builds = [b["result"] for a in agents for b in a["builds"]]
    considered = [r for r in all_builds if r in (PASS, UNSTABLE, FAIL)]
    fleet_success = round(sum(1 for r in considered if r == PASS) / len(considered) * 100) if considered else None
    fleet = {
        "type": "fleetnow", "master": mk, "ts": now_ms,
        "total": len(agents), **counts,
        "busyExec": comp.get("busyExecutors"), "totalExec": comp.get("totalExecutors"),
        "utilPct": round((comp.get("busyExecutors") or 0) / (comp.get("totalExecutors") or 1) * 100),
        "successPct": fleet_success, "queue": queue,
        "offlineNames": [a["name"] for a in agents if a["health"] == "offline"],
    }
    cb_upsert("fleetnow::%s" % mk, fleet)
    cb_upsert("jobcursor::%s" % mk, {"type": "cursor", "master": mk, "jobLast": job_last[mk], "ts": now_ms})

    try:
        handle_alerts(master, agents, now_ms)
    except Exception as e:
        log.exception("[%s] alert handling error: %s", mk, e)

    if write_samples:
        for a in agents:
            append_trend("trend::%s::%s" % (mk, a["name"]), {
                "ts": now_ms, "memPct": a["memPct"], "diskFreeGB": a["diskFreeGB"],
                "busy": a["busy"], "total": a["numExecutors"], "responseMs": a["responseMs"],
                "successPct": a["successPct"],
            })
        append_trend("trend::fleet::%s" % mk, {
            "ts": now_ms, "utilPct": fleet["utilPct"], "successPct": fleet_success,
            "queue": queue, "healthy": counts["healthy"], "degraded": counts["degraded"],
            "failing": counts["failing"], "offline": counts["offline"],
        })

    log.info("[%s] %d agents (%dh/%dd/%df/%doff) util=%s%% success=%s%% queue=%s builds_ringed=%d",
             mk, len(agents), counts["healthy"], counts["degraded"], counts["failing"], counts["offline"],
             fleet["utilPct"], fleet_success, queue, sum(len(r) for r in rings[mk].values()))


# ── dry-run: eyeball redaction on REAL logs before enabling (sends nothing) ──
def _leak_scan(text):
    """Heuristic post-redaction check: flag anything that still looks secret.
    Advisory only — long identifiers (git SHAs, UUIDs) may show up as false
    positives; the point is to make a human LOOK, not to be authoritative."""
    hits = []
    low = text.lower()
    for lit in C.REDACT_LITERALS:
        if lit and lit.lower() in low:
            hits.append("literal:%s" % lit)
    if re.search(r"(?i)authorization:\s*(?:basic|bearer)\s+[A-Za-z0-9+/=]{8,}", text):
        hits.append("auth-header")
    if re.search(r"://[^\s:/@]+:[^\s:/@]+@", text):
        hits.append("url-credentials")
    for m in re.findall(r"\b[A-Za-z0-9+/_\-]{32,}\b", text):
        if "REDACTED" not in m:
            hits.append("long-token:%s…" % m[:8])
    return hits


def dry_run(master_key, agent_name, use_ai=False):
    """Fetch a real agent's recent FAILURE consoles, run extract→redact, and
    print the redacted result + a leak-scan. No Slack, no Ollama (unless --ai),
    no Couchbase writes. Use this to confirm the scrubber before enabling."""
    master = next((m for m in C.MASTERS if m["key"] == master_key), None)
    if not master:
        raise SystemExit("unknown master '%s' — expected one of: %s"
                         % (master_key, ", ".join(m["key"] for m in C.MASTERS)))

    # resolve only the target master's Jenkins token (env → file → prompt)
    tok = C.token_for(master)
    if not tok:
        if not sys.stdin.isatty():
            raise SystemExit("no token for %s — set %s / create %s, or run attached"
                             % (master_key, master["token_env"], master["token_file"]))
        tok = getpass.getpass("Jenkins API token for %s (user %s): " % (master["label"], master["user"])).strip()
    _auth_hdr[master_key] = "Basic " + base64.b64encode(("%s:%s" % (master["user"], tok)).encode()).decode()

    coll()  # need Couchbase to read the agent's build ring
    doc = cb_get("agent::%s::%s" % (master_key, agent_name))
    if not doc:
        raise SystemExit("no agent doc 'agent::%s::%s' — name must match Jenkins displayName exactly"
                         % (master_key, agent_name))
    ring = doc.get("builds") or []
    print("agent %s::%s — ring has %d builds" % (master_key, agent_name, len(ring)))

    inc = A.find_incident(ring, C.ALERT_K, C.ALERT_MIN_DISTINCT)
    if inc:
        print("INCIDENT would fire: %d consecutive FAILURE across jobs: %s"
              % (inc["streak"], ", ".join(inc["jobs"])))
    else:
        recent_fails = sum(1 for b in ring[-C.ALERT_K:] if b.get("result") == "FAILURE")
        print("no incident under thresholds (K=%d, min_distinct=%d) — last-%d window has %d FAILURE"
              % (C.ALERT_K, C.ALERT_MIN_DISTINCT, C.ALERT_K, recent_fails))

    builds = [b for b in ring if b.get("result") == "FAILURE"][-C.LOG_BUILDS:]
    if not builds:
        builds = ring[-C.LOG_BUILDS:]
        print("(no FAILURE builds in ring — showing last %d of any result to eyeball redaction)" % len(builds))

    chunks = []
    for b in builds:
        print("\n" + "=" * 72)
        print("BUILD  %s #%s  (result=%s)" % (b.get("job"), b.get("num"), b.get("result")))
        print("=" * 72)
        try:
            raw = fetch_console_tail(master, b["job"], b["num"], C.LOG_TAIL_BYTES)
        except Exception as e:
            print("  console fetch failed: %s" % e)
            continue
        red = A.redact(A.extract_signal(raw, C.LOG_MAX_LINES), C.REDACT_LITERALS, C.REDACT_IPS)
        print("--- extracted + REDACTED (exactly what would be sent off-box) ---")
        print(red or "(nothing extracted)")
        if red.strip():
            chunks.append("### %s #%s\n%s" % (b.get("job"), b.get("num"), red))
        leaks = _leak_scan(red)
        print("\n  " + ("⚠️  POSSIBLE LEAKS (verify by eye): " + ", ".join(leaks) if leaks else "✓ leak-scan clean"))

    if use_ai:
        snippet = "\n\n".join(chunks) or "(none)"
        inc_ai = inc or {"streak": len(builds), "jobs": list(dict.fromkeys(b.get("job") for b in builds))}
        print("\n" + "=" * 72 + "\nAI PREVIEW (redacted input only; nothing sent to Slack, no CB write)\n" + "=" * 72)
        print(ollama_chat(A.ollama_messages(agent_name, master_key, inc_ai, snippet)) or "(ollama unavailable)")

    print("\nDRY RUN complete — no Slack sent, no Couchbase alert docs written.")


def main():
    log.info("slaves-collector starting — masters=%s bucket=%s poll=%ds sample=%ds",
             [m["key"] for m in C.MASTERS], C.CB_BUCKET, C.STATE_POLL_SEC, C.SAMPLE_EVERY_SEC)
    if C.ALERTS_ENABLED:
        log.info("alerting ON — K=%d min_distinct=%d fleet_suppress=%d | ollama=%s | slack=%s",
                 C.ALERT_K, C.ALERT_MIN_DISTINCT, C.ALERT_FLEET_SUPPRESS,
                 "set" if C.OLLAMA_URL else "off (alerts without AI note)",
                 "set" if C.SLACK_WORKFLOW_URL else "MISSING (will log-only, no Slack!)")
    else:
        log.info("alerting OFF — set SLAVES_ALERTS_ENABLED=true to enable")
    resolve_tokens()   # env → file → interactive prompt (before any Jenkins call)
    coll()
    seed_from_cb()
    if C.ALERTS_ENABLED and C.OLLAMA_URL and C.OLLAMA_WARM_SEC > 0:
        threading.Thread(target=_warmer_loop, name="ollama-warmer", daemon=True).start()
        log.info("ollama warmer on — model=%s every %ds keep_alive=%s", C.OLLAMA_MODEL, C.OLLAMA_WARM_SEC, C.OLLAMA_KEEP_ALIVE)
    global _last_sample_at
    while True:
        now = time.time()
        now_ms = int(now * 1000)
        write_samples = (now - _last_sample_at) >= C.SAMPLE_EVERY_SEC
        for m in C.MASTERS:
            try:
                cycle_master(m, now_ms, write_samples)
            except Exception as e:
                log.exception("[%s] cycle error: %s", m["key"], e)
        if write_samples:
            _last_sample_at = now
        time.sleep(C.STATE_POLL_SEC)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 2 and sys.argv[1] == "--dry-run":
            if len(sys.argv) < 4:
                raise SystemExit("usage: python collector.py --dry-run <master> <agent-name> [--ai]")
            dry_run(sys.argv[2], sys.argv[3], use_ai=("--ai" in sys.argv[4:]))
        else:
            main()
    except KeyboardInterrupt:
        sys.exit(0)
