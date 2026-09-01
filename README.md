# slaves-collector

Standalone service that polls the Jenkins masters and persists agent/fleet
state + trend samples into the Couchbase **`slaves`** bucket. greenboard-v2's
Fleet tab reads from there — so the Jenkins API tokens live **only here**, never
on the greenboard host. Read-only against Jenkins; writes only to `slaves`.

## What it writes (key-prefixed in `slaves._default`)

| Key | Cadence | Contents |
|---|---|---|
| `agent::<master>::<name>` | every poll (~60s) | current state: labels, online/offline + cause, executors busy/total, running jobs, memory, disk, arch, response time, **last-20 builds ring**, success %, health |
| `trend::<master>::<name>` | every sample (~5m) | rolling per-agent samples (mem %, disk free, busy, response ms, success %) — capped at 2016 (~7d) |
| `trend::fleet::<master>` | every sample (~5m) | rolling fleet KPI samples (util %, success %, queue, health counts) |
| `fleetnow::<master>` | every poll | current fleet rollup (counts, util, success, queue, offline names) |
| `jobcursor::<master>` | every poll | last-seen build number per job (collector state, for restart resume) |

`master` is `qe` or `qa`.

## How the last-20-builds work (the important bit)

Jenkins has no per-agent build history API, but each build exposes `builtOn`
(the agent). Instead of the 67s fleet crawl, the collector polls **every job's
*latest* build** in one 2.3s call (`/api/json?tree=jobs[name,lastBuild[number,result,timestamp,builtOn]]`),
tracks the last-seen build number per job, and appends new finished builds to a
per-agent ring (last 20). New agents/jobs are seed-backfilled a few per cycle
(busiest first) so rings fill fast without a stampede. Rings + cursors persist,
so a restart resumes without re-crawling.

## Health model

`offline` → offline. Else `failing` if ≥3 of the last 8 builds FAILED; else
`degraded` if any recent fail OR disk < 25 GB OR mem > 82 % OR ping > 1500 ms;
else `healthy`. (Thresholds in `config.py`.)

## Setup (on the collector VM, 172.23.124.17)

```bash
# 1. place the code (git pull / copy) e.g. /root/slaves-collector
cd /root/slaves-collector

# 2. venv + deps (only couchbase; HTTP uses stdlib urllib)
python3 -m venv env && source env/bin/activate
pip install -r requirements.txt

# 3. create the GSI index once
python create_index.py

# 4. run under screen — RECOMMENDED: start ATTACHED so it prompts for the tokens
#    (kept in memory only, nothing on disk), then detach with Ctrl-A D.
screen -S slaves            # attach a new session
source env/bin/activate
export SLAVES_CB_PASS=…      # Couchbase admin password — never stored in source
python collector.py
#    → paste the qe token, then the qa token, at the hidden prompts. Ctrl-A D to detach.
```

## Where the tokens come from (no plaintext file needed)

Resolution order per master: **env var → token file → interactive prompt**. Pick one:

- **Prompt (recommended — nothing persisted):** don't set env or files. Start the
  collector *attached* in a screen; it asks for each token at a hidden prompt and
  holds it in memory only. Re-paste on restart (rare). Users: qe→`nishanth-vm`, qa→`nishanth`.
- **Transient env:** `export JENKINS_QE_TOKEN=… JENKINS_QA_TOKEN=…` in the launching
  shell, then start. Nothing on disk, but visible in `/proc/<pid>/environ` to root and
  gone on reboot.
- **File (least private):** `qe_token.txt` / `qa_token.txt` (chmod 600) in this dir.
  Gitignored, but a plaintext secret on disk — avoid unless you want zero-touch restarts.

> Honest caveat: the collector runs as root, so root can always read the live
> process. These options prevent a *plaintext secret sitting on disk* (casual `cat`,
> backups, accidental commits) — not a determined root reading process memory.

If started detached with no env/file, it exits immediately with guidance instead
of hanging on an unanswerable prompt.

## Configuration (env overrides, all optional)

| Var | Default | Meaning |
|---|---|---|
| `SLAVES_CB_HOST` / `SLAVES_CB_USER` / `SLAVES_CB_PASS` / `SLAVES_CB_BUCKET` | `172.23.105.219` / `Administrator` / _(no default — set it)_ / `slaves` | Couchbase target. **Namespaced on purpose** — a global `CB_PASS` in the shell profile must not override it. The password has no source default; export `SLAVES_CB_PASS` at launch. |
| `JENKINS_QE_TOKEN` / `JENKINS_QA_TOKEN` | — | token via env instead of file |
| `JENKINS_QE_TOKEN_FILE` / `JENKINS_QA_TOKEN_FILE` | `./qe_token.txt` / `./qa_token.txt` | token file paths |
| `SLAVES_POLL_SEC` | `60` | state + build-history cycle |
| `SLAVES_SAMPLE_SEC` | `300` | trend-sample cadence |
| `SLAVES_BUILD_RING` | `20` | builds kept per agent |

> Note: on the collector VM, Couchbase KV ops are sub-ms; a full cycle over both
> masters (~230 agents) completes in seconds. (From a laptop over VPN each KV op
> is ~500ms, so local test cycles are slow — that's expected.)

The control panel can monitor this like the others (screen `slaves`, pattern
`collector.py` under `/root/slaves-collector`).

## Slave-failure alerting (detect a bad agent → Slack + AI triage)

When an agent's **last K builds are ALL `FAILURE`** (default K=5), the collector
posts a Slack heads-up and attaches an Ollama triage note ("infra or test? why?
what to check?"). It **never takes an agent offline** — a human decides. It's
read-only against Jenkins by design, so it *structurally can't* act.

Pipeline (only runs when an agent actually trips — rare, so it's off the hot path):

1. **Detect** — last K ring builds all `FAILURE`, spanning **≥2 distinct jobs**
   (`ALERT_MIN_DISTINCT`). The distinct-jobs guard kills the big false positive:
   one broken suite landing on an agent K times looks like a bad slave but isn't.
2. **Systemic guard** — if **> `ALERT_FLEET_SUPPRESS`** agents trip in the same
   cycle it's almost never per-slave (bad build / infra-wide blip), so it stays
   quiet instead of paging for each.
3. **Capture** — fetch only the **tail** of the last `LOG_BUILDS` failing builds'
   console (via Jenkins `progressiveText`, never the whole multi-MB log).
4. **Extract** — keep only Python traceback blocks + infra-error lines, capped at
   `LOG_MAX_LINES` per build (~30). High signal, tiny payload.
5. **Redact** — scrub secrets (passwords, tokens, basic-auth, `user:pass@host`
   URLs, AWS keys, PEM keys — plus any literals in `SLAVES_REDACT_LITERALS`, e.g.
   your cluster password) **before anything leaves the box**. Internal `172.23.*`
   IPs are kept (useful, not secret) unless `REDACT_IPS=true`.
6. **Analyze** — POST the redacted snippet to Ollama (`/api/chat`); store the reply.
7. **Classify → notify (or drop)** — this channel is for *problematic slaves* only.
   If the AI verdict is **`test`** (a test/product bug, not the agent), the alert
   is **recorded but NOT sent to Slack**. Verdict `infra` / `unclear` / or AI
   unavailable → POST a flat JSON to the Slack **Workflow** webhook (err toward
   flagging real slave problems). Suppressed alerts also skip the "recovered" note.

Alerts are **edge-triggered + deduped**: fire once per incident (state in
`alert::<master>::<name>`), auto-resolve when a build passes again, and are capped
at `ALERT_MAX_PER_CYCLE` concurrent. The slow work (log fetch + Ollama — ~140s
cold on the CPU box) runs on a **single background worker**, so the 60s poll loop
never stalls and Ollama calls never overlap (which would OOM the small box). All
**OFF until `SLAVES_ALERTS_ENABLED=true`**.

### Enable it

```bash
export SLAVES_ALERTS_ENABLED=true
export OLLAMA_URL=http://172.23.217.9:11434        # the CPU VM (default already this)
export SLACK_WORKFLOW_URL_FILE=./slack_workflow.txt # or SLACK_WORKFLOW_URL=... (gitignored, never commit)
export SLAVES_REDACT_LITERALS=…                     # your cluster password(s) to scrub from logs
# on the Ollama VM, once:  ollama pull qwen2.5:7b-instruct
```

### Slack Workflow setup (one-time, in Slack)

Workflow Builder → new workflow → trigger **"From a webhook"** → declare these
variables, then add a "send message" step to your channel / the recipients and
lay the message out using them. Slack gives you the webhook URL to put above.

| Variable | Example |
|---|---|
| `slave` | `qe-slave-07` |
| `master` | `qe` |
| `streak` | `5` |
| `jobs` | `test_a, test_b, test_c` |
| `url` | link to the Jenkins agent page |
| `summary` | pre-formatted one-liner, e.g. `🔴 Build slave qe-slave-07 on qe — 5 consecutive failures across …` |
| `analysis` | pre-formatted triage block, e.g. `🔴  infra  ·  confidence: high` then `Why:` / `Do:` lines |

_Severity emoji, prepended by the collector: 🔴 infra · 🧪 test · ❓ unclear · ⚠️ unclassified. Slack renders variable values as plain text, so the message leans on emoji + structure rather than markdown._

### Dry-run — verify redaction on REAL logs before enabling

Confirm the scrubber catches secrets in actual QE console output (which may have
formats the synthetic tests don't) **before** any data leaves the box:

```bash
python collector.py --dry-run <master> <agent-name>       # e.g. --dry-run qe qe-slave-07
python collector.py --dry-run qe qe-slave-07 --ai          # also preview the Ollama triage
```

It reads the agent's build ring, fetches the real console of its recent FAILURE
builds, runs the full extract→redact pipeline, and prints **only the redacted
output** plus a heuristic leak-scan. **Sends nothing** to Slack, writes no CB
alert docs, and only calls Ollama if you pass `--ai`. Eyeball the output; if the
leak-scan flags anything real, add it to `SLAVES_REDACT_LITERALS` or tell us so
we tighten a pattern.

### Config knobs (env, all optional)

| Var | Default | Meaning |
|---|---|---|
| `SLAVES_ALERTS_ENABLED` | `false` | master on/off switch |
| `SLAVES_ALERT_K` | `5` | consecutive `FAILURE`s to trip |
| `SLAVES_ALERT_MIN_DISTINCT` | `2` | must span ≥N distinct jobs |
| `SLAVES_ALERT_MAX_PER_CYCLE` | `2` | cap heavy work per poll |
| `SLAVES_ALERT_FLEET_SUPPRESS` | `5` | >N agents at once → treat as systemic, stay quiet |
| `SLAVES_ALERT_REFIRE_SEC` | `0` | 0 = alert once until recovery; >0 = re-remind while firing |
| `SLAVES_ALERT_NOTIFY_RECOVER` | `true` | also post when an agent recovers |
| `SLAVES_LOG_TAIL_BYTES` | `262144` | console tail fetched per build |
| `SLAVES_LOG_MAX_LINES` | `30` | extracted lines per build |
| `SLAVES_LOG_BUILDS` | `2` | last N failing builds analyzed |
| `SLAVES_REDACT_LITERALS` | _(empty)_ | literal secrets to scrub, e.g. your cluster password (comma-sep) |
| `SLAVES_REDACT_IPS` | `false` | also mask `x.x.x.x` IPs |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `http://172.23.217.9:11434` / `qwen2.5:7b-instruct` | triage model (empty URL = alert without AI note) |
| `OLLAMA_TIMEOUT` | `300` | seconds; generous because a cold 7B on CPU takes ~140s (runs off-thread, so a long wait is free) |
| `OLLAMA_KEEP_ALIVE` | `30m` | keep model resident between alerts (`-1` = never unload; costs ~6GB RAM) |
