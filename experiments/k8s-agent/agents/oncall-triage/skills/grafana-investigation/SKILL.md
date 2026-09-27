---
name: grafana-investigation
description: Investigate a firing alert using the Grafana HTTP API — establish onset, read what the alert rule measures, and find what else moved. Use after alert-triage selects an alert.
---

# Grafana Investigation

Read-only. You can search, read dashboards and alert rules, query datasources,
and read annotations. You cannot create or edit anything, and attempting to is
refused at the proxy.

All calls use `$GRAFANA_API_KEY` as a bearer token against `grafana.url` from
the watch config. The value is a proxy-resolved placeholder — never print it.

```bash
curl -sS -H "Authorization: Bearer $GRAFANA_API_KEY" \
  "$GRAFANA_URL/api/search?query=checkout&type=dash-db"
```

## Order of operations

Work outside in. Most investigations end at step 3.

### 1. Confirm what the alert actually measures

Do not trust the alert's title. Fetch the rule and read its query:

```bash
curl -sS -H "Authorization: Bearer $GRAFANA_API_KEY" \
  "$GRAFANA_URL/api/v1/provisioning/alert-rules"
```

An alert named "high error rate" frequently measures something narrower — one
route, one status class, a ratio with a particular denominator. Investigating
the name instead of the query is the most common wasted cycle.

### 2. Establish onset

Get the transition time, then query a window that comfortably contains it —
`grafana.lookback_seconds` before, and through to now:

```bash
curl -sS -H "Authorization: Bearer $GRAFANA_API_KEY" \
  "$GRAFANA_URL/api/alertmanager/grafana/api/v2/alerts"
```

Onset is the single most valuable fact you can establish. Nearly every later
correlation — deploys, commits, config changes — is anchored to it. Get it
precisely before moving on: "sometime this morning" is not onset.

### 3. Query the data

Prefer `POST /api/ds/query` with the datasource UID. The query is a JSON body,
which is why it is a POST despite being a read:

```bash
curl -sS -X POST -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  "$GRAFANA_URL/api/ds/query" -d '{
    "queries": [{
      "refId": "A",
      "datasource": {"uid": "<uid>"},
      "expr": "sum(rate(http_requests_total{status=~\"5..\"}[5m]))",
      "intervalMs": 60000,
      "maxDataPoints": 200
    }],
    "from": "now-1h",
    "to": "now"
  }'
```

Discover UIDs with `GET /api/datasources` when the config does not name them.

**Borrow the humans' queries.** Before writing your own PromQL, look at the
dashboards the team already built for this service:
`GET /api/search?query=<service>` then `GET /api/dashboards/uid/<uid>`, and read
the panel targets. Those queries encode which metrics and labels actually
matter here. A borrowed query is more trustworthy than an invented one.

### 4. Find what else moved

An alert tells you a symptom. Causation needs correlation:

- **Deploys**: `GET /api/annotations?from=<ms>&to=<ms>` — deploy markers are
  commonly annotations. A marker minutes before onset is the strongest lead
  available without touching code.
- **Neighbours**: latency, saturation, and error rate for the same service, and
  the same metrics for its immediate dependencies. A dependency that moved
  first relocates the investigation.
- **Scope**: is it one instance, one region, one route, or everything? A single
  instance is usually infrastructure; everything at once is usually a deploy or
  a dependency.

### 5. Logs, if available

Query Loki through the datasource proxy or `/api/ds/query` with the Loki UID.
Narrow to the onset window and the implicated service. Read a handful of real
error lines; a stack trace beats another graph for locating code.

## Stopping

Stop when the evidence stops, and say where you stopped. These are all
legitimate outcomes:

- "Error rate rose at 14:02; a deploy annotation sits at 14:01; the commits in
  that deploy are X, Y, Z" — a strong lead, cause not yet proven.
- "Latency rose only on instance i-abc while its peers were flat" — points at
  infrastructure, not code.
- "The rule measures a ratio whose denominator collapsed; the numerator is
  unchanged" — the alert is arguably wrong, which is a finding worth reporting.

Do not manufacture a cause to have one. "Correlated with deploy X, mechanism not
established" is a useful report. A confident wrong answer costs the on-call
engineer more than no answer.
