---
name: grafana-investigation
description: Investigate a firing alert through the Grafana MCP server — establish onset, read what the alert rule measures, and find what else moved. Use after alert-triage selects an alert.
---

# Grafana Investigation

Grafana is reached through MCP tools, not HTTP. You hold no Grafana credential
and never construct a Grafana URL: the MCP server holds the credential and you
call tools on it.

Your reach is the tool allowlist in the sandbox policy. Everything in it reads;
nothing writes. A call to a tool outside the list is refused at the proxy before
it reaches the server — that is a boundary, not an obstacle, so report it rather
than looking for another route to the same effect.

Run `tools/list` once if you need the exact argument shapes. Tool names below
are the ones you may call.

## Order of operations

Work outside in. Most investigations end at step 3.

### 1. Confirm what the alert actually measures

Do not trust the alert's title. Read the rule:

- `list_alert_groups` — what is firing now.
- `get_alert_group` — the rule behind a specific group, including its query.

An alert named "high error rate" frequently measures something narrower: one
route, one status class, a ratio with a particular denominator. Investigating
the name rather than the query is the most common wasted cycle.

### 2. Establish onset

Get the transition time and hold on to it. Onset is the single most valuable
fact you can establish — nearly every later correlation is anchored to it.
"Sometime this morning" is not onset.

### 3. Query the data

- `query_prometheus` for metrics. Give it the datasource UID, the expression,
  and a window that comfortably contains onset.
- `list_datasources` / `get_datasource` when you need the UID.
- `list_prometheus_metric_names`, `list_prometheus_label_names`,
  `list_prometheus_label_values` when you are unsure a series exists before
  querying it.

**Borrow the humans' queries first.** Before writing your own PromQL:

- `search_dashboards` for the service name.
- `get_dashboard_panel_queries` on the most relevant dashboard.

Those queries encode which metrics and labels actually matter here. A borrowed
query is more trustworthy than an invented one, and it is faster.

### 4. Find what else moved

A symptom is not a cause. Correlate:

- **Deploys**: `get_annotations` across the onset window. Deploy markers are
  commonly annotations, and a marker minutes before onset is the strongest lead
  available without touching code.
- **Incidents already open**: `list_incidents`, `get_incident` — someone may
  already be on this, which changes your job to adding evidence rather than
  duplicating it. `get_current_oncall_users` tells you who.
- **Neighbours**: latency, saturation, and error rate for the same service, and
  the same for its immediate dependencies. A dependency that moved first
  relocates the investigation.
- **Scope**: one instance, one region, one route, or everything? A single
  instance is usually infrastructure; everything at once is usually a deploy or
  a dependency.

### 5. Logs

- `query_loki_logs` — narrow to the onset window and the implicated service.
- `query_loki_patterns` / `query_loki_stats` — shape of the log volume.
- `find_error_pattern_logs` and `find_slow_requests` — Grafana's own Sift
  helpers, which are often faster than hand-built LogQL.

Read a handful of real error lines. A stack trace beats another graph for
locating code.

## Stopping

Stop when the evidence stops, and say where you stopped. All of these are
legitimate outcomes:

- "Error rate rose at 14:02; a deploy annotation sits at 14:01; the commits in
  that deploy are X, Y, Z" — a strong lead, cause not yet proven.
- "Latency rose only on instance i-abc while its peers were flat" — points at
  infrastructure, not code.
- "The rule measures a ratio whose denominator collapsed; the numerator is
  unchanged" — the alert is arguably wrong, which is itself a finding.

Do not manufacture a cause to have one. "Correlated with deploy X, mechanism not
established" is a useful report. A confident wrong answer costs the on-call
engineer more than no answer.

## Recording what you ran

Name the tools and arguments you used in your summary. A human must be able to
re-run your investigation without reconstructing it, and the tool call is the
reproducible unit now — not a curl command.
