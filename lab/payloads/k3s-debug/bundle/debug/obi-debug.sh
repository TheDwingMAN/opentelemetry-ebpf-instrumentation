#!/usr/bin/env bash
# Follows OBI's metrics from OBI to the OpenTelemetry Collector (and ClickHouse) and says where
# they stop. It only reads: pods, logs, the ConfigMap and metrics (through kubectl port-forward).
#
#   ./obi-debug.sh
#   COLLECTOR_NAMESPACE=otel COLLECTOR_SELECTOR=app.kubernetes.io/name=otel-collector ./obi-debug.sh
#   CLICKHOUSE_URL='http://user:password@clickhouse.example:8123' ./obi-debug.sh
#
# Needs kubectl, with access to OBI's (and the collector's) namespace, and curl. Without
# COLLECTOR_SELECTOR it looks for a pod running an otelcol image.
set -u

OBI_NAMESPACE=${OBI_NAMESPACE:-obi}
OBI_SELECTOR=${OBI_SELECTOR:-app.kubernetes.io/name=obi}
OBI_POD=${OBI_POD:-}
COLLECTOR_NAMESPACE=${COLLECTOR_NAMESPACE:-}
COLLECTOR_SELECTOR=${COLLECTOR_SELECTOR:-}
COLLECTOR_POD=${COLLECTOR_POD:-}
COLLECTOR_METRICS_PORT=${COLLECTOR_METRICS_PORT:-8888}
CLICKHOUSE_URL=${CLICKHOUSE_URL:-}
CLICKHOUSE_DATABASE=${CLICKHOUSE_DATABASE:-otel}

FORWARDS=()
TAB=$(printf '\t')
cleanup() { for pid in ${FORWARDS[@]+"${FORWARDS[@]}"}; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT

section() { printf '\n== %s\n' "$1"; }
ok() { printf '  OK    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

# verdict <priority> <text>: keeps the one closest to OBI (lowest priority), where the metrics stop first
VERDICT=""
VERDICT_PRIORITY=99
verdict() { if [ "$1" -lt "$VERDICT_PRIORITY" ]; then VERDICT_PRIORITY=$1; VERDICT=$2; fi; }

# forward <namespace> <pod> <port>: forwards a free local port to the pod's port, sets FWD_PORT
forward() {
  local port=$((20000 + RANDOM % 20000))
  kubectl -n "$1" port-forward "pod/$2" "$port:$3" >/dev/null 2>&1 &
  FORWARDS+=($!)
  FWD_PORT=$port
  for _ in $(seq 1 30); do
    curl -s -o /dev/null "http://127.0.0.1:$port/" && return 0
    sleep 0.5
  done
  return 1
}

# yaml_block <key>: the uncommented top-level block <key>: of the config, without the key line
yaml_block() {
  awk -v key="$1:" '
    $0 ~ "^"key { inside = 1; next }
    inside && /^[^ #]/ { inside = 0 }
    inside && /^[ ]+[^ #]/ { print }
  ' <<< "$CONFIG"
}

# yaml_value <block text> <key>: the value of the first "key: value" line
yaml_value() { sed -n "s/^ *$2: *\"\{0,1\}\([^\"#]*\)\"\{0,1\}.*/\1/p" <<< "$1" | head -1 | tr -d ' '; }

# sum_metric <metrics text> <name regexp> [label filter regexp]: sums the samples
sum_metric() {
  awk -v name="^($2)[{ ]" -v filter="${3:-}" '
    $0 ~ name && (filter == "" || $0 ~ filter) { s += $NF; n++ }
    END { if (n) printf "%.0f", s; else print "" }
  ' <<< "$1"
}

# per_label <metrics text> <name regexp> <label>: "value total" per value of the label
per_label() {
  awk -v name="^($2)[{]" -v label="$3" '
    $0 ~ name {
      v = "?"
      if (match($0, label "=\"[^\"]*\"")) v = substr($0, RSTART + length(label) + 2, RLENGTH - length(label) - 3)
      s[v] += $NF
    }
    END { for (v in s) printf "%s %.0f\n", v, s[v] }
  ' <<< "$1" | sort
}

######## 1. OBI pods
section "1. OBI pods (namespace $OBI_NAMESPACE, selector $OBI_SELECTOR)"
PODS=$(kubectl -n "$OBI_NAMESPACE" get pods -l "$OBI_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.phase}{" "}{.spec.nodeName}{" "}{.status.containerStatuses[0].restartCount}{" "}{.status.containerStatuses[0].lastState.terminated.reason}{"\n"}{end}' 2>&1)
if [ -z "$PODS" ] || ! grep -q ' Running ' <<< "$PODS"; then
  bad "no running OBI pod"
  note "${PODS:-no pods}"
  note "kubectl -n $OBI_NAMESPACE describe ds; kubectl -n $OBI_NAMESPACE get events --sort-by=.lastTimestamp"
  exit 1
fi
while read -r name phase node restarts reason; do
  line="$name $phase on $node, restarts: ${restarts:-0}"
  [ -n "$reason" ] && line="$line (last exit: $reason)"
  if [ "$phase" = Running ] && [ "${restarts:-0}" = 0 ]; then ok "$line"; else bad "$line"; fi
done <<< "$PODS"
[ -z "$OBI_POD" ] && OBI_POD=$(awk '$2 == "Running" { print $1; exit }' <<< "$PODS")
note "checking $OBI_POD (set OBI_POD to check another one)"
if [ "$(awk -v p="$OBI_POD" '$1 == p { print $4 }' <<< "$PODS")" != 0 ]; then
  note "logs before its last restart: kubectl -n $OBI_NAMESPACE logs $OBI_POD --previous"
fi

######## 2. OBI configuration
section "2. OBI configuration"
CONFIGMAP=$(kubectl -n "$OBI_NAMESPACE" get pod "$OBI_POD" -o jsonpath='{.spec.volumes[*].configMap.name}' | awk '{ print $1 }')
CONFIG=""
if [ -n "$CONFIGMAP" ]; then
  CONFIG=$(kubectl -n "$OBI_NAMESPACE" get configmap "$CONFIGMAP" -o go-template='{{range $k, $v := .data}}{{$v}}{{"\n"}}{{end}}')
  note "ConfigMap $CONFIGMAP"
fi
ENV=$(kubectl -n "$OBI_NAMESPACE" get pod "$OBI_POD" -o jsonpath='{range .spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}')
env_value() { sed -n "s/^$1=//p" <<< "$ENV" | head -1; }

FEATURES=$(awk '/^metrics:/ { m = 1; next } m && /^[^ #]/ { m = 0 } m && /^ +- / { printf "%s ", $2 }' <<< "$CONFIG")
note "metrics.features: ${FEATURES:-none}"
[ -n "$(env_value OTEL_EBPF_METRICS_FEATURES)" ] && note "OTEL_EBPF_METRICS_FEATURES=$(env_value OTEL_EBPF_METRICS_FEATURES)"

OTLP_BLOCK=$(yaml_block otel_metrics_export)
OTLP_ENDPOINT=$(env_value OTEL_EXPORTER_OTLP_METRICS_ENDPOINT)
[ -z "$OTLP_ENDPOINT" ] && OTLP_ENDPOINT=$(yaml_value "$OTLP_BLOCK" endpoint)
[ -z "$OTLP_ENDPOINT" ] && OTLP_ENDPOINT=$(env_value OTEL_EXPORTER_OTLP_ENDPOINT)
OTLP_PROTOCOL=$(env_value OTEL_EXPORTER_OTLP_METRICS_PROTOCOL)
[ -z "$OTLP_PROTOCOL" ] && OTLP_PROTOCOL=$(env_value OTEL_EXPORTER_OTLP_PROTOCOL)
[ -z "$OTLP_PROTOCOL" ] && OTLP_PROTOCOL=$(yaml_value "$OTLP_BLOCK" protocol)
if [ -z "$OTLP_ENDPOINT" ]; then
  bad "OBI sends no OTLP: otel_metrics_export has no endpoint (it is commented out in the bundle)"
  note "and no OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT variable is set"
  verdict 3 "OBI doesn't send OTLP to the collector: uncomment otel_metrics_export in obi-config.yaml, set the collector address (http://<collector>:4318, protocol http/protobuf) and apply it again (or have the collector scrape OBI's port instead)"
else
  ok "OTLP endpoint: $OTLP_ENDPOINT, protocol: ${OTLP_PROTOCOL:-guessed from the port}"
  port=$(sed -n 's#^[a-z]*://[^/:]*:\([0-9]*\).*#\1#p' <<< "$OTLP_ENDPOINT")
  case "$port:$OTLP_PROTOCOL" in
    *4317:http*) bad "port $port is usually OTLP/gRPC, but the protocol is $OTLP_PROTOCOL" ;;
    *4318:grpc) bad "port $port is usually OTLP/HTTP, but the protocol is grpc" ;;
  esac
  protocol=$OTLP_PROTOCOL
  [ -z "$protocol" ] && case "$port" in *4317) protocol=grpc ;; *) protocol=http/protobuf ;; esac
  # OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is the whole URL: without /v1/metrics, OBI posts to / and
  # the collector answers 404. The YAML endpoint and OTEL_EXPORTER_OTLP_ENDPOINT get the path added.
  if [ -n "$(env_value OTEL_EXPORTER_OTLP_METRICS_ENDPOINT)" ] && [ "$protocol" != grpc ] &&
    [[ "$OTLP_ENDPOINT" != */v1/metrics ]]; then
    bad "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is used as the whole URL, and it doesn't end in /v1/metrics"
    verdict 3 "OBI posts its metrics to the wrong path and the collector answers 404: set OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=${OTLP_ENDPOINT%/}/v1/metrics (or use OTEL_EXPORTER_OTLP_ENDPOINT or otel_metrics_export.endpoint, which get the path added)"
  fi
fi

PROM_BLOCK=$(yaml_block prometheus_export)
PROM_PORT=$(env_value OTEL_EBPF_PROMETHEUS_PORT)
[ -z "$PROM_PORT" ] && PROM_PORT=$(yaml_value "$PROM_BLOCK" port)
PROM_PATH=$(env_value OTEL_EBPF_PROMETHEUS_PATH)
[ -z "$PROM_PATH" ] && PROM_PATH=$(yaml_value "$PROM_BLOCK" path)
PROM_PATH=${PROM_PATH:-/metrics}

INTERNAL_BLOCK=$(yaml_block internal_metrics)
INTERNAL_EXPORTER=$(env_value OTEL_EBPF_INTERNAL_METRICS_EXPORTER)
[ -z "$INTERNAL_EXPORTER" ] && INTERNAL_EXPORTER=$(yaml_value "$INTERNAL_BLOCK" exporter)
INTERNAL_PORT=$(env_value OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT)
[ -z "$INTERNAL_PORT" ] && INTERNAL_PORT=$(yaml_value "$INTERNAL_BLOCK" port)
INTERNAL_PATH=$(env_value OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH)
[ -z "$INTERNAL_PATH" ] && INTERNAL_PATH=$(yaml_value "$INTERNAL_BLOCK" path)
INTERNAL_PATH=${INTERNAL_PATH:-/internal/metrics}

######## 3. OBI logs
section "3. OBI logs"
LOGS=$(kubectl -n "$OBI_NAMESPACE" logs "$OBI_POD" --tail=5000 2>&1)
if grep -q 'starting OBI in Stat metrics mode' <<< "$LOGS"; then
  ok "the stats agent started"
else
  bad "no 'starting OBI in Stat metrics mode' in the logs: the storage metrics are not running"
  verdict 1 "OBI doesn't run its stats agent: check metrics.features and the logs"
fi
PROBLEMS=$(grep -iE 'level=(warn|error)|failed to upload|exporting failed|connection refused|no such host|deadline exceeded|x509|unauthorized|forbidden' <<< "$LOGS" |
  sed -E 's/^time=[^ ]+ //' | cut -c1-220 | sort | uniq -c | sort -rn | head -15)
if grep -q 'failed to upload metrics' <<< "$LOGS"; then
  bad "OBI fails to send metrics to the collector ('failed to upload metrics' below)"
  verdict 5 "OBI can't deliver to the collector ($OTLP_ENDPOINT): see the 'failed to upload metrics' lines in the OBI logs above. connection refused or no such host: wrong address or port; 404 Not Found: wrong URL path; deadline exceeded: no answer in time (wrong protocol for the port, a network policy, or a collector that refuses the data)"
fi
if [ -n "$PROBLEMS" ]; then
  note "warnings and errors (count, message):"
  sed 's/^/          /' <<< "$PROBLEMS"
else
  ok "no warnings or errors"
fi

######## 4. What OBI measures and exports
section "4. OBI's own metrics endpoints"
STAT_SERIES=""
if [ -n "$PROM_PORT" ] && [ "$PROM_PORT" != 0 ]; then
  if forward "$OBI_NAMESPACE" "$OBI_POD" "$PROM_PORT"; then
    PROM=$(curl -s "http://127.0.0.1:$FWD_PORT$PROM_PATH")
    STAT_SERIES=$(grep -c '^obi_stat_' <<< "$PROM")
    NAMES=$(grep '^obi_stat_' <<< "$PROM" | sed -E 's/[{ ].*//; s/_(bucket|sum|count)$//' | sort -u)
    if [ "$STAT_SERIES" -gt 0 ]; then
      ok "OBI measures: $STAT_SERIES obi_stat_* series, $(wc -l <<< "$NAMES") metrics on :$PROM_PORT$PROM_PATH"
      sed 's/^/          /' <<< "$NAMES" | head -20
    else
      bad "no obi_stat_* series on :$PROM_PORT$PROM_PATH"
      verdict 2 "OBI measures nothing: no obi_stat_* series (check the features, the image and the logs)"
    fi
  else
    bad "can't reach OBI's Prometheus port $PROM_PORT through kubectl port-forward"
  fi
else
  note "prometheus_export is off: can't see what OBI measures"
fi

EXPORTS=""
EXPORT_ERRORS=""
if [ "$INTERNAL_EXPORTER" = prometheus ] && [ -n "$INTERNAL_PORT" ]; then
  if forward "$OBI_NAMESPACE" "$OBI_POD" "$INTERNAL_PORT"; then
    INTERNAL=$(curl -s "http://127.0.0.1:$FWD_PORT$INTERNAL_PATH")
    EXPORTS=$(sum_metric "$INTERNAL" obi_otel_metric_exports_total)
    EXPORT_ERRORS=$(sum_metric "$INTERNAL" obi_otel_metric_export_errors_total)
    note "OTLP metric exports: ${EXPORTS:-0}, failed: ${EXPORT_ERRORS:-0}"
    if [ "${EXPORT_ERRORS:-0}" -gt 0 ]; then
      bad "OBI fails to send to the collector, by error type:"
      per_label "$INTERNAL" obi_otel_metric_export_errors_total error_type | sed 's/^/          /'
      verdict 5 "OBI can't deliver to the collector ($OTLP_ENDPOINT): see the 'failed to upload metrics' lines in the OBI logs above. connection refused or no such host: wrong address or port; 404 Not Found: wrong URL path; deadline exceeded: no answer in time (wrong protocol for the port, a network policy, or a collector that refuses the data)"
    elif [ "${EXPORTS:-0}" -gt 0 ]; then
      ok "OBI delivers its metrics to the collector"
    elif [ -n "$OTLP_ENDPOINT" ]; then
      bad "no OTLP export yet: OBI exports every 60 s by default; run this again in a minute"
    fi
  else
    bad "can't reach OBI's internal metrics port $INTERNAL_PORT"
  fi
else
  note "OBI's internal metrics are off, so this can't tell whether its OTLP exports succeed."
  note "To turn them on (restarts the OBI pods; they are served next to the storage metrics):"
  note "  kubectl -n $OBI_NAMESPACE set env ds/obi OTEL_EBPF_INTERNAL_METRICS_EXPORTER=prometheus \\"
  note "    OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT=${PROM_PORT:-9400}"
fi

######## 5. The collector
section "5. OpenTelemetry Collector"
if [ -z "$COLLECTOR_POD" ]; then
  if [ -n "$COLLECTOR_SELECTOR" ]; then
    COLLECTOR_POD=$(kubectl -n "${COLLECTOR_NAMESPACE:-default}" get pods -l "$COLLECTOR_SELECTOR" \
      --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  else
    found=$(kubectl get pods -A --field-selector=status.phase=Running \
      -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}' 2>/dev/null |
      grep -E 'otelcol|opentelemetry-collector' | head -1)
    COLLECTOR_NAMESPACE=$(awk '{ print $1 }' <<< "$found")
    COLLECTOR_POD=$(awk '{ print $2 }' <<< "$found")
  fi
fi
COLLECTOR_NAMESPACE=${COLLECTOR_NAMESPACE:-default}
if [ -z "$COLLECTOR_POD" ]; then
  note "no collector pod found: set COLLECTOR_NAMESPACE and COLLECTOR_SELECTOR (or COLLECTOR_POD)"
else
  note "checking $COLLECTOR_NAMESPACE/$COLLECTOR_POD"
  if forward "$COLLECTOR_NAMESPACE" "$COLLECTOR_POD" "$COLLECTOR_METRICS_PORT" &&
    COL=$(curl -sf "http://127.0.0.1:$FWD_PORT/metrics") && [ -n "$COL" ]; then
    ACCEPTED=$(sum_metric "$COL" 'otelcol_receiver_accepted_metric_points(_total)?')
    REFUSED=$(sum_metric "$COL" 'otelcol_receiver_refused_metric_points(_total)?')
    note "metric points received, per receiver:"
    per_label "$COL" 'otelcol_receiver_accepted_metric_points(_total)?' receiver | sed 's/^/          accepted /'
    per_label "$COL" 'otelcol_receiver_refused_metric_points(_total)?' receiver | awk '$2 > 0' | sed 's/^/          refused  /'
    note "metric points sent, per exporter:"
    per_label "$COL" 'otelcol_exporter_sent_metric_points(_total)?' exporter | sed 's/^/          sent     /'
    FAILED=$(per_label "$COL" 'otelcol_exporter_(send|enqueue)_failed_metric_points(_total)?' exporter | awk '$2 > 0')
    [ -n "$FAILED" ] && sed 's/^/          failed   /' <<< "$FAILED"
    if [ $((${ACCEPTED:-0} + ${REFUSED:-0})) = 0 ]; then
      bad "the collector received no metric points"
      verdict 6 "nothing reaches the collector: check OBI's endpoint ($OTLP_ENDPOINT), the collector Service and port, and that the metrics pipeline has the otlp receiver"
    fi
    FAILED_NAMES=$(awk '{ printf "%s%s", sep, $1; sep = ", " }' <<< "$FAILED")
    if [ -n "$FAILED" ]; then
      bad "the collector fails to send metrics to: $FAILED_NAMES"
    fi
    if [ "${REFUSED:-0}" -gt 0 ]; then
      bad "the collector refuses metric points: a processor (memory_limiter) or an exporter returns errors"
      note "an exporter without a sending_queue that fails makes the collector refuse the data, so OBI's"
      note "exports fail too, even when the other exporters of the pipeline wrote it"
    fi
    if [ -n "$FAILED" ] && [ "${REFUSED:-0}" -gt 0 ]; then
      verdict 4 "the collector can't write to $FAILED_NAMES and so refuses the metrics (the exporter has no sending_queue): fix that exporter (see the collector logs below) or give it a sending_queue"
    elif [ -n "$FAILED" ]; then
      verdict 4 "the collector receives the metrics but can't write them to $FAILED_NAMES: see its logs below"
    elif [ "${REFUSED:-0}" -gt 0 ]; then
      verdict 4 "the collector refuses the metrics: see its logs below (memory_limiter, or an exporter that fails)"
    fi
  else
    bad "can't read the collector's own metrics on port $COLLECTOR_METRICS_PORT"
    note "turn them on in the collector config (service.telemetry.metrics.readers, pull, prometheus"
    note "exporter on port 8888) or set COLLECTOR_METRICS_PORT"
  fi
  COL_LOGS=$(kubectl -n "$COLLECTOR_NAMESPACE" logs "$COLLECTOR_POD" --tail=2000 2>&1 |
    grep -iE "\"level\":\"(warn|error)\"|${TAB}(warn|error)${TAB}|exporting failed|dropping|refused" |
    sed -E 's/^[0-9TZ:.+-]+[[:space:]]+//' | cut -c1-220 | sort | uniq -c | sort -rn | head -10)
  if [ -n "$COL_LOGS" ]; then
    note "collector warnings and errors (count, message):"
    sed 's/^/          /' <<< "$COL_LOGS"
  else
    ok "no warnings or errors in the collector logs"
  fi
fi

######## 6. ClickHouse
section "6. ClickHouse"
TABLES_SQL="SELECT database, name, total_rows FROM system.tables WHERE name LIKE 'otel_metrics%' ORDER BY database, name"
if [ -z "$CLICKHOUSE_URL" ]; then
  note "set CLICKHOUSE_URL (the HTTP interface, e.g. http://user:password@host:8123) to check it, or run:"
  note "  $TABLES_SQL;"
  note "  SELECT MetricName, count(), max(TimeUnix) FROM $CLICKHOUSE_DATABASE.otel_metrics_sum"
  note "  WHERE MetricName LIKE 'obi%' GROUP BY MetricName;   -- and otel_metrics_histogram"
else
  ch() { curl -s "$CLICKHOUSE_URL/" --data-binary "$1 FORMAT TSV"; }
  TABLES=$(ch "$TABLES_SQL")
  if [ -z "$TABLES" ] || grep -q 'Exception' <<< "$TABLES"; then
    bad "no otel_metrics tables${TABLES:+: $TABLES}"
    verdict 7 "ClickHouse has no metrics tables: check the exporter's database and create_schema"
  else
    note "metrics tables (database, table, rows):"
    sed 's/^/          /' <<< "$TABLES"
    OBI_ROWS=""
    while read -r db table _; do
      rows=$(ch "SELECT MetricName, count(), max(TimeUnix) FROM $db.$table WHERE MetricName LIKE 'obi%' GROUP BY MetricName ORDER BY MetricName")
      [ -n "$rows" ] && OBI_ROWS+="$(sed "s/^/$db.$table /" <<< "$rows")"$'\n'
    done <<< "$TABLES"
    if [ -n "$OBI_ROWS" ]; then
      ok "OBI metrics in ClickHouse (table, metric, rows, latest):"
      sed '/^$/d; s/^/          /' <<< "$OBI_ROWS" | head -30
      note "names are the OpenTelemetry ones (obi.stat.disk.io) when OBI sends OTLP, and the Prometheus"
      note "ones (obi_stat_disk_io_bytes_total) when the collector scrapes OBI"
    else
      bad "no metric named obi* in any otel_metrics table"
      verdict 7 "the metrics don't reach ClickHouse: check the collector's metrics pipeline and exporter"
    fi
  fi
fi

section "Result"
if [ -n "$VERDICT" ]; then
  echo "  $VERDICT"
else
  echo "  No break found along the way. If you still see nothing, check the database, table and"
  echo "  metric names you query (MetricName LIKE 'obi%'), and the time range."
fi
