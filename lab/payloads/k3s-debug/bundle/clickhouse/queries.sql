-- OBI storage metrics in ClickHouse, as the OpenTelemetry Collector's clickhouse exporter
-- stores them (database `otel`, default table names). Tested with otelcol-contrib 0.161.0
-- and ClickHouse 25.8.
--
-- Where the metrics are:
--   otel.otel_metrics_sum        counters (IsMonotonic = true): obi.stat.disk.io,
--                                obi.stat.disk.operations, obi.stat.disk.operation.time,
--                                obi.stat.disk.discard.io, obi.stat.nfs.client.io
--                                up-down counters (IsMonotonic = false):
--                                obi.stat.disk.pending_operations, obi.stat.k8s.pod.volume.device
--   otel.otel_metrics_histogram  obi.stat.disk.operation.duration, obi.stat.disk.queue.duration,
--                                obi.stat.disk.flush.duration, obi.stat.disk.discard.duration,
--                                obi.stat.fs.sync.duration, obi.stat.nfs.client.procedure.duration
--                                (otel_metrics_exponential_histogram instead, with
--                                histogram_aggregation: base2_exponential_bucket_histogram)
--
-- Attributes are in the Attributes map with their OpenTelemetry names (system.device,
-- disk.io.direction, k8s.namespace.name...). ResourceAttributes['host.id'] tells the nodes apart.
-- Counters and histograms are cumulative (AggregationTemporality = 2): take differences.

-- 1. Operations per second, per node, device and direction, per minute
SELECT t, host, device, direction, round(sum(delta) / 60, 1) AS ops_per_s
FROM (
  SELECT toStartOfMinute(TimeUnix) AS t,
         ResourceAttributes['host.id'] AS host,
         Attributes['system.device'] AS device,
         Attributes['disk.io.direction'] AS direction,
         Value - lagInFrame(Value, 1, Value) OVER (
           PARTITION BY cityHash64(ResourceAttributes, Attributes) ORDER BY TimeUnix
           ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS d,
         if(d < 0, Value, d) AS delta -- a decrease is a restart of OBI
  FROM otel.otel_metrics_sum
  WHERE MetricName = 'obi.stat.disk.operations'
    AND Attributes['obi.disk.stacked'] = 'false' -- physical disks only, so I/O isn't counted twice
    AND TimeUnix > now() - INTERVAL 1 HOUR
)
GROUP BY t, host, device, direction
ORDER BY t, host, device, direction;

-- 2. Average service time per device, last 5 minutes (a few very slow requests move it a lot:
--    look at 3. too)
SELECT ResourceAttributes['host.id'] AS host,
       Attributes['system.device'] AS device, Attributes['disk.io.direction'] AS direction,
       round(1e6 * (max(Sum) - min(Sum)) / nullIf(max(Count) - min(Count), 0), 1) AS avg_us,
       max(Count) - min(Count) AS operations
FROM otel.otel_metrics_histogram
WHERE MetricName = 'obi.stat.disk.operation.duration' AND TimeUnix > now() - INTERVAL 5 MINUTE
GROUP BY ResourceAttributes, Attributes;

-- 3. 99th percentile of the service time per device, last 5 minutes: the upper bound of the
--    bucket it falls in (inf: above the largest bound)
SELECT host, device,
       arrayFirstIndex(c -> c >= 0.99 * arraySum(counts), arrayCumSum(counts)) AS i,
       if(i > length(bounds), inf, bounds[i]) AS p99_seconds_at_most,
       arraySum(counts) AS operations
FROM (
  SELECT host, device, any(bounds) AS bounds, sumForEach(delta) AS counts
  FROM (
    SELECT ResourceAttributes['host.id'] AS host, Attributes['system.device'] AS device,
           any(ExplicitBounds) AS bounds,
           arrayMap((a, b) -> a - b, argMax(BucketCounts, TimeUnix), argMin(BucketCounts, TimeUnix)) AS delta
    FROM otel.otel_metrics_histogram
    WHERE MetricName = 'obi.stat.disk.operation.duration' AND TimeUnix > now() - INTERVAL 5 MINUTE
    GROUP BY ResourceAttributes, Attributes
  )
  GROUP BY host, device
);

-- 4. Bytes read and written per Kubernetes workload, last hour
SELECT Attributes['k8s.namespace.name'] AS namespace, Attributes['k8s.owner.name'] AS owner,
       Attributes['disk.io.direction'] AS direction,
       formatReadableSize(sum(bytes)) AS total
FROM (
  SELECT Attributes, max(Value) - min(Value) AS bytes
  FROM otel.otel_metrics_sum
  WHERE MetricName = 'obi.stat.disk.io' AND TimeUnix > now() - INTERVAL 1 HOUR
  GROUP BY ResourceAttributes, Attributes
)
GROUP BY namespace, owner, direction
ORDER BY sum(bytes) DESC;

-- 5. Pods, their PersistentVolumeClaims and PersistentVolumes, and the disks those are on,
--    as last reported (Value 1: mounted; 0: no longer)
SELECT Attributes['k8s.namespace.name'] AS namespace, Attributes['k8s.pod.name'] AS pod,
       Attributes['k8s.persistentvolumeclaim.name'] AS pvc,
       Attributes['k8s.persistentvolume.name'] AS pv,
       Attributes['obi.disk.volume.device'] AS mounted_from, Attributes['system.device'] AS disk,
       ResourceAttributes['host.id'] AS host
FROM otel.otel_metrics_sum
WHERE MetricName = 'obi.stat.k8s.pod.volume.device' AND TimeUnix > now() - INTERVAL 5 MINUTE
GROUP BY ResourceAttributes, Attributes
HAVING argMax(Value, TimeUnix) = 1;

-- 6. Requests in flight per device, as last reported
SELECT ResourceAttributes['host.id'] AS host, Attributes['system.device'] AS device,
       Attributes['disk.io.direction'] AS direction, argMax(Value, TimeUnix) AS in_flight
FROM otel.otel_metrics_sum
WHERE MetricName = 'obi.stat.disk.pending_operations' AND TimeUnix > now() - INTERVAL 5 MINUTE
GROUP BY ResourceAttributes, Attributes;
