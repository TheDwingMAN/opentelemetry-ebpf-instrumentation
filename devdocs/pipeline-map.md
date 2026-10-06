# OBI pipeline map

The whole OBI pipeline is divided in two main connected pipelines. The reason for not having a
single pipeline is that there are plans to split OBI into two: a finder/instrumenter executable
with high privileges and a reader/decorator executable with lesser privileges.

The dashed boxes are optional stages that will run only under certain conditions/configurations.

Check the in-code documentation for more information about each symbol.

## Table Of Contents

- [Application instrumentation pipeline](#application-instrumentation-pipeline)
- [Network metrics pipeline](#network-metrics-pipeline)
- [Stat metrics pipeline](#stat-metrics-pipeline)

## Application instrumentation pipeline

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    subgraph discovery.Finder pipeline
        PW(ProcessWatcher) --> |new/removed processes| KWE
        KWE(WatcherKubeEnricher):::optional --> |process enriched with k8s metadata| DE
        DE(DockerEnricher):::optional --> |process enriched with docker metadata| CM
        CM(CriteriaMatcher) --> |processes matching the selection criteria| ET(ExecTyper)
        ET --> |ELFs and its metadata| CU
        CU(ContainerStoreUpdater):::optional --> |ELFs and its metadata| TA
        TA(TraceAttacher) -.-> EBPF1(ebpf.Tracer)
        TA -.-> |creates one per executable| EBPF2(ebpf.Tracer)
        TA -.-> EBPF3(ebpf.Tracer)
    end
    subgraph Decoration and forwarding pipeline
        EBPF1 -.-> TR
        EBPF2 -.-> |"[]request.Span"| TR
        EBPF3 -.-> TR
        TR(traces.ReadDecorator) --> ROUT(Routes<br/>decorator)
        ROUT:::optional --> DOCKDEC(Docker<br/>decorator)
        ROUT:::optional --> KD(Kubernetes<br/>decorator)
        KD:::optional --> DOCKDEC
        DOCKDEC:::optional --> NR
        NR(Name resolver):::optional --> AF
        
        AF(Attributes filter):::optional --> OTELT(OTEL/ALLOY<br/> traces<br/> exporter):::optional

        
        AF --> IPD(Unknown IP<br/>dropper):::optional
        IPD --> SNCL(Span Name<br/>cardinality<br/>limiter)
        SNCL --> OTELRM(OTEL<br/>RED metrics<br/> exporter):::optional
        SNCL --> OTELSM(OTEL<br/>span/svc graph<br/>metrics<br/> exporter):::optional
        SNCL --> PROM(Prometheus<br/>HTTP<br/>endpoint):::optional
    end
    CU -.-> |New PIDs| KSTORE
    DE -.-> |Pod info| DOCKAPI(Docker API):::optional
    DOCKDEC -.-> |Pod info| DOCKAPI(Docker API):::optional
    KSTORE(KubeStore):::optional <-.- | Aggregated & indexed Pod info | KD
    IF("Informer<br/>(Kube API)"):::optional -.-> |Pods & ReplicaSets status| KSTORE
    IF -.-> |new Kube objects| KWE
    AF ---> PC
    subgraph process metrics pipeline
        PC("process.Collector"):::optional --> POTEL
        PC --> PPROM
        POTEL("OTEL exporter"):::optional
        PPROM("Prometheus exporter"):::optional
    end
    TA -.-> |Python PID lifecycle| PYTHON
    subgraph Python runtime metrics pipeline
        PYTHON("Generic tracer Python controller"):::optional -.-> |Attaches PID probe| PYBPF("Python GC eBPF probe"):::optional
        PYBPF --> |Ring-buffer snapshots| PYQUEUE("Runtime metrics queue"):::optional
        PYBPF --> PYMAP("Latest snapshot map"):::optional
        PYMAP -.-> |Read on process exit| PYTHON
        PYTHON -.-> |Final snapshot| PYQUEUE
        PYQUEUE --> RMGATE
        RMGATE("Dynamic PID gate"):::optional --> PYOTEL
        RMGATE --> PYPROM
        PYOTEL("OTEL runtime metrics exporter"):::optional
        PYPROM("Prometheus endpoint"):::optional
    end
```

## Network metrics pipeline

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    MT(eBPF<br/>Map Tracer) --> PF
    RT(eBPF<br/>Ringbuf Tracer) --> PF
    PF(Internet<br/>protocol filter):::optional --> DD
    DD(Flow Deduper):::optional --> K8S
    KIN(Kube informer):::optional --> KSTORE
    KSTORE(Kube Store):::optional --> K8S
    K8S(Kubernetes<br/>decorator):::optional --> RDNS
    RDNS(Reverse DNS):::optional --> GeoIP
    GeoIP(Geo IP Provider):::optional --> CIDRS
    CIDRS(CIDRs<br/>redecorator):::optional --> FLTR
    FLTR(Attributes<br/>filter):::optional --> OTEL(OpenTelemetry<br/>metrics<br/>export):::optional
    FLTR --> PROM(Prometheus<br/>metrics<br/>export):::optional
    FLTR --> FlowPrinter(Flow Printer):::optional
```

## Stat metrics pipeline

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    RT(eBPF<br/>Ringbuf Tracer) --> K8S
    KIN(Kube informer):::optional --> KSTORE
    KSTORE(Kube Store):::optional --> K8S
    K8S(Kubernetes<br/>decorator):::optional --> RDNS
    RDNS(Reverse DNS):::optional --> GeoIP
    GeoIP(Geo IP Provider):::optional --> CIDRS
    CIDRS(CIDRs<br/>redecorator):::optional --> FLTR
    FLTR(Attributes<br/>filter):::optional --> OTEL(OpenTelemetry<br/>metrics<br/>export):::optional
    FLTR --> PROM(Prometheus<br/>metrics<br/>export):::optional
    FLTR --> StatPrinter(Stat Printer):::optional
```

### Storage metrics

Storage stats take one of two routes into the same OTEL and Prometheus exporters. Block, filesystem
and NFS metrics count in kernel maps by default and skip the per-event route: a `statagg` family
reads the maps and decorates each kernel key once (then again every 30 s), running the same stages
in the same order with the same `filters.stats` and dynamic PID selection, so both routes drop the
same series. With `ebpf.storage_aggregation.disabled` (or `stats.print_stats`), block and
filesystem metrics take the ring buffer route instead: each operation is an event and goes through
the pipeline above. `obi.stat.disk.pending_operations` takes neither: each exporter snapshots the
kernel's in-flight maps at collection and decorates the snapshot the same way.

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    BLK(eBPF block<br/>per-event tracer):::optional --> K8S
    FSE(eBPF filesystem<br/>per-event tracer):::optional --> K8S
    K8S(Kubernetes<br/>decorator):::optional --> PID(PID metadata<br/>decorator<br/>PV/PVC lookup):::optional
    PID --> DYN(Dynamic PID<br/>selector):::optional
    DYN --> FLTR(Attributes<br/>filter):::optional
    FLTR --> EXP(OTEL and Prometheus<br/>exporters)
    BLKM(eBPF blk_agg, blk_q_agg<br/>blk_cg_agg kernel maps) --> FAM
    FSM(eBPF fs_io_accum<br/>kernel map):::optional --> FAM
    NFSM(eBPF nfs_rpc_accum<br/>kernel map):::optional --> FAM
    FAM(statagg family reader):::optional --> DEC(Shared decoration<br/>same stages, per kernel key):::optional
    CGI(Cgroup index<br/>cgroup v2):::optional -.-> DEC
    DEC --> EXP
    INF(eBPF in-flight maps<br/>pending_operations snapshot):::optional --> PDEC(Shared decoration<br/>per exporter):::optional
    PDEC --> EXP
    PV("PersistentVolume<br/>get (Kube API)"):::optional -.-> PID
    PV -.-> DEC
```
