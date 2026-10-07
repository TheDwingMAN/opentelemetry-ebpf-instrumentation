#!/bin/bash
# NVMe multipath with only the request probes (bio probes off): isolates the bio probes
export NVME_OBI_FEATURES=stats_disk_operation_duration,stats_disk_io,stats_disk_operations,stats_disk_operation_time,stats_disk_queue_duration,stats_disk_flush,stats_disk_discard,stats_disk_pending_operations
exec bash ./main.sh
