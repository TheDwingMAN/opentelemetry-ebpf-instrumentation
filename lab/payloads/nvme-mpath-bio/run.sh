#!/bin/bash
# NVMe multipath with the bio probes on (stats_disk_bio_devices) besides the request probes
export NVME_OBI_FEATURES=stats_disk_operation_duration,stats_disk_operations,stats_disk_bio_devices
exec bash ./main.sh
