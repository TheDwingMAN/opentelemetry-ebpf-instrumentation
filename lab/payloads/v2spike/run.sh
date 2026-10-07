#!/bin/bash
# v2 feasibility spike: block rq (flush/discard/queue/partition), bio on dm, sync kinds, NFS.
cd /work
./v2probe
echo "v2probe rc=$?"
