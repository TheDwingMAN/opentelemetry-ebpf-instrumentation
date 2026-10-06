#!/usr/bin/env bash
# Tear down the OBI storage test cluster.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
kind delete cluster --name obi-storage
