#!/bin/bash
set -euo pipefail

cd /opt/hips-so2

python3 hips.py --guardar-db --enviar-email --json
