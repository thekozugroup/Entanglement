#!/bin/sh
set -eu
cd /workspace/Entanglement
work=/workspace/entangle-emulated-arm-f499e3ed-slim
flock -x /tmp/entangle-f499e3ed-platform-vfs.lock python3 -B "$work/provision.py"
python3 -B "$work/proof/arm-build-driver.py"
python3 -B "$work/proof/package-arm.py"
python3 -B "$work/finish.py"
