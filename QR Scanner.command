#!/usr/bin/env bash
# Finder에서 더블클릭하는 macOS 실행기입니다.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"

if ! "$SCRIPT_DIR/run_mac.sh"; then
    echo
    echo "실행에 실패했습니다. 위의 오류 내용을 확인한 뒤 아무 키나 누르세요."
    read -r -n 1
    exit 1
fi
