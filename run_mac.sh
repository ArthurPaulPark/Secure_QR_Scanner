#!/usr/bin/env bash
# Secure, reproducible macOS launcher for the QR scanner.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
MARKER="$VENV_DIR/.requirements.sha256"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10 이상이 필요합니다. https://www.python.org 에서 설치해 주세요."
    exit 1
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Python 3.10 이상이 필요합니다. 현재 버전: $PYTHON_VERSION"
    exit 1
fi

REQUIREMENTS_HASH="$(shasum -a 256 "$REQUIREMENTS" | awk '{print $1}')"
ENVIRONMENT_FINGERPRINT="$REQUIREMENTS_HASH:$PYTHON_VERSION"
if [[ -d "$VENV_DIR" && (! -f "$MARKER" || "$(<"$MARKER")" != "$ENVIRONMENT_FINGERPRINT") ]]; then
    echo "의존성 잠금 파일이 변경되어 가상환경을 다시 만듭니다."
    rm -rf -- "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "격리된 가상환경을 만들고 고정된 의존성을 설치합니다…"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --only-binary=:all: --requirement "$REQUIREMENTS"
    "$VENV_DIR/bin/python" -m pip check
    printf '%s\n' "$ENVIRONMENT_FINGERPRINT" > "$MARKER"
fi

echo "QR 스캐너를 시작합니다. 분석 중 외부 URL에는 연결하지 않습니다."
exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/qr_scanner.py"
