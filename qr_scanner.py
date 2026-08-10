#!/usr/bin/env python3
"""Offline QR image scanner with conservative URL risk indicators.

Security properties:
* QR contents are never fetched during analysis.  This prevents SSRF, DNS
  rebinding, tracking requests, and state-changing GET/HEAD requests.
* Only a bounded, regular image file is read once with O_NOFOLLOW when the
  platform supports it.  Decoding happens from that in-memory byte string.
* The app never labels a link "safe". It never fetches QR links during
  analysis; browser navigation is a separate, explicit user-confirmed action.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import stat
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import cv2
    import numpy as np
except ImportError:  # pragma: no cover - handled by the startup screen
    cv2 = None
    np = None


APP_TITLE = "QR 코드 스캐너 · 오프라인 위험 신호 검사"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
MAX_DECODE_PIXELS = 24_000_000
MAX_QR_TEXT_LENGTH = 4_096
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}

LEGIT_DOMAINS = {
    "amazon.com", "apple.com", "github.com", "google.com", "instagram.com",
    "kakao.com", "microsoft.com", "naver.com", "paypal.com", "samsung.com",
    "youtube.com",
}
BRAND_KEYWORDS = {
    "amazon", "apple", "google", "kakao", "microsoft", "naver", "paypal", "samsung",
}
BAD_TLDS = {"click", "cf", "ga", "gq", "link", "ml", "mov", "online", "pw", "tk", "top", "xyz", "zip"}
SHORTENERS = {"bit.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "t.co", "tiny.cc", "tinyurl.com", "v.gd"}
REDIRECT_PARAMETER_NAMES = {"continue", "dest", "destination", "goto", "link", "next", "redirect", "return", "return_url", "target", "url"}
DANGEROUS_SCHEMES = {"data", "file", "javascript", "vbscript"}

C = {
    "bg": "#F4F7FB", "surface": "#FFFFFF", "border": "#DDE4EF",
    "text": "#102033", "muted": "#66758A", "blue": "#2563EB", "blue_dark": "#101B33",
    "blue_light": "#EAF1FF", "green": "#147A52", "green_lt": "#E8F7F0",
    "amber": "#A36308", "amber_lt": "#FFF4DD", "red": "#C63C3C", "red_lt": "#FDEBEC",
    "slate": "#EEF2F7",
}


@dataclass(frozen=True)
class ScanOutcome:
    codes: list[str]
    preview_png: bytes


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_image_path(path: str) -> Path:
    """Return a verified local regular file path; reject symlinks and bad types."""
    _check(isinstance(path, str) and path, "이미지 경로가 비어 있습니다.")
    candidate = Path(path)
    try:
        initial = os.lstat(candidate)
        resolved = candidate.resolve(strict=True)
        final = os.stat(resolved)
    except (OSError, ValueError) as exc:
        raise ValueError("읽을 수 없는 파일 경로입니다.") from exc

    _check(not stat.S_ISLNK(initial.st_mode), "심볼릭 링크 파일은 열 수 없습니다.")
    _check(stat.S_ISREG(final.st_mode), "일반 이미지 파일만 열 수 있습니다.")
    _check(resolved.suffix.lower() in ALLOWED_IMAGE_EXTENSIONS, "지원하지 않는 이미지 형식입니다.")
    _check(final.st_size <= MAX_FILE_BYTES, f"이미지는 {MAX_FILE_BYTES // 1024 // 1024}MB 이하여야 합니다.")
    _check(final.st_size > 0, "빈 이미지 파일입니다.")
    return resolved


def read_image_bytes(path: str) -> bytes:
    """Read one validated file descriptor, avoiding a path check/read race."""
    safe_path = validate_image_path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(safe_path, flags)
    except OSError as exc:
        raise ValueError("이미지 파일을 안전하게 열 수 없습니다.") from exc

    try:
        info = os.fstat(fd)
        _check(stat.S_ISREG(info.st_mode), "일반 이미지 파일만 열 수 있습니다.")
        _check(0 < info.st_size <= MAX_FILE_BYTES, "허용 범위를 벗어난 이미지 파일입니다.")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            _check(bool(chunk), "이미지 파일을 읽는 중 내용이 변경되었습니다.")
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)

    _check(_matches_expected_image_signature(data, safe_path.suffix.lower()), "파일 내용이 확장자와 일치하지 않습니다.")
    return data


def _matches_expected_image_signature(data: bytes, extension: str) -> bool:
    signatures = {
        ".png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": data.startswith(b"\xff\xd8\xff"),
        ".jpeg": data.startswith(b"\xff\xd8\xff"),
        ".bmp": data.startswith(b"BM"),
        ".webp": len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP",
        ".tif": data.startswith((b"II*\x00", b"MM\x00*")),
        ".tiff": data.startswith((b"II*\x00", b"MM\x00*")),
    }
    return signatures.get(extension, False)


def _is_official_domain(hostname: str) -> bool:
    return any(hostname == domain or hostname.endswith("." + domain) for domain in LEGIT_DOMAINS)


def _result(raw: str, overall: str, score: int, checks: list[tuple[str, str, str]], **extra: str) -> dict:
    return {"raw": raw, "overall": overall, "score": min(score, 100), "checks": checks, **extra}


def analyze_qr_content(raw: str) -> dict:
    """Analyze URL syntax locally.  This function deliberately performs no I/O."""
    raw = raw.strip()
    if len(raw) > MAX_QR_TEXT_LENGTH:
        return _result(raw[:MAX_QR_TEXT_LENGTH], "danger", 100,
                       [("bad", "QR 데이터가 너무 깁니다", "허용된 길이를 초과해 처리하지 않았습니다.")], type="text")
    if not raw:
        return _result(raw, "warning", 25, [("warn", "빈 QR 데이터", "내용이 없는 QR 코드입니다.")], type="text")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return _result(raw, "danger", 100,
                       [("bad", "제어 문자가 포함되어 있습니다", "숨겨진 제어 문자가 있는 데이터는 열지 마세요.")], type="text")

    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", raw)
    if scheme_match and scheme_match.group(1).lower() in DANGEROUS_SCHEMES:
        scheme = scheme_match.group(1).lower()
        return _result(raw, "danger", 100,
                       [("bad", f"위험한 URI 스킴 ({scheme}:)", "코드 실행 또는 로컬 데이터 접근에 악용될 수 있습니다.")],
                       type="url", url=raw, domain="")

    is_web_url = bool(re.match(r"^https?://", raw, re.IGNORECASE)) or raw.lower().startswith("www.")
    if not is_web_url:
        if scheme_match:
            return _result(raw, "warning", 35,
                           [("warn", "지원하지 않는 URI 스킴", "http/https 링크만 분석하며 이 항목은 열 수 없습니다.")], type="text")
        return _result(raw, "text", 0, [], type="text")

    candidate = raw if not raw.lower().startswith("www.") else "https://" + raw
    try:
        parsed = urllib.parse.urlsplit(candidate)
        _check(parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc), "http/https URL 형식이 아닙니다.")
        _check(parsed.hostname is not None, "호스트명이 없습니다.")
        _ = parsed.port  # validate the port before normalizing
    except (ValueError, UnicodeError) as exc:
        return _result(raw, "danger", 100, [("bad", "유효하지 않은 URL", "URL 형식을 해석할 수 없습니다.")], type="url")

    hostname = parsed.hostname.rstrip(".").lower()
    checks: list[tuple[str, str, str]] = []
    risk = 0
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return _result(raw, "danger", 100, [("bad", "유효하지 않은 도메인", "도메인을 안전하게 정규화할 수 없습니다.")], type="url")

    if hostname != ascii_hostname or "xn--" in ascii_hostname:
        checks.append(("bad", "유사 도메인 사칭 가능성", "유니코드/퓨니코드 도메인은 익숙한 브랜드와 비슷하게 보일 수 있습니다."))
        risk += 50
    if parsed.username is not None or parsed.password is not None:
        checks.append(("warn", "사용자 정보가 포함된 URL", "@ 앞 문자열로 실제 접속 도메인을 숨기는 수법일 수 있습니다."))
        risk += 30

    try:
        address = ipaddress.ip_address(ascii_hostname)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            checks.append(("bad", "내부·예약 IP 주소", "로컬/사설/예약 주소는 이 앱에서 열 수 없습니다."))
            risk = 100
        else:
            checks.append(("warn", "IP 주소 직접 사용", "일반적인 서비스 URL은 도메인을 사용합니다."))
            risk += 30
    elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", ascii_hostname):
        return _result(raw, "danger", 100, [("bad", "유효하지 않은 도메인", "도메인 레이블 형식이 올바르지 않습니다.")], type="url")

    tld = ascii_hostname.rsplit(".", 1)[-1]
    if parsed.scheme.lower() == "http":
        checks.append(("bad", "HTTP 비암호화", "전송 내용이 노출·변조될 수 있습니다."))
        risk += 30
    else:
        checks.append(("ok", "HTTPS 형식", "URL 형식은 HTTPS지만 사이트 자체의 신뢰성을 보장하지는 않습니다."))
    if tld in BAD_TLDS:
        checks.append(("warn", f"주의가 필요한 확장자 (.{tld})", "피싱에 악용될 수 있어 추가 확인이 필요합니다."))
        risk += 25
    if any(keyword in ascii_hostname for keyword in BRAND_KEYWORDS) and not _is_official_domain(ascii_hostname):
        checks.append(("warn", "브랜드 사칭 가능성", "공식 도메인이 아닌데 유명 서비스 이름을 포함합니다."))
        risk += 40
    if ascii_hostname in SHORTENERS or any(ascii_hostname.endswith("." + shortener) for shortener in SHORTENERS):
        checks.append(("warn", "단축 URL", "최종 목적지가 숨겨질 수 있습니다. 이 앱은 리다이렉트를 따라가지 않습니다."))
        risk += 20
    query_names = {key.lower() for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)}
    if query_names & REDIRECT_PARAMETER_NAMES:
        checks.append(("warn", "리다이렉트 파라미터", "다른 사이트로 이동시키는 값이 포함될 수 있습니다."))
        risk += 20
    if len(ascii_hostname.split(".")) > 4:
        checks.append(("warn", "복잡한 서브도메인", "실제 등록 도메인을 숨기는 데 악용될 수 있습니다."))
        risk += 15

    if not checks or all(status == "ok" for status, _, _ in checks):
        checks.append(("ok", "로컬 위험 신호 미발견", "이 결과는 페이지 내용·평판·리다이렉트를 검사하지 않았으며 안전을 보증하지 않습니다."))

    risk = min(risk, 100)
    overall = "danger" if risk >= 60 else "warning" if risk >= 25 else "review"
    # Rebuild the authority from validated pieces.  In particular, do not pass
    # userinfo embedded in a QR URL to the browser.
    display_host = f"[{ascii_hostname}]" if address is not None and address.version == 6 else ascii_hostname
    normalized_netloc = display_host if parsed.port is None else f"{display_host}:{parsed.port}"
    normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), normalized_netloc, parsed.path, parsed.query, ""))
    return _result(raw, overall, risk, checks, type="url", url=normalized, domain=ascii_hostname)


def browser_url_for_result(result: dict) -> str | None:
    """Return a previously normalized web URL eligible for explicit navigation."""
    if result.get("type") != "url" or result.get("overall") == "danger":
        return None
    url = result.get("url")
    if not isinstance(url, str):
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
    except ValueError:
        return None
    return url


def decode_qr_image(data: bytes) -> ScanOutcome:
    """Decode a bounded image with several local OpenCV-only QR strategies."""
    if cv2 is None or np is None:
        raise RuntimeError("OpenCV가 설치되어 있지 않습니다. run_mac.sh로 의존성을 설치하세요.")
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("지원하지 않거나 손상된 이미지 파일입니다.")
    height, width = image.shape[:2]
    _check(width > 0 and height > 0 and width * height <= MAX_IMAGE_PIXELS,
           f"이미지 해상도는 최대 {MAX_IMAGE_PIXELS:,}픽셀입니다.")

    codes: set[str] = set()
    detector = cv2.QRCodeDetector()

    # Multi-code detection takes precedence so a single image containing several
    # QR codes is not reduced to only the most prominent one.
    if hasattr(detector, "detectAndDecodeMulti"):
        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(image)
            if ok:
                codes.update(item for item in decoded_info if item and len(item) <= MAX_QR_TEXT_LENGTH)
        except cv2.error:
            pass

    if not codes:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        # Produce preprocessing variants lazily: normal QR codes finish after
        # the first or second attempt without paying for every enhancement.
        variants = [image, gray]
        clahe: np.ndarray | None = None
        for variant in variants:
            try:
                value, _, _ = detector.detectAndDecode(variant)
                if value and len(value) <= MAX_QR_TEXT_LENGTH:
                    codes.add(value)
                    break
            except cv2.error:
                continue

        if not codes:
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
            _, otsu = cv2.threshold(clahe, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            adaptive = cv2.adaptiveThreshold(clahe, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                             cv2.THRESH_BINARY, 31, 4)
            for variant in (clahe, otsu, adaptive):
                try:
                    value, _, _ = detector.detectAndDecode(variant)
                    if value and len(value) <= MAX_QR_TEXT_LENGTH:
                        codes.add(value)
                        break
                except cv2.error:
                    continue

        # Small QR codes in screenshots benefit substantially from enlargement.
        # The processing cap bounds temporary memory use even for a maximum-size image.
        if not codes:
            decode_scale = min(2.0, (MAX_DECODE_PIXELS / (width * height)) ** 0.5)
            if decode_scale > 1.05:
                enlarged = cv2.resize(gray, None, fx=decode_scale, fy=decode_scale,
                                      interpolation=cv2.INTER_CUBIC)
                try:
                    value, _, _ = detector.detectAndDecode(enlarged)
                    if value and len(value) <= MAX_QR_TEXT_LENGTH:
                        codes.add(value)
                except cv2.error:
                    pass

        # Curved codes are common on bottles, posters, and photographed paper.
        if not codes and hasattr(detector, "detectAndDecodeCurved"):
            try:
                value, _, _ = detector.detectAndDecodeCurved(gray)
                if value and len(value) <= MAX_QR_TEXT_LENGTH:
                    codes.add(value)
            except cv2.error:
                pass

    preview = image.copy()
    preview_height, preview_width = preview.shape[:2]
    scale = min(700 / preview_width, 300 / preview_height, 1.0)
    if scale < 1:
        preview = cv2.resize(preview, (max(1, int(preview_width * scale)), max(1, int(preview_height * scale))), interpolation=cv2.INTER_AREA)
    ok, encoded = cv2.imencode(".png", preview)
    if not ok:
        raise ValueError("미리보기 이미지를 만들 수 없습니다.")
    return ScanOutcome(sorted(codes), encoded.tobytes())


class QRScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x820")
        self.minsize(720, 640)
        self.configure(bg=C["bg"])
        self._scan_id = 0
        self._image_ref: tk.PhotoImage | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        hero = tk.Frame(self, bg=C["blue_dark"], padx=38, pady=26)
        hero.pack(fill="x")
        left = tk.Frame(hero, bg=C["blue_dark"])
        left.pack(side="left")
        tk.Label(left, text="QR Guard", font=("Helvetica", 27, "bold"), bg=C["blue_dark"], fg="#FFFFFF").pack(anchor="w")
        tk.Label(left, text="QR 이미지 분석 · 링크를 방문하지 않는 로컬 보안 검사", font=("Helvetica", 12), bg=C["blue_dark"], fg="#C5D4F6").pack(anchor="w", pady=(4, 0))
        badge = tk.Label(hero, text="●  OFFLINE", font=("Helvetica", 11, "bold"), bg="#1D345C", fg="#9BE7C3", padx=12, pady=7)
        badge.pack(side="right", anchor="n")

        body = tk.Frame(self, bg=C["bg"], padx=34, pady=24)
        body.pack(fill="both", expand=True)
        upload = tk.Frame(body, bg=C["surface"], highlightbackground=C["border"], highlightthickness=1, padx=24, pady=20)
        upload.pack(fill="x")
        tk.Label(upload, text="01", font=("Helvetica", 11, "bold"), bg=C["blue_light"], fg=C["blue"], padx=9, pady=5).pack(anchor="w")
        tk.Label(upload, text="QR 이미지 선택", font=("Helvetica", 18, "bold"), bg=C["surface"], fg=C["text"]).pack(anchor="w", pady=(12, 2))
        tk.Label(upload, text="PNG · JPG · BMP · WebP · TIFF  |  최대 8MB", font=("Helvetica", 11), bg=C["surface"], fg=C["muted"]).pack(anchor="w")
        action_row = tk.Frame(upload, bg=C["surface"])
        action_row.pack(fill="x", pady=(17, 0))
        self._button(action_row, "이미지 선택", self._open_file, primary=True).pack(side="left")
        self._button(action_row, "새 검사", self._reset).pack(side="left", padx=8)
        self._file_var = tk.StringVar(value="선택된 이미지 없음")
        tk.Label(action_row, textvariable=self._file_var, font=("Helvetica", 11), bg=C["surface"], fg=C["muted"]).pack(side="left", padx=12)

        self._preview_frame = tk.Frame(body, bg=C["surface"], highlightbackground=C["border"], highlightthickness=1, padx=14, pady=14)
        preview_top = tk.Frame(self._preview_frame, bg=C["surface"])
        preview_top.pack(fill="x", pady=(0, 9))
        tk.Label(preview_top, text="02  이미지 미리보기", font=("Helvetica", 12, "bold"), bg=C["surface"], fg=C["text"]).pack(side="left")
        tk.Label(preview_top, text="로컬 메모리에서만 처리됨", font=("Helvetica", 10), bg=C["surface"], fg=C["green"]).pack(side="right")
        self._preview = tk.Label(self._preview_frame, bg=C["slate"])
        self._preview.pack(fill="x")

        status = tk.Frame(body, bg=C["green_lt"], padx=13, pady=10)
        status.pack(fill="x", pady=(16, 12))
        self._status_var = tk.StringVar(value="준비됨 — 분석 중 QR 링크에 연결하지 않습니다.")
        tk.Label(status, text="✓", font=("Helvetica", 12, "bold"), bg=C["green_lt"], fg=C["green"]).pack(side="left")
        tk.Label(status, textvariable=self._status_var, font=("Helvetica", 11), bg=C["green_lt"], fg=C["green"]).pack(side="left", padx=8)

        result_title = tk.Frame(body, bg=C["bg"])
        result_title.pack(fill="x", pady=(2, 8))
        tk.Label(result_title, text="검사 결과", font=("Helvetica", 17, "bold"), bg=C["bg"], fg=C["text"]).pack(side="left")
        self._result_count = tk.StringVar(value="이미지를 선택하면 결과가 표시됩니다")
        tk.Label(result_title, textvariable=self._result_count, font=("Helvetica", 10), bg=C["bg"], fg=C["muted"]).pack(side="right")

        outer = tk.Frame(body, bg=C["bg"])
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self._results = tk.Frame(canvas, bg=C["bg"])
        window = canvas.create_window((0, 0), window=self._results, anchor="nw")
        self._results.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(-int(event.delta), "units") if event.delta else None)
        self._show_empty_state()

    def _button(self, parent: tk.Misc, text: str, command, primary: bool = False) -> tk.Button:
        return tk.Button(parent, text=text, command=command, font=("Helvetica", 11, "bold"), padx=16, pady=9,
                         bg=C["blue"] if primary else C["slate"], fg="#FFFFFF" if primary else C["text"],
                         activebackground="#1D4ED8" if primary else C["border"], activeforeground="#FFFFFF" if primary else C["text"],
                         relief="flat", bd=0, cursor="hand2")

    def _open_file(self) -> None:
        path = filedialog.askopenfilename(title="QR 이미지 선택", filetypes=[("QR 이미지", "*.png *.jpg *.jpeg *.bmp *.webp *.tif *.tiff")])
        if not path:
            return
        try:
            data = read_image_bytes(path)
        except ValueError as exc:
            self._show_error(str(exc))
            return
        self._scan_id += 1
        scan_id = self._scan_id
        self._file_var.set(Path(path).name)
        self._clear_results()
        self._result_count.set("이미지에서 QR 코드를 찾는 중")
        self._status_var.set("다중 인식과 이미지 보정을 적용해 분석 중입니다…")
        threading.Thread(target=self._scan_worker, args=(scan_id, data), daemon=True).start()

    def _scan_worker(self, scan_id: int, data: bytes) -> None:
        try:
            outcome = decode_qr_image(data)
            results = [analyze_qr_content(code) for code in outcome.codes]
            self.after(0, self._show_results, scan_id, outcome.preview_png, results)
        except (ValueError, RuntimeError) as exc:
            self.after(0, self._show_error_if_current, scan_id, str(exc))
        except Exception:
            self.after(0, self._show_error_if_current, scan_id, "이미지 분석 중 예상하지 못한 오류가 발생했습니다.")

    def _show_results(self, scan_id: int, preview_png: bytes, results: list[dict]) -> None:
        if scan_id != self._scan_id:
            return
        self._show_preview(preview_png)
        self._clear_results()
        if not results:
            self._status_var.set("QR 코드를 찾지 못했습니다. 더 선명하거나 크게 찍힌 이미지를 사용해 보세요.")
            self._result_count.set("QR 코드 0개")
            self._message("인식하지 못했습니다. 이미지의 QR 코드가 작거나 흐린 경우, QR 부분을 잘라낸 뒤 다시 선택해 보세요.", C["surface"], C["muted"])
            return
        self._status_var.set(f"QR 코드 {len(results)}개를 찾았습니다. 분석은 외부 연결 없이 완료됐습니다.")
        self._result_count.set(f"QR 코드 {len(results)}개 감지")
        for index, result in enumerate(results, start=1):
            self._render_result(index, result)

    def _show_preview(self, png: bytes) -> None:
        self._image_ref = tk.PhotoImage(data=base64.b64encode(png).decode("ascii"), format="png")
        self._preview.configure(image=self._image_ref, text="")
        self._preview_frame.pack(fill="x", pady=(16, 0))

    def _show_error_if_current(self, scan_id: int, message: str) -> None:
        if scan_id == self._scan_id:
            self._show_error(message)

    def _show_error(self, message: str) -> None:
        self._clear_results()
        self._result_count.set("분석할 수 없음")
        self._status_var.set("이미지를 분석할 수 없습니다.")
        self._message(message, C["red_lt"], C["red"])

    def _message(self, text: str, bg: str, fg: str) -> None:
        tk.Label(self._results, text=text, bg=bg, fg=fg, padx=18, pady=18, justify="left", wraplength=780, font=("Helvetica", 12)).pack(fill="x", pady=4)

    def _show_empty_state(self) -> None:
        self._message("이미지를 선택해 QR 코드와 링크 위험 신호를 확인하세요.\n\n• 이미지와 QR 내용은 내 컴퓨터 밖으로 전송하지 않습니다.\n• 링크를 방문하거나 자동으로 열지 않습니다.", C["surface"], C["muted"])

    def _clear_results(self) -> None:
        for widget in self._results.winfo_children():
            widget.destroy()

    def _reset(self) -> None:
        self._scan_id += 1
        self._image_ref = None
        self._preview.configure(image="", text="")
        self._preview_frame.pack_forget()
        self._file_var.set("선택된 이미지 없음")
        self._clear_results()
        self._show_empty_state()
        self._result_count.set("이미지를 선택하면 결과가 표시됩니다")
        self._status_var.set("준비됨 — 분석 중 QR 링크에 연결하지 않습니다.")

    def _render_result(self, index: int, result: dict) -> None:
        styles = {
            "review": (C["green_lt"], C["green"], "검토 필요"),
            "warning": (C["amber_lt"], C["amber"], "주의"),
            "danger": (C["red_lt"], C["red"], "위험"),
            "text": (C["slate"], C["muted"], "텍스트"),
        }
        head_bg, head_fg, title = styles[result["overall"]]
        card = tk.Frame(self._results, bg=C["surface"], highlightbackground=C["border"], highlightthickness=1)
        card.pack(fill="x", pady=6)
        header = tk.Frame(card, bg=head_bg, padx=16, pady=10)
        header.pack(fill="x")
        tk.Label(header, text=f"#{index:02d}", bg=head_bg, fg=head_fg, font=("Helvetica", 11, "bold")).pack(side="left", padx=(0, 10))
        tk.Label(header, text=title, bg=head_bg, fg=head_fg, font=("Helvetica", 12, "bold")).pack(side="left")
        if result["type"] == "url":
            tk.Label(header, text=f"위험 신호 {result['score']}/100", bg=head_bg, fg=head_fg, font=("Helvetica", 10, "bold")).pack(side="right")
        body = tk.Frame(card, bg=C["surface"], padx=16, pady=13)
        body.pack(fill="x")
        tk.Label(body, text=result["raw"], bg=C["slate"], fg=C["text"], font=("Courier", 11), justify="left", wraplength=760, padx=11, pady=9).pack(fill="x", pady=(0, 10))
        for state, label, description in result["checks"]:
            color = {"ok": C["green"], "warn": C["amber"], "bad": C["red"]}[state]
            line = tk.Frame(body, bg=C["surface"])
            line.pack(fill="x", pady=2)
            tk.Label(line, text={"ok": "✓", "warn": "!", "bad": "×"}[state], bg=C["surface"], fg=color, font=("Helvetica", 12, "bold"), width=2).pack(side="left")
            text = tk.Frame(line, bg=C["surface"])
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=label, bg=C["surface"], fg=C["text"], font=("Helvetica", 11, "bold"), anchor="w").pack(fill="x")
            tk.Label(text, text=description, bg=C["surface"], fg=C["muted"], font=("Helvetica", 10), justify="left", wraplength=720, anchor="w").pack(fill="x")
        actions = tk.Frame(body, bg=C["surface"])
        actions.pack(anchor="w", pady=(10, 0))
        self._button(actions, "QR 내용 복사", lambda value=result["raw"]: self._copy(value)).pack(side="left")
        if url := browser_url_for_result(result):
            label = "브라우저에서 열기" if result["overall"] == "review" else "주의 링크 열기"
            self._button(actions, label, lambda target=url, level=result["overall"]: self._open_in_browser(target, level), primary=True).pack(side="left", padx=8)
        elif result.get("type") == "url":
            tk.Label(actions, text="위험 링크는 앱에서 열 수 없습니다", bg=C["surface"], fg=C["red"], font=("Helvetica", 10, "bold")).pack(side="left", padx=10)

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self._status_var.set("QR 내용을 클립보드에 복사했습니다.")

    def _open_in_browser(self, url: str, level: str) -> None:
        prefix = "주의 신호가 감지된 링크입니다.\n\n" if level == "warning" else ""
        accepted = messagebox.askyesno(
            APP_TITLE,
            f"{prefix}외부 브라우저가 다음 주소에 연결합니다.\n\n{url}\n\n"
            "이 앱은 링크의 실제 페이지나 이후 리다이렉트를 검사하지 않았습니다. 계속할까요?",
            icon="warning",
        )
        if not accepted:
            return
        try:
            webbrowser.open_new_tab(url)
        except webbrowser.Error:
            messagebox.showerror(APP_TITLE, "기본 브라우저를 열 수 없습니다. QR 내용을 복사해 직접 열어 주세요.")

if __name__ == "__main__":
    if cv2 is None:
        raise SystemExit("OpenCV가 필요합니다. ./run_mac.sh 를 실행해 설치하세요.")
    QRScannerApp().mainloop()
