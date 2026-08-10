import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import qr_scanner


class UrlAnalysisSecurityTests(unittest.TestCase):
    def test_analysis_never_performs_network_io(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not be used")):
            result = qr_scanner.analyze_qr_content("https://example.com/login")
        self.assertEqual(result["overall"], "review")

    def test_private_ip_is_dangerous_and_not_openable(self):
        result = qr_scanner.analyze_qr_content("http://127.0.0.1:8080/admin")
        self.assertEqual(result["overall"], "danger")
        self.assertGreaterEqual(result["score"], 60)

    def test_dangerous_scheme_is_blocked(self):
        result = qr_scanner.analyze_qr_content("javascript:alert(1)")
        self.assertEqual(result["overall"], "danger")
        self.assertEqual(result["score"], 100)

    def test_unlisted_https_is_not_called_safe(self):
        result = qr_scanner.analyze_qr_content("https://unlisted.example/path")
        self.assertEqual(result["overall"], "review")
        self.assertNotEqual(result["overall"], "safe")

    def test_punycode_and_brand_impersonation_are_flagged(self):
        result = qr_scanner.analyze_qr_content("https://apple-login.example.xyz")
        self.assertEqual(result["overall"], "danger")

    def test_userinfo_is_removed_from_normalized_url(self):
        result = qr_scanner.analyze_qr_content("https://fake:secret@example.com/login")
        self.assertNotIn("fake:secret@", result["url"])
        self.assertIn("사용자 정보", " ".join(label for _, label, _ in result["checks"]))

    def test_only_non_dangerous_normalized_urls_are_openable(self):
        self.assertEqual(
            qr_scanner.browser_url_for_result(qr_scanner.analyze_qr_content("https://example.com")),
            "https://example.com",
        )
        self.assertIsNone(qr_scanner.browser_url_for_result(qr_scanner.analyze_qr_content("http://127.0.0.1")))


class ImageInputSecurityTests(unittest.TestCase):
    def _write(self, directory: str, name: str, content: bytes) -> Path:
        path = Path(directory) / name
        path.write_bytes(content)
        return path

    def test_rejects_extension_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, "not-image.png", b"not an image")
            with self.assertRaisesRegex(ValueError, "확장자"):
                qr_scanner.read_image_bytes(str(path))

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._write(directory, "source.png", b"\x89PNG\r\n\x1a\n")
            link = Path(directory) / "link.png"
            try:
                link.symlink_to(target)
            except OSError as exc:  # pragma: no cover - platform limitation
                self.skipTest(str(exc))
            with self.assertRaisesRegex(ValueError, "심볼릭"):
                qr_scanner.read_image_bytes(str(link))

    def test_rejects_oversized_file_before_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.png"
            with path.open("wb") as handle:
                handle.seek(qr_scanner.MAX_FILE_BYTES)
                handle.write(b"x")
            with self.assertRaisesRegex(ValueError, "MB"):
                qr_scanner.read_image_bytes(str(path))

    def test_decodes_a_valid_qr_image_from_memory(self):
        encoder = qr_scanner.cv2.QRCodeEncoder_create(qr_scanner.cv2.QRCodeEncoder_Params())
        image = encoder.encode("https://example.com/qr")
        image = qr_scanner.cv2.copyMakeBorder(image, 4, 4, 4, 4, qr_scanner.cv2.BORDER_CONSTANT, value=255)
        image = qr_scanner.cv2.resize(image, None, fx=8, fy=8, interpolation=qr_scanner.cv2.INTER_NEAREST)
        ok, encoded = qr_scanner.cv2.imencode(".png", image)
        self.assertTrue(ok)

        outcome = qr_scanner.decode_qr_image(encoded.tobytes())
        self.assertEqual(outcome.codes, ["https://example.com/qr"])

    def test_decodes_a_low_contrast_qr_image(self):
        encoder = qr_scanner.cv2.QRCodeEncoder_create(qr_scanner.cv2.QRCodeEncoder_Params())
        image = encoder.encode("https://example.com/low-contrast")
        image = qr_scanner.cv2.copyMakeBorder(image, 4, 4, 4, 4, qr_scanner.cv2.BORDER_CONSTANT, value=255)
        image = qr_scanner.cv2.resize(image, None, fx=4, fy=4, interpolation=qr_scanner.cv2.INTER_NEAREST)
        image = qr_scanner.cv2.normalize(image, None, 115, 190, qr_scanner.cv2.NORM_MINMAX)
        image = qr_scanner.cv2.GaussianBlur(image, (3, 3), 0)
        ok, encoded = qr_scanner.cv2.imencode(".png", image)
        self.assertTrue(ok)

        outcome = qr_scanner.decode_qr_image(encoded.tobytes())
        self.assertEqual(outcome.codes, ["https://example.com/low-contrast"])


if __name__ == "__main__":
    unittest.main()
