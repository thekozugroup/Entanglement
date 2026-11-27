"""Independent checks for the distributed image benchmark's correctness gates."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark_image_batch as bench


def encoded(image, fmt="PNG"):
    buffer = io.BytesIO()
    image.save(buffer, fmt)
    return buffer.getvalue()


class ImageGateTests(unittest.TestCase):
    def test_corpus_has_distinct_inputs_and_independent_references(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "source.png"
            pixels = bytes((15 * x + 17 * y + 5 * c) % 256
                           for y in range(64) for x in range(64) for c in range(3))
            Image.frombytes("RGB", (64, 64), pixels).save(path)
            cases = bench.corpus(path)
        self.assertEqual(len({payload for payload, _ in cases}), bench.IMAGES)
        for payload, reference in cases:
            _, jpeg = payload.split(b"\n", 1)
            with Image.open(io.BytesIO(jpeg)) as image:
                expected = image.convert("RGB").resize(bench.SIZE, Image.Resampling.LANCZOS)
            self.assertEqual(reference.tobytes(), expected.tobytes())

    def test_oracle_refuses_wrong_format_dimensions_and_content(self):
        reference = Image.new("RGB", bench.SIZE, "black")
        self.assertEqual(bench.verify_png(encoded(reference), reference)[1], 0.0)
        for invalid in [encoded(reference, "JPEG"), encoded(reference.resize((4, 8))),
                        encoded(Image.new("RGB", bench.SIZE, (0, 4, 0)))]:
            with self.assertRaises(ValueError):
                bench.verify_png(invalid, reference)

    def test_missing_worker_and_route_mismatch_are_detected(self):
        from types import SimpleNamespace
        import json
        reference = Image.new("RGB", bench.SIZE, "black")
        png = encoded(reference)
        result = {"chosen_peer": "worker-a", "output": list(png)}
        reply = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
        with patch.object(bench, "exchange", return_value=(0.01, reply)):
            arguments = ("three_remote", SimpleNamespace(sock=""), [b"request"])
            cases = [(b"input", reference)]
            with self.assertRaisesRegex(ValueError, "unexpected worker"):
                bench.measure(*arguments, ["worker-a", "worker-b"], cases, {})
            with self.assertRaisesRegex(ValueError, "different PNG"):
                bench.measure(*arguments, ["worker-a"], cases, {0: "changed"})
