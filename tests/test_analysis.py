import csv
import json
from pathlib import Path
import tempfile
import unittest

from g37offline import ROM_SIZE
from g37offline.inputs import load, envelope, summarize_inventory
from g37offline.model import Image, Segment, compare, digest
from g37offline.workflow import Options, analyze, export
from test_transport import encode


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.write_text(text)
        return path

    def test_shuffled_requests_place_by_address(self):
        lines = []
        for address, value in [(10, b"XYZ"), (0, b"ABC")]:
            lines += encode(b"\x23" + address.to_bytes(4, "big") + len(value).to_bytes(2, "big"), can_id="7E0")
            lines += encode(b"\x63" + value)
        a = load(self.write("mixed.log", "\n".join(lines)))
        self.assertEqual(a.image.read(10, 3), b"XYZ")
        self.assertEqual(a.image.read(0, 3), b"ABC")
        self.assertIsNone(a.image.read(3, 7))
        self.assertEqual(a.counts["data_records"], 2)

    def test_unresolved_requests_negative_and_access(self):
        lines = encode(b"\x23" + b"\x00" * 4 + b"\x00\x03", can_id="7E0")
        lines += encode(b"\x7f\x23")
        lines += encode(b"\x67\x01\x12\x34\x56\x78")
        lines += encode(b"\x27\x02secret", can_id="7E0")
        lines += encode(b"\x67\x02")
        result = analyze(Options(str(self.write("negative.log", "\n".join(lines)))))
        a = result.analysis
        self.assertEqual(a.counts["truncated_negative_replies"], 1)
        self.assertEqual(a.counts["outstanding_requests"], 1)
        self.assertEqual(a.image.coverage()["recovered_bytes"], 0)
        events = json.dumps(a.events)
        for secret in ["secret", "12345678", "can_id", "0x7E8"]:
            self.assertNotIn(secret, events)
        self.assertEqual([e["event"] for e in a.events], ["challenge", "response", "reported_acceptance"])

    def test_pending_then_success_and_channel_mismatch(self):
        req = encode(b"\x23" + b"\x00" * 4 + b"\x00\x03", can_id="7E0")
        path = self.write("pending.log", "\n".join(req + encode(b"\x7f\x23\x78") + encode(b"\x63ABC")))
        self.assertEqual(load(path).image.read(0, 3), b"ABC")
        path = self.write("other-channel.log", "\n".join(req + encode(b"\x63ABC", channel="can1")))
        self.assertEqual(load(path).counts["orphan_data_responses"], 1)

    def test_overlap_identical_and_conflicting_ranges(self):
        image = Image(10)
        image.add(Segment(2, b"ABC", {"line": 1}))
        image.add(Segment(2, b"ABC", {"line": 2}))
        self.assertEqual(image.identical_overlap_bytes, 3)
        self.assertEqual(len(image.provenance(2, 3)), 2)
        image.add(Segment(3, b"QCD", {"line": 3}))
        c = image.coverage()
        self.assertEqual(c["first_conflicting_address"], 3)
        self.assertEqual(c["state_bytes"]["conflicting"], 1)
        self.assertIsNone(image.read(2, 3))
        self.assertEqual(c["conflicts"][0]["previous_segments"], [0])

    def test_bounds_before_allocation(self):
        for off, data in [(-1, b"x"), (ROM_SIZE, b"x"), (0x81008200, b"x"), (0, b"")]:
            with self.assertRaises(ValueError):
                Image().add(Segment(off, data, {}))

    def test_byte_differences_and_unmatched_tail(self):
        a, b = Image(4), Image(5)
        a.add(Segment(0, b"ABCD", {}))
        b.add(Segment(0, b"AXYD!", {}))
        diff = compare(a, b)
        self.assertEqual(diff["diff_runs"], [[1, 3]])
        self.assertEqual(diff["unmatched_tails"], [[4, 5]])

    def test_unsupported_and_ambiguous_inputs(self):
        for name, content in [("made-up.hpt", "abc"), ("unknown.log", "arbitrary text"), ("ambiguous.log", "can0 7E8#026341\ncan0 7E8 PDU 6341")]:
            a = load(self.write(name, content))
            self.assertEqual(a.image.coverage()["recovered_bytes"], 0)
            self.assertEqual(a.counts["unsupported_input"], 1)
        p = self.root / "short.bin"
        p.write_bytes(b"\xFF" * 3)
        with self.assertRaises(ValueError):
            load(p, binary="full")
        with self.assertRaises(ValueError):
            load(p, binary="interval")
        self.assertIsNone(load(p).image.read(0, 3))

    def test_sidecar_bytes_are_never_the_output(self):
        path = self.write("raw.log", "\n".join(encode(b"\x63ABC")))
        sidecar = self.write("side.csv", "rom_offset_hex,length,data_hex,first_exported_frame_line,last_exported_frame_line\n0x10,3,58595A,1,1\n")
        a = load(path, sidecar=sidecar)
        self.assertEqual(a.counts["sidecar_data_disagreements"], 1)
        self.assertIsNone(a.image.read(16, 3))

    def test_export_collision_cancellation_and_base_provenance(self):
        inp = self.root / "interval.bin"
        inp.write_bytes(b"ABCD")
        base = self.root / "base.bin"
        base.write_bytes(b"\xff" * ROM_SIZE)
        result = analyze(Options(str(inp), binary="interval", offset=0x8200, base=str(base)))
        self.assertEqual(result.view.state[0], 3)
        self.assertEqual(result.view.state[0x8200], 1)
        with self.assertRaises(ValueError):
            export(result, self.root / "not-observed", "observed")
        self.assertFalse((self.root / "not-observed").exists())
        with self.assertRaises(InterruptedError):
            export(result, self.root / "cancelled", cancelled=lambda: True)
        self.assertFalse((self.root / "cancelled").exists())
        self.assertFalse(list(self.root.glob(".cancelled*")))
        out = export(result, self.root / "overlay", "overlay")
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["view_coverage"]["state_bytes"]["base"], ROM_SIZE - 4)
        self.assertEqual(report["export"]["base_spans"][0]["range"], [0, 0x8200])
        with self.assertRaises(FileExistsError):
            export(result, out, "overlay")
        self.assertEqual(inp.read_bytes(), b"ABCD")

    def test_synthetic_file_fixture_and_missing_six_bytes(self):
        fixture = Path(__file__).parent / "fixtures"
        inp = fixture / "synthetic-responses.log"
        sidecar = fixture / "synthetic-addresses.csv"
        result = analyze(Options(str(inp), sidecar=str(sidecar)))
        expected = bytes(range(63)) + bytes.fromhex("19a74f82c31d")
        self.assertEqual(result.analysis.image.read(0x100, 69, True), expected)
        self.assertEqual(result.report["requested_coverage"]["state_bytes"]["missing"], 0)
        short = self.write("short.log", "\n".join(inp.read_text().splitlines()[:-1]))
        result = analyze(Options(str(short), sidecar=str(sidecar)))
        self.assertEqual(result.report["requested_coverage"]["state_bytes"]["missing"], 6)

    def test_export_rejects_changed_source_after_preview(self):
        p = self.root / "interval.bin"
        p.write_bytes(b"ABC")
        result = analyze(Options(str(p), binary="interval", offset=0x100))
        p.write_bytes(b"XYZ")
        with self.assertRaisesRegex(ValueError, "Source changed"):
            export(result, self.root / "stale")
        self.assertFalse((self.root / "stale").exists())

    def test_opaque_envelope_inventory(self):
        encoded = bytes([0x34, 0x81, 0, 0x82, 0, 128]) + b"A" * 128 + b"\x00\x00"
        item = envelope(encoded)
        self.assertEqual(item["rom_offset"], 0x8200)
        self.assertEqual(item["rom_extent_bytes"], 128)
        self.assertEqual(item["status"], "opaque")
        self.assertEqual(summarize_inventory([item])["capture"]["recovered_bytes_from_envelopes"], 0)
        with self.assertRaises(ValueError):
            envelope(b"\x34" + b"\0" * 55)

    def test_only_readonly_modules_imported(self):
        import subprocess, sys
        p = subprocess.run([sys.executable, "-c", "import sys; import g37offline.__main__; from g37offline.checksums import reader; reader(); assert not any(k in sys.modules for k in ['socket','can','serial','ctypes','tkinter']); assert not any('combined_gui' in k for k in sys.modules)"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
