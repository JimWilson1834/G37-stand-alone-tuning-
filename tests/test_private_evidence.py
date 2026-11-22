"""Opt-in real-evidence regressions. No private bytes are checked into Git."""
import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from g37offline import ROM_SIZE, STOCK_SHA256
from g37offline.checksums import verify
from g37offline.inputs import load, import_decoded, summarize_inventory
from g37offline.model import Image, Segment, compare, digest
from g37offline.workflow import Options, analyze, export
from g37offline.xdf import Definition

EVIDENCE = Path(os.environ.get("G37_EVIDENCE", "/nonexistent-g37-evidence"))
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless((EVIDENCE / "historical/fixtures/read-data-responses.log").is_file(), "Set G37_EVIDENCE to the extracted archive")
class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = EVIDENCE / "historical/fixtures"
        cls.maps = EVIDENCE / "historical/maps"

    def test_archive_digests(self):
        for line in (EVIDENCE / "SHA256SUMS.txt").read_text().splitlines():
            sha, name = line.split(maxsplit=1)
            self.assertEqual(digest((EVIDENCE / name.lstrip("*")).read_bytes()), sha, name)

    def test_complete_read_independent_segments_and_tail_provenance(self):
        raw = load(self.fixtures / "read-data-responses.log", sidecar=self.fixtures / "read-segments.csv")
        normal = load(self.fixtures / "read-segments.csv")
        self.assertEqual(raw.counts["raw_frames"], 249661)
        self.assertEqual(raw.counts["complete_messages"], 24967)
        self.assertEqual(raw.counts["data_records"], 24967)
        self.assertEqual(raw.counts["records_with_63_data_bytes"], 24966)
        self.assertEqual(raw.counts["records_with_6_data_bytes"], 1)
        data = raw.image.read(0, ROM_SIZE, True)
        self.assertEqual(digest(data), STOCK_SHA256)
        self.assertEqual(data, normal.image.read(0, ROM_SIZE, True))
        self.assertEqual(data, (self.fixtures / "hpt-read-reconstructed.bin").read_bytes())
        last = raw.image.provenance(ROM_SIZE - 6, 6)[0]
        self.assertEqual(last["source"]["origin"], "captured_response_frames")
        self.assertEqual(last["source"]["address_provenance"]["record"]["source_request_line"], "299633")
        legacy = (self.fixtures / "rebuilt_uds23_0x00000000.bin").read_bytes()
        self.assertEqual(len(legacy), ROM_SIZE - 6)
        self.assertEqual(data[:-6], legacy)
        self.assertEqual(raw.image.coverage()["state_bytes"]["filled"], 0)

    def test_real_tail_compact_spaced_varied_and_missing(self):
        sidecar = self.fixtures / "read-tail-expected.json"
        expected = (self.fixtures / "read-tail-expected.bin").read_bytes()
        start = ROM_SIZE - 69
        for name in ["read-tail-compact.log", "read-tail-spaced.log"]:
            a = load(self.fixtures / name, sidecar=sidecar)
            self.assertEqual(a.image.read(start, 69, True), expected)
            self.assertEqual(a.counts["raw_frames"], 11)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            metadata = json.loads(sidecar.read_text())
            varied_expected = (self.fixtures / "synthetic-tail-varied-expected.bin").read_bytes()
            for r in metadata["responses"]:
                off = r["rom_offset"] - start
                r["data_hex"] = varied_expected[off:off + r["length"]].hex()
            sc = tmp / "sidecar.json"
            sc.write_text(json.dumps(metadata))
            a = load(self.fixtures / "synthetic-tail-varied.log", sidecar=sc)
            self.assertEqual(a.image.read(start, 69, True), varied_expected)
            truncated = tmp / "truncated.log"
            truncated.write_text("\n".join((self.fixtures / "synthetic-tail-varied.log").read_text().splitlines()[:-1]))
            result = analyze(Options(str(truncated), sidecar=str(sc)))
            self.assertEqual(result.report["requested_coverage"]["state_bytes"]["missing"], 6)
            self.assertEqual(result.report["captured_coverage"]["recovered_bytes"], 63)
            with self.assertRaises(ValueError):
                export(result, tmp / "refused", "observed")
            # Change only expected bytes: the raw path must detect disagreement.
            metadata["responses"][0]["data_hex"] = "00" * 63
            sc.write_text(json.dumps(metadata))
            a = load(self.fixtures / "read-tail-compact.log", sidecar=sc)
            self.assertEqual(a.counts["sidecar_data_disagreements"], 2)

    def test_write_inventory_counts_and_decoded_association(self):
        path = self.fixtures / "write-record-envelope-index.csv"
        a = load(path)
        inv = summarize_inventory(a.inventory)
        for variant, count, end in [("full", 12028, ROM_SIZE), ("partial", 764, 0x20000)]:
            self.assertEqual(inv[variant]["ordinary_records"], count)
            self.assertEqual(inv[variant]["terminal_records"], 1)
            self.assertEqual(inv[variant]["claimed_ranges"], [[0x8200, end]])
            self.assertEqual(inv[variant]["claimed_extent_bytes"], end - 0x8200)
        self.assertEqual(inv["full"]["different_ordinary_envelopes"], 0)
        self.assertEqual(inv["partial"]["different_ordinary_envelopes"], 3)
        self.assertEqual(a.image.coverage()["recovered_bytes"], 0)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"schema": "g37-decoded-interval-v1", "input_sha256": digest(path.read_bytes()), "variant": "full",
                        "capture_sha256": "e30e942bd045b92aeba076b48a0fded79aa342244612310c271c960bc2f23296",
                        "capture_evidence_file": str(self.fixtures / "capture-evidence.json"),
                        "capture_evidence_sha256": digest((self.fixtures / "capture-evidence.json").read_bytes()),
                        "decoded_file": str(self.fixtures / "teat_decoded_sparse_0x008200_0x180000.bin"),
                        "decoded_sha256": "822ebf4b44d8af3929205e58419997af7c19214287020c48dd30decbe88a3774",
                        "rom_offset": 0x8200, "length": ROM_SIZE - 0x8200,
                        "reference_file": str(ROOT / "ACTUAL TOOL/DEF/Original.bin"), "reference_sha256": STOCK_SHA256,
                        "decoder": {"name": "archived decoded artifact; transform not rerun", "version": "historical"}}
            m = Path(tmp) / "decoded.json"
            m.write_text(json.dumps(manifest))
            import_decoded(a, m)
            self.assertEqual(a.image.state[0], 0)
            self.assertEqual(digest(a.image.read(0x8200, ROM_SIZE - 0x8200, True)), manifest["decoded_sha256"])
            for key, bad in [("input_sha256", "0" * 64), ("rom_offset", 0x8201), ("decoded_sha256", "0" * 64),
                             ("variant", "partial"), ("capture_sha256", "0" * 64), ("capture_evidence_sha256", "0" * 64)]:
                wrong = {**manifest, key: bad}
                m.write_text(json.dumps(wrong))
                with self.assertRaises(ValueError):
                    import_decoded(load(path), m)

    def test_exact_historical_map_comparison_and_checksums(self):
        a = load(self.maps / "comparison-fixtures/test2.bin", binary="full").image
        path = next((self.maps / "comparison-fixtures").glob("bintest1*.bin"))
        b = load(path, binary="full").image
        diff = compare(a, b, 0x8200, ROM_SIZE)
        self.assertEqual(diff["changed_bytes"], 727)
        self.assertEqual(len(diff["diff_runs"]), 308)
        for name, mapped in [("Test(1).xdf", 715), ("TESTED.xdf", 717)]:
            d = Definition(self.maps / "definitions" / name)
            report = d.compare(a, b, 0x8200, ROM_SIZE)
            self.assertEqual(report["mapped_changed_bytes"], mapped)
            self.assertEqual(report["unmapped_changed_bytes"], 727 - mapped)
        d = Definition(self.maps / "definitions/TESTED.xdf")
        changes = d.compare(a, b, 0x8200, ROM_SIZE)["cell_differences"]
        for off, raw_a, raw_b, va, vb in [(0x1B604, "91e7", "6400", 72.951171875, 50),
                                           (0xA3F0, "d4", "54", 20, 20), (0x1469E, "14", "a0", 250, 2000)]:
            cell = next(c for c in changes if c["before"].get("address") == off)
            self.assertEqual((cell["before"]["raw_hex"], cell["after"]["raw_hex"]), (raw_a, raw_b))
            self.assertEqual((cell["before"]["value"], cell["after"]["value"]), (va, vb))
        self.assertEqual(sum(c["status"] == "pass" for c in verify(a)), 1)
        self.assertEqual(sum(c["status"] == "pass" for c in verify(b)), 4)
        original = load(ROOT / "ACTUAL TOOL/DEF/Original.bin", binary="full").image
        self.assertEqual(compare(a, original)["changed_bytes"], 9299)
