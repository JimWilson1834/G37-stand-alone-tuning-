from collections import Counter
from pathlib import Path
import tempfile
import unittest

from g37offline import ROM_SIZE, STOCK_SHA256, XDF_SHA256
from g37offline.checksums import verify, reader
from g37offline.inputs import load
from g37offline.model import Image, Segment, digest
from g37offline.xdf import Definition, evaluate, compatibility

ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / "ACTUAL TOOL/DEF/Original.bin"
XDF = ROOT / "ACTUAL TOOL/DEF/TESTED.xdf"


class XdfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition = Definition(XDF)
        cls.stock = load(STOCK, binary="full").image

    def test_definition_identity_counts_and_duplicates(self):
        d = self.definition
        self.assertEqual(d.source["sha256"], XDF_SHA256)
        self.assertEqual(d.summary()["object_counts"], {"XDFTABLE": 101, "XDFCONSTANT": 88, "XDFFLAG": 8})
        self.assertEqual(d.summary()["category_count"], 57)
        self.assertEqual(d.summary()["unresolved_objects"], 13)
        titles = Counter(o.title for o in d.objects)
        self.assertEqual(titles["Rpm Fuel Restore"], 2)
        self.assertEqual(titles["MON8200"], 3)
        for obj in d.objects:
            if obj.plane.address is None:
                self.assertEqual(obj.plane.decode(self.stock)["status"], "unresolved")

    def cell_at(self, offset):
        obj = next(o for o in self.definition.objects if o.plane.address == offset)
        return obj.plane.decode(self.stock)

    def test_known_anchors_and_lowercase_x(self):
        for address, raw, result in [(0x88F0, "70", 3.5), (0x1469E, "66", 1275),
                                      (0x15BE2, "3200", 25), (0x1B5EE, "3200", 25), (0x92B2, "2580", 7500)]:
            c = self.cell_at(address)
            self.assertEqual(c["raw_hex"], raw)
            self.assertEqual(c["value"], result)
        self.assertEqual(self.cell_at(0x92B2)["formula"], "x*25/32")
        self.assertEqual(self.cell_at(0x92B2)["raw_unsigned"], 9600)

    def test_formula_safety_and_mask(self):
        self.assertEqual(evaluate("(X & 127) - 64", 0xD4), 20)
        self.assertEqual(evaluate("(X & 127) - 64", 0x54), 20)
        self.assertEqual(evaluate("x*25/32", 9600), 7500)
        for equation in ["128/X", "__import__('os').system('false')", "X.foo", "[X]", "2 ** 100000000", "Y+1", "1e999"]:
            with self.subTest(equation=equation), self.assertRaises((ValueError, SyntaxError)):
                evaluate(equation, 0)

    def test_sparse_cell_crosses_boundary(self):
        obj = next(o for o in self.definition.objects if o.plane.address == 0x92B2)
        image = Image()
        image.add(Segment(0x92B2, b"\x25", {}))
        cell = obj.plane.decode(image)
        self.assertIsNone(cell["value"])
        self.assertEqual(cell["status"], "uncovered_or_conflicting")
        image.add(Segment(0x92B3, b"\x80", {}))
        self.assertEqual(obj.plane.decode(image)["value"], 7500)
        image.add(Segment(0x92B3, b"\x81", {}))
        self.assertIsNone(obj.plane.decode(image)["value"])

    def test_flags_endian_defaults_base_and_strides(self):
        xml = '''<XDFFORMAT><XDFHEADER><BASEOFFSET offset="16" subtract="1"/><DEFAULTS datasizeinbits="16" signed="1" lsbfirst="1"/></XDFHEADER>
        <XDFCONSTANT uniqueid="a"><title>Default</title><EMBEDDEDDATA mmedaddress="0x20"/><MATH equation="X"/></XDFCONSTANT>
        <XDFFLAG uniqueid="b"><title>Mask</title><EMBEDDEDDATA mmedaddress="0x24" mmedelementsizebits="8" mmedtypeflags="0"/><mask>0x80</mask></XDFFLAG>
        <XDFTABLE uniqueid="c"><title>Column major</title><XDFAXIS id="z"><EMBEDDEDDATA mmedaddress="0x30" mmedelementsizebits="8" mmedtypeflags="0x04" mmedrowcount="2" mmedcolcount="2"/></XDFAXIS></XDFTABLE>
        <XDFCONSTANT uniqueid="d"><title>Stride</title><EMBEDDEDDATA mmedaddress="0x40" mmedelementsizebits="8" mmedrowcount="2" mmedcolcount="2" mmedmajorstridebits="32" mmedminorstridebits="16"/></XDFCONSTANT>
        </XDFFORMAT>'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.xdf"
            p.write_text(xml)
            d = Definition(p)
            image = Image()
            image.add(Segment(0x10, b"\xfe\xff\0\0\x80", {}))
            a, b, c, stride = d.objects
            self.assertEqual(a.plane.decode(image)["value"], -2)
            self.assertTrue(b.plane.decode(image, mask=b.mask)["value"])
            self.assertEqual([c.plane.cell_offset(r, col) for r in range(2) for col in range(2)], [32, 34, 33, 35])
            self.assertEqual([stride.plane.cell_offset(r, col) for r in range(2) for col in range(2)], [48, 50, 52, 54])

    def test_checksum_golden_mutation_and_partial(self):
        result = verify(self.stock)
        self.assertEqual([r["status"] for r in result], ["pass"] * 4)
        self.assertEqual(digest(self.stock.data), STOCK_SHA256)
        mutated = Image()
        data = bytearray(self.stock.data)
        data[0x9000] ^= 1
        mutated.add(Segment(0, bytes(data), {}))
        self.assertTrue(any(c["status"] == "fail" for c in verify(mutated)))
        sparse = Image()
        sparse.add(Segment(0x8200, bytes(data[0x8200:0x20000]), {}))
        result = verify(sparse)
        self.assertEqual(result[0]["status"], "fail")
        self.assertEqual([r["status"] for r in result[1:]], ["unavailable"] * 3)
        self.assertFalse(hasattr(reader(), "patch_data"))

    def test_identity_does_not_follow_size(self):
        self.assertEqual(compatibility(self.stock, self.definition)["state"], "known_stock")
        image = Image()
        image.add(Segment(0, b"\0" * ROM_SIZE, {}))
        self.assertEqual(compatibility(image, self.definition)["state"], "manually_selected_unverified_profile")
