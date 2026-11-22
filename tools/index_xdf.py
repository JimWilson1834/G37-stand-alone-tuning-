"""Write a CSV index of the checked-in TunerPro definition to stdout."""
import csv
import sys
from pathlib import Path
from xml.etree import ElementTree

XDF = Path(__file__).resolve().parents[1] / "ACTUAL TOOL" / "DEF" / "TESTED.xdf"


def write_index(stream):
    root = ElementTree.parse(XDF).getroot()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("object_id", "type", "title", "address", "rows", "columns",
                     "element_bits", "storage_flags", "major_stride_bits",
                     "minor_stride_bits", "equation", "units", "flag_mask"))
    for obj in root:
        if obj.tag == "XDFHEADER":
            continue
        if obj.tag not in {"XDFCONSTANT", "XDFTABLE", "XDFFLAG"}:
            raise ValueError(f"Unknown XDF object type: {obj.tag}")
        is_table = obj.tag == "XDFTABLE"
        value = obj.find("XDFAXIS[@id='z']") if is_table else obj
        if value is None:
            raise ValueError(f"Missing value axis in {obj.get('uniqueid')}")
        element = value.find("EMBEDDEDDATA")
        fields = {} if element is None else element.attrib
        math = value.find("MATH")
        writer.writerow((
            obj.get("uniqueid"), obj.tag, obj.findtext("title"),
            fields.get("mmedaddress"), fields.get("mmedrowcount", "" if is_table else "1"),
            fields.get("mmedcolcount", "" if is_table else "1"),
            fields.get("mmedelementsizebits"), fields.get("mmedtypeflags"),
            fields.get("mmedmajorstridebits"), fields.get("mmedminorstridebits"),
            math.get("equation") if math is not None else "",
            value.findtext("units"), obj.findtext("mask"),
        ))


if __name__ == "__main__":
    # Configure the byte encoding and line endings consistently on Windows and Unix.
    sys.stdout.reconfigure(encoding="utf-8", newline="")
    write_index(sys.stdout)
