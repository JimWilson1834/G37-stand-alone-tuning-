"""Read-only XDF cells, safe arithmetic and raw-byte-aware map comparisons."""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass, field
import math
import operator
from pathlib import Path
import struct
from xml.etree import ElementTree as ET

from . import STOCK_SHA256, XDF_SHA256
from .inputs import integer
from .model import Image, digest, identity


def evaluate(equation: str, value: int | float):
    """Walk a small arithmetic AST. No eval, calls, attributes or external names."""
    tree = ast.parse(equation.strip(), mode="eval")
    if len(list(ast.walk(tree))) > 128:
        raise ValueError("Expression too complex")
    binary = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
              ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
              ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor}

    def visit(n):
        if isinstance(n, ast.Expression):
            result = visit(n.body)
        elif isinstance(n, ast.Name) and n.id in {"X", "x"}:
            result = value
        elif isinstance(n, ast.Constant) and type(n.value) in {int, float}:
            result = n.value
        elif isinstance(n, ast.UnaryOp) and type(n.op) in {ast.USub, ast.UAdd, ast.Invert}:
            result = {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}[type(n.op)](visit(n.operand))
        elif isinstance(n, ast.BinOp) and type(n.op) in binary:
            result = binary[type(n.op)](visit(n.left), visit(n.right))
        else:
            raise ValueError(f"Unsupported expression operation {type(n).__name__}")
        if not math.isfinite(result) or abs(result) > 1e20:
            raise ValueError("Expression result outside finite arithmetic bounds")
        return result

    try:
        return visit(tree)
    except (ArithmeticError, TypeError) as ex:
        raise ValueError(f"Expression error: {ex}") from ex


def attributes(node, name):
    found = node.find(name)
    return dict(found.attrib) if found is not None else {}


@dataclass
class Plane:
    address: int | None
    bits: int
    rows: int
    columns: int
    flags: int
    major: int
    minor: int
    signed: bool
    endian: str
    floating: bool
    units: str
    equation: str
    variables: list[dict]
    storage: dict

    def cell_offset(self, row, column):
        if self.address is None:
            raise ValueError("Unresolved address")
        if self.bits not in {8, 16, 32, 64} or self.flags & ~0x10007:
            raise ValueError("Unsupported bit width or storage flags")
        if self.major < 0 or self.minor < 0 or self.major % 8 or self.minor % 8:
            raise ValueError("Unsupported negative or non-byte-aligned stride")
        if self.flags & 4:
            displacement = column * (self.major or self.rows * self.bits) + row * (self.minor or self.bits)
        else:
            displacement = row * (self.major or self.columns * self.bits) + column * (self.minor or self.bits)
        return self.address + displacement // 8

    def decode(self, image: Image, row=0, column=0, mask=None):
        cell = {"row": row, "column": column, "formula": self.equation,
                "lowercase_x_supported": "x" in self.equation, "units": self.units,
                "bits": self.bits, "byte_order": self.endian, "signed": self.signed}
        if self.address is None:
            return {**cell, "status": "unresolved", "address": None, "value": None}
        try:
            off = self.cell_offset(row, column)
            cell["address"] = off
            raw = image.read(off, self.bits // 8)
            cell["provenance"] = image.provenance(off, self.bits // 8)
            if raw is None:
                return {**cell, "status": "uncovered_or_conflicting", "value": None}
            cell["raw_hex"] = raw.hex()
            cell["raw_unsigned"] = int.from_bytes(raw, self.endian)
            if self.floating:
                if self.bits not in {32, 64}:
                    raise ValueError("Unsupported floating storage width")
                value = struct.unpack((">" if self.endian == "big" else "<") + ("f" if self.bits == 32 else "d"), raw)[0]
            else:
                value = int.from_bytes(raw, self.endian, signed=self.signed)
            cell["raw_value"] = value
            if mask is not None:
                cell.update(mask=mask, masked_value=cell["raw_unsigned"] & mask)
                result = bool(cell["raw_unsigned"] & mask)
            else:
                if any(v.get("id") not in {"X", "x"} or v.get("type", "0") != "0" for v in self.variables):
                    raise ValueError("Unsupported external MATH variable; metadata retained")
                result = evaluate(self.equation, value)
            return {**cell, "status": "decoded", "value": result}
        except (ValueError, SyntaxError) as ex:
            return {**cell, "status": "unsupported_or_error", "error": str(ex), "value": None}


@dataclass
class Object:
    object_id: str
    title: str
    kind: str
    plane: Plane
    categories: list[dict]
    axes: dict = field(default_factory=dict)
    mask: int | None = None
    description: str = ""


class Definition:
    def __init__(self, path):
        self.path = Path(path)
        raw = self.path.read_bytes()
        if len(raw) > 10 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("Unsupported XML declarations or oversized definition")
        root = ET.fromstring(raw)
        if root.tag != "XDFFORMAT":
            raise ValueError("Expected an XDF XML definition")
        header = root.find("XDFHEADER")
        if header is None:
            raise ValueError("Missing XDFHEADER")
        self.source = identity(self.path)
        self.defaults = attributes(header, "DEFAULTS")
        self.base = attributes(header, "BASEOFFSET")
        self.categories = [dict(n.attrib) for n in header.findall("CATEGORY")]
        self.regions = [dict(n.attrib) for n in header.findall("REGION")]
        self.objects = []
        self.warnings = []
        self.unsupported_objects = []
        for node in root:
            if node.tag == "XDFHEADER":
                continue
            if node.tag not in {"XDFTABLE", "XDFCONSTANT", "XDFFLAG"}:
                self.unsupported_objects.append({"id": node.get("uniqueid"), "kind": node.tag})
                continue
            value = node.find("XDFAXIS[@id='z']") if node.tag == "XDFTABLE" else node
            if value is None:
                raise ValueError(f"Missing value plane for {node.get('uniqueid')}")
            axes = {}
            for axis in node.findall("XDFAXIS"):
                if axis.get("id") == "z":
                    continue
                axes[axis.get("id")] = {"labels": [dict(n.attrib) for n in axis.findall("LABEL")],
                                        "units": axis.findtext("units", ""), "attributes": dict(axis.attrib),
                                        "indexcount": axis.findtext("indexcount"),
                                        "embedinfo": attributes(axis, "embedinfo"), "dalink": attributes(axis, "DALINK"),
                                        "plane": self.plane(axis)}
            self.objects.append(Object(node.get("uniqueid", ""), node.findtext("title", ""), node.tag,
                                       self.plane(value), [dict(n.attrib) for n in node.findall("CATEGORYMEM")],
                                       axes, integer(node.findtext("mask")) if node.findtext("mask") else None,
                                       node.findtext("description", "")))
        if self.source["sha256"] == XDF_SHA256:
            self.warnings.append("VVEL tail axis labels repeat; their physical meaning is unverified. Trimming bit 7 semantics unresolved.")

    def plane(self, node):
        storage = attributes(node, "EMBEDDEDDATA")
        flags = integer(storage.get("mmedtypeflags", "0"))
        explicit_flags = "mmedtypeflags" in storage
        addr = integer(storage["mmedaddress"]) if "mmedaddress" in storage else None
        if addr is not None:
            base = integer(self.base.get("offset", "0"))
            addr += -base if self.base.get("subtract", "0") == "1" else base
        bits = integer(storage.get("mmedelementsizebits", self.defaults.get("datasizeinbits", "8")))
        rows, cols = integer(storage.get("mmedrowcount", "1")), integer(storage.get("mmedcolcount", node.findtext("indexcount", "1")))
        if rows <= 0 or cols <= 0 or rows * cols > 1000000:
            raise ValueError("Unsupported table dimensions")
        math_node = node.find("MATH")
        equation = math_node.get("equation", "X") if math_node is not None else "X"
        return Plane(addr, bits, rows, cols, flags, integer(storage.get("mmedmajorstridebits", "0")),
                     integer(storage.get("mmedminorstridebits", "0")),
                     bool(flags & 1) if explicit_flags else self.defaults.get("signed", "0") == "1",
                     "little" if (bool(flags & 2) if explicit_flags else self.defaults.get("lsbfirst", "0") == "1") else "big",
                     bool(flags & 0x10000) if explicit_flags else self.defaults.get("float", "0") == "1",
                     node.findtext("units", ""), equation,
                     [dict(n.attrib) for n in math_node.findall("VAR")] if math_node is not None else [], storage)

    def summary(self):
        return {"source": self.source, "defaults": self.defaults, "base_offset": self.base, "regions": self.regions,
                "category_count": len(self.categories), "categories": self.categories,
                "object_counts": dict(Counter(o.kind for o in self.objects)),
                "unresolved_objects": sum(o.plane.address is None for o in self.objects),
                "unsupported_objects": self.unsupported_objects, "warnings": self.warnings}

    def cells(self, image: Image):
        objects_by_id = {o.object_id: o for o in self.objects}
        for obj in self.objects:
            axes = {}
            for name, axis in obj.axes.items():
                info = {k: v for k, v in axis.items() if k != "plane"}
                if axis["plane"].address is not None:
                    info["cells"] = [axis["plane"].decode(image, r, c)
                                     for r in range(axis["plane"].rows) for c in range(axis["plane"].columns)]
                elif info["embedinfo"].get("linkobjid") in objects_by_id:
                    linked = objects_by_id[info["embedinfo"]["linkobjid"]]
                    info["reference_status"] = "resolved_object"
                    info["cells"] = [linked.plane.decode(image, r, c, linked.mask)
                                     for r in range(linked.plane.rows) for c in range(linked.plane.columns)]
                else:
                    info["reference_status"] = "literal_labels" if info["labels"] else "unresolved"
                axes[name] = info
            yield {"object_id": obj.object_id, "title": obj.title, "kind": obj.kind, "description": obj.description,
                   "storage": obj.plane.storage, "categories": obj.categories, "axes": axes,
                   "cells": [obj.plane.decode(image, r, c, obj.mask)
                             for r in range(obj.plane.rows) for c in range(obj.plane.columns)]}

    def compare(self, a: Image, b: Image, start=0, end=None):
        end = min(a.size, b.size) if end is None else end
        changed = {i for i in range(start, end) if a.state[i] not in {0, 5} and b.state[i] not in {0, 5} and a.data[i] != b.data[i]}
        matched = set()
        differences = []
        for obj in self.objects:
            if obj.plane.address is None:
                continue
            for r in range(obj.plane.rows):
                for c in range(obj.plane.columns):
                    try:
                        off = obj.plane.cell_offset(r, c)
                    except ValueError:
                        continue
                    hits = changed.intersection(range(off, off + obj.plane.bits // 8))
                    if hits:
                        matched.update(hits)
                        differences.append({"object_id": obj.object_id, "title": obj.title,
                                            "before": obj.plane.decode(a, r, c, obj.mask),
                                            "after": obj.plane.decode(b, r, c, obj.mask)})
        return {"mapped_changed_bytes": len(matched), "unmapped_changed_bytes": len(changed - matched),
                "unmapped_addresses": sorted(changed - matched), "cell_differences": differences}


def compatibility(image: Image, definition: Definition, derivative=None):
    full = image.read(0, image.size)
    sha = digest(full) if full is not None else None
    if definition.source["sha256"] != XDF_SHA256:
        state = "manually_selected_unverified_profile"
    elif sha == STOCK_SHA256:
        state = "known_stock"
    elif derivative and derivative.get("rom_sha256") == sha and derivative.get("base_sha256") == STOCK_SHA256 and derivative.get("xdf_sha256") == XDF_SHA256:
        state = "verified_derivative_binding"
    elif full is not None:
        state = "manually_selected_unverified_profile"
    else:
        state = "unsupported_or_partial_calibration_identity"
    return {"state": state, "rom_sha256": sha, "xdf_sha256": definition.source["sha256"],
            "qualification": "Derivative sidecars bind declared lineage; size alone does not establish compatibility"}
