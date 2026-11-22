"""Reuse only the legacy standalone checker's read-only arithmetic, without Tk."""
import ast
from functools import lru_cache
from pathlib import Path
import types

from . import ROM_SIZE


@lru_cache(maxsize=1)
def reader():
    path = Path(__file__).resolve().parents[1] / "ACTUAL TOOL" / "g37_vq37_checksum_gui.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    allowed_imports = {"__future__", "dataclasses"}
    names = {"_need", "be16", "be32", "Checksums", "read_stored", "calc_checksums"}
    constants = {"ROM_SIZE", "LOW16_FIELD", "HIGH16_FIELD", "XOR32_FIELD", "ADD32_FIELD",
                 "LOW16_RANGE", "HIGH16_RANGE", "MAIN32_RANGE", "MAIN32_EXCLUDES"}
    selected = [n for n in tree.body if
                (isinstance(n, ast.ImportFrom) and n.module in allowed_imports) or
                (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names) or
                (isinstance(n, ast.Assign) and all(isinstance(t, ast.Name) and t.id in constants for t in n.targets))]
    module = types.ModuleType("_g37_legacy_readonly")
    # dataclasses consult sys.modules when postponed annotations are active.
    import sys
    sys.modules[module.__name__] = module
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), module.__dict__)
    return module


def verify(image):
    fields = [("low16_8200", 0x8200, 2, 0x8202, 0x20000),
              ("high16_20000", 0x20000, 2, 0x20002, ROM_SIZE),
              ("xor32_95f0", 0x95F0, 4, 0x8200, ROM_SIZE),
              ("add32_95f8", 0x95F8, 4, 0x8200, ROM_SIZE)]
    if image.size != ROM_SIZE:
        raise ValueError("Checksum integration requires exact ROM size")
    result = []
    calculated = None
    for name, off, width, start, end in fields:
        stored = image.read(off, width)
        available = stored is not None and image.read(start, end - start) is not None
        if available:
            if calculated is None:
                calculated = reader().calc_checksums(image.data)
            value = getattr(calculated, name)
            st = int.from_bytes(stored, "big")
            result.append({"field": name, "address": off, "stored": st, "calculated": value,
                           "status": "pass" if st == value else "fail",
                           "coverage": "recovered" if image.read(start, end - start, True) is not None and image.read(off, width, True) is not None else "includes_base_or_fill"})
        else:
            result.append({"field": name, "address": off, "stored": int.from_bytes(stored, "big") if stored is not None else None,
                           "calculated": None, "status": "unavailable", "reason": "Missing or conflicting required bytes"})
    return result
