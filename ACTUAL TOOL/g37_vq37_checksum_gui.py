#!/usr/bin/env python3
"""
G37 / VQ37 ECU checksum GUI

Known checksum fields from Ghidra work:
  0x8200  = BE16 sum over 0x8202..0x1FFFF. This includes the 0x95F0/0x95F8 fields, so patch it last.
  0x20000 = BE16 sum over 0x20002..0x17FFFF
  0x95F0  = BE32 XOR over 0x8200..0x17FFFF, excluding 0x8200, 0x95F0, 0x95F8, 0x20000
  0x95F8  = BE32 ADD over 0x8200..0x17FFFF, excluding same words

Expected input: a full 0x180000-byte ROM image with normal ECU addressing.
Works on Windows/Linux/macOS with standard Python 3 + tkinter.
"""
from __future__ import annotations

import argparse
import os
import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROM_SIZE = 0x180000
LOW16_FIELD = 0x8200
HIGH16_FIELD = 0x20000
XOR32_FIELD = 0x95F0
ADD32_FIELD = 0x95F8

LOW16_RANGE = (0x8202, 0x20000)      # end exclusive
HIGH16_RANGE = (0x20002, 0x180000)   # end exclusive
MAIN32_RANGE = (0x8200, 0x180000)    # end exclusive
MAIN32_EXCLUDES = {LOW16_FIELD, XOR32_FIELD, ADD32_FIELD, HIGH16_FIELD}


def _need(data: bytes | bytearray, end: int) -> None:
    if len(data) < end:
        raise ValueError(
            f"Input is too short: {len(data):#x} bytes. Need at least {end:#x} bytes for full checksum."
        )


def be16(data: bytes | bytearray, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "big")


def be32(data: bytes | bytearray, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


def put_be16(data: bytearray, off: int, value: int) -> None:
    data[off:off + 2] = (value & 0xFFFF).to_bytes(2, "big")


def put_be32(data: bytearray, off: int, value: int) -> None:
    data[off:off + 4] = (value & 0xFFFFFFFF).to_bytes(4, "big")


@dataclass(frozen=True)
class Checksums:
    low16_8200: int
    high16_20000: int
    xor32_95f0: int
    add32_95f8: int

    def as_lines(self, prefix: str = "") -> list[str]:
        return [
            f"{prefix}0x8200  BE16 lower sum : 0x{self.low16_8200:04X}",
            f"{prefix}0x20000 BE16 upper sum : 0x{self.high16_20000:04X}",
            f"{prefix}0x95F0  BE32 XOR       : 0x{self.xor32_95f0:08X}",
            f"{prefix}0x95F8  BE32 ADD       : 0x{self.add32_95f8:08X}",
        ]


def read_stored(data: bytes | bytearray) -> Checksums:
    _need(data, ROM_SIZE)
    return Checksums(
        low16_8200=be16(data, LOW16_FIELD),
        high16_20000=be16(data, HIGH16_FIELD),
        xor32_95f0=be32(data, XOR32_FIELD),
        add32_95f8=be32(data, ADD32_FIELD),
    )


def calc_checksums(data: bytes | bytearray) -> Checksums:
    _need(data, ROM_SIZE)

    low_sum = 0
    for off in range(LOW16_RANGE[0], LOW16_RANGE[1], 2):
        low_sum = (low_sum + be16(data, off)) & 0xFFFF

    high_sum = 0
    for off in range(HIGH16_RANGE[0], HIGH16_RANGE[1], 2):
        high_sum = (high_sum + be16(data, off)) & 0xFFFF

    xor32 = 0
    add32 = 0
    for off in range(MAIN32_RANGE[0], MAIN32_RANGE[1], 4):
        if off in MAIN32_EXCLUDES:
            continue
        word = be32(data, off)
        xor32 ^= word
        add32 = (add32 + word) & 0xFFFFFFFF

    return Checksums(low_sum, high_sum, xor32, add32)


def patch_data(data: bytes | bytearray) -> tuple[bytearray, Checksums, Checksums]:
    _need(data, ROM_SIZE)
    out = bytearray(data)
    before = read_stored(out)

    # Order matters:
    #   - 0x95F0/0x95F8 are inside the 0x8202..0x1FFFF lower 16-bit sum range.
    #   - the 32-bit XOR/ADD excludes 0x8200, 0x95F0, 0x95F8, and 0x20000.
    # Therefore patch 0x20000 and 0x95F0/0x95F8 first, then compute/write 0x8200 last.
    first = calc_checksums(out)
    put_be16(out, HIGH16_FIELD, first.high16_20000)
    put_be32(out, XOR32_FIELD, first.xor32_95f0)
    put_be32(out, ADD32_FIELD, first.add32_95f8)

    final = calc_checksums(out)
    put_be16(out, LOW16_FIELD, final.low16_8200)

    after = read_stored(out)
    return out, before, after


def checksum_match(stored: Checksums, calc: Checksums) -> bool:
    return stored == calc


def diff_checksum_fields(a: bytes | bytearray, b: bytes | bytearray) -> list[str]:
    fields = [
        (LOW16_FIELD, 2, "0x8200 lower BE16"),
        (HIGH16_FIELD, 2, "0x20000 upper BE16"),
        (XOR32_FIELD, 4, "0x95F0 XOR32"),
        (ADD32_FIELD, 4, "0x95F8 ADD32"),
    ]
    lines = []
    for off, size, name in fields:
        av = int.from_bytes(a[off:off + size], "big")
        bv = int.from_bytes(b[off:off + size], "big")
        ok = "MATCH" if av == bv else "DIFF "
        fmt = f"0x{{:0{size * 2}X}}"
        lines.append(f"{ok} {name:<20} patched={fmt.format(av)}  reference={fmt.format(bv)}")
    return lines


def count_diffs(a: bytes | bytearray, b: bytes | bytearray, start: int = 0, end: int | None = None) -> tuple[int, list[tuple[int, int, int]]]:
    if end is None:
        end = min(len(a), len(b))
    diffs = []
    count = 0
    for off in range(start, end):
        if a[off] != b[off]:
            count += 1
            if len(diffs) < 50:
                diffs.append((off, a[off], b[off]))
    return count, diffs


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("G37 / VQ37 ECU Checksum Tool")
        self.geometry("980x680")
        self.minsize(860, 560)

        self.input_path = tk.StringVar()
        self.ref_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.make_backup = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 5}
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True)

        row = 0
        ttk.Label(frm, text="Input BIN to check/patch:").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.input_path, width=90).grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse", command=self.browse_input).grid(row=row, column=2, **pad)

        row += 1
        ttk.Label(frm, text="Optional HPT/reference BIN:").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.ref_path, width=90).grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse", command=self.browse_ref).grid(row=row, column=2, **pad)

        row += 1
        ttk.Label(frm, text="Output patched BIN:").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.output_path, width=90).grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Save As", command=self.browse_output).grid(row=row, column=2, **pad)

        row += 1
        opts = ttk.Frame(frm)
        opts.grid(row=row, column=0, columnspan=3, sticky="w", **pad)
        ttk.Checkbutton(opts, text="Make .bak when overwriting", variable=self.make_backup).pack(side="left")

        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="ew", **pad)
        ttk.Button(btns, text="Validate Input", command=self.validate_input).pack(side="left", padx=4)
        ttk.Button(btns, text="Patch and Save", command=self.patch_and_save).pack(side="left", padx=4)
        ttk.Button(btns, text="Compare Patched Output to Reference", command=self.compare_output_ref).pack(side="left", padx=4)
        ttk.Button(btns, text="Clear Log", command=lambda: self.log.delete("1.0", "end")).pack(side="left", padx=4)

        row += 1
        info = (
            "Algorithm: 0x8200=sum16(0x8202..0x1FFFF, patched last), "
            "0x20000=sum16(0x20002..0x17FFFF), "
            "0x95F0=XOR32 and 0x95F8=ADD32 over 0x8200..0x17FFFF excluding 0x8200/0x95F0/0x95F8/0x20000."
        )
        ttk.Label(frm, text=info, wraplength=920).grid(row=row, column=0, columnspan=3, sticky="w", **pad)

        row += 1
        self.log = tk.Text(frm, wrap="none", height=28)
        self.log.grid(row=row, column=0, columnspan=3, sticky="nsew", padx=8, pady=8)
        yscroll = ttk.Scrollbar(frm, orient="vertical", command=self.log.yview)
        yscroll.grid(row=row, column=3, sticky="ns")
        self.log.configure(yscrollcommand=yscroll.set)

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(row, weight=1)

    def write(self, text: str = "") -> None:
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.update_idletasks()

    def browse_input(self) -> None:
        path = filedialog.askopenfilename(title="Select BIN", filetypes=[("BIN files", "*.bin"), ("All files", "*.*")])
        if path:
            self.input_path.set(path)
            if not self.output_path.get():
                p = Path(path)
                self.output_path.set(str(p.with_name(p.stem + "_checksum_fixed" + p.suffix)))

    def browse_ref(self) -> None:
        path = filedialog.askopenfilename(title="Select reference/HPT BIN", filetypes=[("BIN files", "*.bin"), ("All files", "*.*")])
        if path:
            self.ref_path.set(path)

    def browse_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Save patched BIN", defaultextension=".bin", filetypes=[("BIN files", "*.bin"), ("All files", "*.*")])
        if path:
            self.output_path.set(path)

    def load_bin(self, path: str) -> bytes:
        if not path:
            raise ValueError("No file selected.")
        data = Path(path).read_bytes()
        if len(data) != ROM_SIZE:
            self.write(f"WARNING: file size is {len(data):#x}, expected full ROM size {ROM_SIZE:#x}.")
            self.write("         The tool will still run only if the required full range exists.")
        _need(data, ROM_SIZE)
        return data

    def validate_input(self) -> None:
        try:
            path = self.input_path.get()
            data = self.load_bin(path)
            stored = read_stored(data)
            calc = calc_checksums(data)
            self.write("=" * 80)
            self.write(f"Validate: {path}")
            self.write(f"File size: {len(data):#x}")
            self.write("Stored fields:")
            for line in stored.as_lines("  "):
                self.write(line)
            self.write("Calculated fields:")
            for line in calc.as_lines("  "):
                self.write(line)
            self.write(f"Result: {'PASS - stored checksums match calculated values' if stored == calc else 'FAIL - needs checksum patch'}")
        except Exception as e:
            messagebox.showerror("Validation error", str(e))
            self.write(f"ERROR: {e}")

    def patch_and_save(self) -> None:
        try:
            in_path = self.input_path.get()
            out_path = self.output_path.get()
            if not out_path:
                raise ValueError("Choose an output path first.")
            data = self.load_bin(in_path)
            patched, before, after = patch_data(data)
            out = Path(out_path)
            if out.exists() and self.make_backup.get():
                backup = out.with_suffix(out.suffix + ".bak")
                backup.write_bytes(out.read_bytes())
                self.write(f"Backup written: {backup}")
            out.write_bytes(patched)
            self.write("=" * 80)
            self.write(f"Patched: {in_path}")
            self.write(f"Saved:   {out_path}")
            self.write("Before stored fields:")
            for line in before.as_lines("  "):
                self.write(line)
            self.write("After stored fields:")
            for line in after.as_lines("  "):
                self.write(line)
            verify = calc_checksums(patched)
            self.write(f"Post-save verify: {'PASS' if after == verify else 'FAIL'}")
        except Exception as e:
            messagebox.showerror("Patch error", str(e))
            self.write(f"ERROR: {e}")

    def compare_output_ref(self) -> None:
        try:
            out_path = self.output_path.get() or self.input_path.get()
            ref_path = self.ref_path.get()
            patched = self.load_bin(out_path)
            ref = self.load_bin(ref_path)
            self.write("=" * 80)
            self.write(f"Compare patched/output: {out_path}")
            self.write(f"Against reference:       {ref_path}")
            self.write("Checksum field comparison:")
            for line in diff_checksum_fields(patched, ref):
                self.write("  " + line)
            total, first = count_diffs(patched, ref, 0, min(len(patched), len(ref)))
            self.write(f"Total byte diffs over common file length: {total}")
            if first:
                self.write("First diffs:")
                for off, a, b in first:
                    self.write(f"  0x{off:06X}: output=0x{a:02X} reference=0x{b:02X}")
        except Exception as e:
            messagebox.showerror("Compare error", str(e))
            self.write(f"ERROR: {e}")


def cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="G37/VQ37 ECU checksum patcher")
    ap.add_argument("input", nargs="?", help="input full 0x180000 BIN")
    ap.add_argument("output", nargs="?", help="output patched BIN")
    ap.add_argument("--check", action="store_true", help="validate only; do not write")
    ap.add_argument("--compare", help="optional reference BIN to compare checksum fields against after patch/check")
    args = ap.parse_args(argv)

    if not args.input:
        App().mainloop()
        return 0

    data = Path(args.input).read_bytes()
    _need(data, ROM_SIZE)
    stored = read_stored(data)
    calc = calc_checksums(data)
    print("Stored:")
    print("\n".join(stored.as_lines("  ")))
    print("Calculated:")
    print("\n".join(calc.as_lines("  ")))
    print("Status:", "PASS" if stored == calc else "FAIL/NEEDS PATCH")

    if args.check:
        return 0 if stored == calc else 2

    if not args.output:
        raise SystemExit("Output path required unless --check is used")

    patched, before, after = patch_data(data)
    Path(args.output).write_bytes(patched)
    print(f"Wrote patched BIN: {args.output}")
    print("After:")
    print("\n".join(after.as_lines("  ")))

    if args.compare:
        ref = Path(args.compare).read_bytes()
        _need(ref, ROM_SIZE)
        print("Compare checksum fields to reference:")
        for line in diff_checksum_fields(patched, ref):
            print("  " + line)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(cli(sys.argv[1:]))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
