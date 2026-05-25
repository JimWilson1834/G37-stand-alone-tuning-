#!/usr/bin/env python3
"""
G37 / VQ37 Hitachi SH705x HPT-style GUI flasher - ECU SERVER/REAL-ECU TEST BUILD v12

Purpose
-------
This is a test flasher for Jim's ECU server/emulator workflow and guarded real-ECU testing. It generates the
same family of HPT-style 0x34 records from a full 0x180000 BIN and sends them
via ISO-TP over Linux SocketCAN or Windows J2534/OpenPort raw CAN. v6 adds a saved base/reference BIN workflow for HPT-like safety checks.

Use on the ECU server first. Do not use on a real vehicle/ECU until the server
trace compares correctly and you are ready for live-risk testing. v9 keeps the longer live timeouts, adds explicit failure protocols, and changes the post-flash key cycle to the HPT-like flow: key OFF for 3 seconds, key ON, click OK, then send the final 10 81 cleanup request. v11 fixes ISO-TP FlowControl handling. v12 adds audited failure tracking for records attempted-vs-ACKed, a more tolerant FlowControl auto mode for imperfect servers, and safer warnings if any 34 record was transmitted but not ACKed.

Known HPT route implemented:
    10 85
    27 81 / 27 82 security unlock
    31 81 <mode> F0 5A     where mode 0x81=partial, 0x82=full
    poll 31 81 01 until 71 81 02
    repeated 34 <mode> <addr24> 80 <encoded 0x80 bytes> <crc trailer>
    31 82 00
    31 82 01
    34 83 00 00 00 30 FF..FF <crc trailer>
    HPT-like key cycle prompt
    10 81

Record transform:
    Raw BIN bytes -> inverse of ECU FUN_000044B0(key=0x6E6C2EE9) -> 0x34 payload

Checksum patching:
    0x8200  = BE16 sum over 0x8202-0x1FFFF
    0x20000 = BE16 sum over 0x20002-0x17FFFF
    0x95F0  = XOR32 over 0x8200-0x17FFFF excluding 0x8200, 0x95F0, 0x95F8, 0x20000
    0x95F8  = ADD32 over same range/exclusions

Notes
-----
- Live sending supports Linux SocketCAN or Windows J2534/OpenPort raw CAN. Use J2534 on Windows.
- SecurityAccess uses the recovered dynamic 27 81/27 82 seed-key algorithm plus manual override.
  Current built-in examples include A64075C3 -> 2F2344B0 and 11058C29 -> 7F168536.
  There is also a server-only checkbox to skip 27 unlock for emulator testing.
- Dry-run/build mode is safe and writes a .records.txt file without sending CAN.
"""

from __future__ import annotations

import os
import json
import hashlib
import socket
import struct
import threading
import time
import traceback
from ctypes import CDLL, Structure, byref, c_ulong, c_void_p, c_ubyte, create_string_buffer
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

# -----------------------------
# Constants
# -----------------------------

ROM_SIZE = 0x180000
DEFAULT_TX_ID = 0x7E0
DEFAULT_RX_ID = 0x7E8
DEFAULT_KEY = 0x6E6C2EE9
CRC_TARGET = 0xF0B8

PARTIAL_START = 0x008200
PARTIAL_END = 0x020000
FULL_START = 0x008200
FULL_END = 0x180000
BLOCK_LEN = 0x80
CONFIG_PATH = Path.home() / ".g37_hpt_flasher_gui_config.json"

# Conservative live-ECU timeouts. The emulator responds quickly, but real ECUs can
# sit in busy/pending states during erase/finalize. These values deliberately wait
# longer than the early server-only builds.
BASE_RESPONSE_TIMEOUT = 10.0
SESSION_TIMEOUT = 10.0
SECURITY_TIMEOUT = 10.0
PREPARE_START_TIMEOUT = 20.0
PREPARE_POLL_TIMEOUT = 15.0
PREPARE_MAX_SECONDS = 180.0
RECORD_ACK_TIMEOUT = 12.0
FINALIZE_START_TIMEOUT = 60.0
FINALIZE_POLL_TIMEOUT = 20.0
FINALIZE_MAX_SECONDS = 240.0
FINAL83_TIMEOUT = 60.0
CLEANUP_TIMEOUT = 30.0
KEY_CYCLE_VERIFY_TIMEOUT = 20.0

FINAL83_PAYLOAD = bytes.fromhex(
    "34 83 00 00 00 30 " + ("FF " * 48)
)

KNOWN_SECURITY_KEYS = {
    # Pairs observed/confirmed in HPT logs / probes.
    0xA64075C3: 0x2F2344B0,
    0x11058C29: 0x7F168536,
    0x6D82F406: 0xF7C5902E,
    0x9B9A3DEE: 0xDFD52A56,
}

# -----------------------------
# 0x44B0 transform + inverse
# -----------------------------

def u16(x: int) -> int:
    return x & 0xFFFF


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def mix_4578(target: int, other: int, key_part: int) -> int:
    x = u16(other + key_part)
    t_full = (x << 1)
    t_full = t_full + (t_full >> 16) + x - 1
    t = u16(t_full)
    m_full = (t << 4)
    m_full = m_full + (m_full >> 16)
    return u16(target ^ t ^ m_full)


def mix_454e(target: int, other: int, key_part: int) -> int:
    x = u16(other + key_part)
    m_full = (x << 2)
    m_full = m_full + (m_full >> 16) + x - 1
    return u16(target ^ m_full)


def decode_44b0(encoded: bytes, key: int = DEFAULT_KEY) -> bytes:
    if len(encoded) % 4:
        raise ValueError("0x44B0 length must be multiple of 4")
    high = (key >> 16) & 0xFFFF
    low = key & 0xFFFF
    out = bytearray()
    for i in range(0, len(encoded), 4):
        a = (encoded[i] << 8) | encoded[i + 1]
        b = (encoded[i + 2] << 8) | encoded[i + 3]
        a = mix_4578(a, b, low)
        a, b = b, a
        a = mix_454e(a, b, high)
        out.extend(((a >> 8) & 0xFF, a & 0xFF, (b >> 8) & 0xFF, b & 0xFF))
    return bytes(out)


def encode_44b0(raw: bytes, key: int = DEFAULT_KEY) -> bytes:
    """Inverse of decode_44b0. Converts desired flash bytes into ECU/HPT 0x34 payload bytes."""
    if len(raw) % 4:
        raise ValueError("0x44B0 inverse length must be multiple of 4")
    high = (key >> 16) & 0xFFFF
    low = key & 0xFFFF
    out = bytearray()
    for i in range(0, len(raw), 4):
        raw0 = (raw[i] << 8) | raw[i + 1]
        raw1 = (raw[i + 2] << 8) | raw[i + 3]
        # Decode relation:
        #   a1 = enc_a mixed with enc_b using low key
        #   output = [enc_b mixed with a1 using high key, a1]
        # Therefore raw1 == a1, raw0 == enc_b ^ g(raw1+high).
        enc_b = mix_454e(raw0, raw1, high)
        enc_a = mix_4578(raw1, enc_b, low)
        out.extend(((enc_a >> 8) & 0xFF, enc_a & 0xFF, (enc_b >> 8) & 0xFF, enc_b & 0xFF))
    return bytes(out)

# -----------------------------
# ECU record CRC16 / trailer
# -----------------------------

POLY = 0x8408


def crc16_ecu(data: bytes, init: int = 0xFFFF) -> int:
    crc = init & 0xFFFF
    for b in data:
        v = b
        for _ in range(8):
            bit = crc & 1
            crc = (crc & 0xFFFF) >> 1
            if bit != (v & 1):
                crc ^= POLY
            v >>= 1
    return crc & 0xFFFF


def crc_update_byte(crc: int, b: int) -> int:
    return crc16_ecu(bytes([b]), crc)


def crc_update_bit(old: int, data_bit: int) -> int:
    bit = old & 1
    crc = (old & 0xFFFF) >> 1
    if bit != data_bit:
        crc ^= POLY
    return crc & 0xFFFF


def crc_reverse_update_byte(next_crc: int, b: int) -> int:
    """Reverse crc_update_byte for one known byte."""
    state = next_crc & 0xFFFF
    for i in range(7, -1, -1):
        d = (b >> i) & 1
        found = None
        for old_lsb in (0, 1):
            tmp = state ^ (POLY if (old_lsb != d) else 0)
            if tmp <= 0x7FFF:
                old = ((tmp << 1) & 0xFFFF) | old_lsb
                if crc_update_bit(old, d) == state:
                    found = old
                    break
        if found is None:
            raise RuntimeError("CRC reverse failed")
        state = found
    return state & 0xFFFF


def make_crc_trailer(prefix: bytes, target: int = CRC_TARGET) -> bytes:
    """Find two trailer bytes so crc16_ecu(prefix + trailer) == target."""
    s0 = crc16_ecu(prefix)
    forward = {}
    for b1 in range(256):
        forward[crc_update_byte(s0, b1)] = b1
    for b2 in range(256):
        need_s1 = crc_reverse_update_byte(target, b2)
        b1 = forward.get(need_s1)
        if b1 is not None:
            trailer = bytes([b1, b2])
            if crc16_ecu(prefix + trailer) == target:
                return trailer
    raise RuntimeError("Could not build CRC trailer")

# -----------------------------
# BIN checksum patcher
# -----------------------------

def be16(data: bytes | bytearray, off: int) -> int:
    return (data[off] << 8) | data[off + 1]


def put_be16(data: bytearray, off: int, value: int) -> None:
    data[off] = (value >> 8) & 0xFF
    data[off + 1] = value & 0xFF


def be32(data: bytes | bytearray, off: int) -> int:
    return (data[off] << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3]


def put_be32(data: bytearray, off: int, value: int) -> None:
    data[off] = (value >> 24) & 0xFF
    data[off + 1] = (value >> 16) & 0xFF
    data[off + 2] = (value >> 8) & 0xFF
    data[off + 3] = value & 0xFF


def sum16_words(data: bytes | bytearray, start: int, end_exclusive: int) -> int:
    total = 0
    for off in range(start, end_exclusive, 2):
        total = (total + be16(data, off)) & 0xFFFF
    return total


def compute_bin_checksums(data: bytes | bytearray) -> dict:
    if len(data) != ROM_SIZE:
        raise ValueError(f"Expected 0x{ROM_SIZE:X} bytes, got 0x{len(data):X}")
    lower = sum16_words(data, 0x8202, 0x20000)
    upper = sum16_words(data, 0x20002, 0x180000)
    xor32 = 0
    add32 = 0
    excludes = {0x8200, 0x95F0, 0x95F8, 0x20000}
    for off in range(0x8200, 0x180000, 4):
        if off in excludes:
            continue
        w = be32(data, off)
        xor32 ^= w
        add32 = (add32 + w) & 0xFFFFFFFF
    return {"8200": lower, "20000": upper, "95F0": xor32, "95F8": add32}


def patch_bin_checksums(data: bytes | bytearray) -> bytes:
    """
    Patch all four known ROM checksum fields.

    Order matters:
      - 0x95F0 / 0x95F8 are excluded from the 32-bit XOR/ADD calculation.
      - 0x8200 is excluded from the 32-bit XOR/ADD calculation.
      - BUT the 0x8200 lower 16-bit sum covers 0x8202-0x1FFFF,
        which includes the bytes at 0x95F0 and 0x95F8.

    Therefore, write 0x95F0/0x95F8 first, then recompute/write 0x8200 last.
    """
    out = bytearray(data)

    # First compute and write fields that do not depend on stored 0x8200/0x20000/0x95F0/0x95F8.
    c = compute_bin_checksums(out)
    put_be32(out, 0x95F0, c["95F0"])
    put_be32(out, 0x95F8, c["95F8"])
    put_be16(out, 0x20000, c["20000"])

    # Now recompute 0x8200 after 0x95F0/0x95F8 have changed, because lower sum includes them.
    lower = sum16_words(out, 0x8202, 0x20000)
    put_be16(out, 0x8200, lower)

    # Final self-check.
    final = compute_bin_checksums(out)
    if be16(out, 0x8200) != final["8200"]:
        raise RuntimeError("checksum self-check failed at 0x8200")
    if be16(out, 0x20000) != final["20000"]:
        raise RuntimeError("checksum self-check failed at 0x20000")
    if be32(out, 0x95F0) != final["95F0"]:
        raise RuntimeError("checksum self-check failed at 0x95F0")
    if be32(out, 0x95F8) != final["95F8"]:
        raise RuntimeError("checksum self-check failed at 0x95F8")

    return bytes(out)



# -----------------------------
# Base/reference config + analysis
# -----------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text())
    except Exception:
        pass
    return {}


def save_config(cfg: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2, sort_keys=True))
    except Exception:
        pass


def checksum_status_text(data: bytes) -> str:
    c = compute_bin_checksums(data)
    stored = {
        "8200": be16(data, 0x8200),
        "20000": be16(data, 0x20000),
        "95F0": be32(data, 0x95F0),
        "95F8": be32(data, 0x95F8),
    }
    ok = all(stored[k] == c[k] for k in c)
    return (
        f"checksums {'OK' if ok else 'BAD'} | "
        f"8200 stored/calc {stored['8200']:04X}/{c['8200']:04X}, "
        f"20000 {stored['20000']:04X}/{c['20000']:04X}, "
        f"95F0 {stored['95F0']:08X}/{c['95F0']:08X}, "
        f"95F8 {stored['95F8']:08X}/{c['95F8']:08X}"
    )


def analyze_base_vs_target(base_path: Optional[Path], target_data: bytes, log: Callable[[str], None]) -> None:
    if not base_path or not str(base_path).strip():
        log("No base/reference BIN selected. HPT-style fixed partial/full writes are still available, but partial write assumes the ECU already matches the unwritten upper region.")
        return
    if not base_path.exists():
        log(f"Base/reference BIN not found: {base_path}")
        return
    base = base_path.read_bytes()
    if len(base) != ROM_SIZE:
        log(f"Base/reference BIN size is wrong: 0x{len(base):X}; expected 0x{ROM_SIZE:X}. Safety analysis skipped.")
        return
    if len(target_data) != ROM_SIZE:
        log("Target size is wrong. Safety analysis skipped.")
        return

    changed = []
    min_off = None
    max_off = None
    changed_blocks = set()
    changed_above_partial = False
    changed_before_writable = False
    for i, (a, b) in enumerate(zip(base, target_data)):
        if a != b:
            if min_off is None:
                min_off = i
            max_off = i
            changed.append(i)
            if i < FULL_START:
                changed_before_writable = True
            if i >= PARTIAL_END:
                changed_above_partial = True
            if FULL_START <= i < FULL_END:
                changed_blocks.add(i & ~(BLOCK_LEN - 1))

    if min_off is None:
        log("Base/reference analysis: target is byte-for-byte identical to base after checksum patching.")
        log("Recommended mode: partial is enough for server testing; full also works but is unnecessary.")
        return

    log(f"Base/reference analysis: {len(changed)} changed byte(s), {len(changed_blocks)} changed 0x80 block(s).")
    log(f"Changed range: 0x{min_off:06X}-0x{max_off:06X}.")
    if changed_before_writable:
        log("WARNING: Target differs before 0x008200. This HPT-style route will NOT write that protected/front region.")
    if changed_above_partial:
        log("Recommended mode: FULL. Target differs at or above 0x020000, outside HPT-style partial range.")
    else:
        log("Recommended mode: PARTIAL. All target differences are inside 0x008200-0x01FFFF or checksum fields in that lower range.")

# -----------------------------
# Record builder
# -----------------------------

@dataclass
class FlashRecord:
    subtype: int
    address: int
    raw_payload: bytes
    encoded_payload: bytes
    payload: bytes  # full UDS 0x34 payload including trailer


def build_34_record(subtype: int, address: int, raw_payload: bytes) -> FlashRecord:
    if len(raw_payload) != BLOCK_LEN:
        raise ValueError("Only 0x80-byte records are supported")
    encoded = encode_44b0(raw_payload)
    prefix = bytes([0x34, subtype, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF, BLOCK_LEN]) + encoded
    trailer = make_crc_trailer(prefix)
    payload = prefix + trailer
    if crc16_ecu(payload) != CRC_TARGET:
        raise AssertionError("record CRC self-test failed")
    return FlashRecord(subtype, address, raw_payload, encoded, payload)


def build_final83_payload() -> bytes:
    trailer = make_crc_trailer(FINAL83_PAYLOAD)
    p = FINAL83_PAYLOAD + trailer
    if crc16_ecu(p) != CRC_TARGET:
        raise AssertionError("final83 CRC self-test failed")
    return p


def iter_flash_records(rom: bytes, mode: str, progress: Optional[Callable[[str], None]] = None) -> Iterable[FlashRecord]:
    if mode == "partial":
        subtype, start, end = 0x81, PARTIAL_START, PARTIAL_END
    elif mode == "full":
        subtype, start, end = 0x82, FULL_START, FULL_END
    else:
        raise ValueError("mode must be partial or full")
    for idx, addr in enumerate(range(start, end, BLOCK_LEN), 1):
        if progress and (idx == 1 or idx % 100 == 0):
            progress(f"Building record {idx} @ 0x{addr:06X}")
        yield build_34_record(subtype, addr, rom[addr:addr + BLOCK_LEN])


# -----------------------------
# J2534 constants / helpers
# -----------------------------

J2534_STATUS_NOERROR = 0x00
J2534_CAN = 0x00000005
J2534_ISO15765 = 0x00000006
J2534_ISO15765_FRAME_PAD = 0x00000040
J2534_PASS_FILTER = 0x00000001
J2534_CLEAR_MSG_FILTERS = 0x0000000A
J2534_START_MSG_FILTER = 0x0000000B

class PASSTHRU_MSG(Structure):
    _fields_ = [
        ("ProtocolID", c_ulong),
        ("RxStatus", c_ulong),
        ("TxFlags", c_ulong),
        ("Timestamp", c_ulong),
        ("DataSize", c_ulong),
        ("ExtraDataIndex", c_ulong),
        ("Data", c_ubyte * 4128),
    ]


def make_pt_msg(protocol_id: int, data: bytes, tx_flags: int = 0) -> PASSTHRU_MSG:
    msg = PASSTHRU_MSG()
    msg.ProtocolID = protocol_id
    msg.RxStatus = 0
    msg.TxFlags = tx_flags
    msg.Timestamp = 0
    msg.DataSize = len(data)
    msg.ExtraDataIndex = 0
    for i, b in enumerate(data):
        msg.Data[i] = b
    return msg


def pt_msg_data(msg: PASSTHRU_MSG) -> bytes:
    return bytes(int(msg.Data[i]) & 0xFF for i in range(int(msg.DataSize)))

# -----------------------------
# SocketCAN ISO-TP minimal transport
# -----------------------------

class SocketCanIsoTp:
    def __init__(self, iface: str, tx_id: int, rx_id: int, log: Callable[[str], None], timeout: float = 2.0):
        self.iface = iface
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.log = log
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.sock.bind((self.iface,))
        self.sock.settimeout(self.timeout)
        self.log(f"Opened SocketCAN {self.iface}, TX=0x{self.tx_id:X}, RX=0x{self.rx_id:X}")

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_can(self, can_id: int, data: bytes) -> None:
        if not self.sock:
            raise RuntimeError("CAN socket not open")
        if len(data) > 8:
            raise ValueError("CAN frame data > 8")
        frame = struct.pack("=IB3x8s", can_id, len(data), data.ljust(8, b"\x00"))
        self.sock.send(frame)

    def recv_can(self, wanted_id: Optional[int] = None, timeout: Optional[float] = None) -> Tuple[int, bytes]:
        if not self.sock:
            raise RuntimeError("CAN socket not open")
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                frame = self.sock.recv(16)
                can_id, dlc, data = struct.unpack("=IB3x8s", frame)
                can_id &= 0x1FFFFFFF
                data = data[:dlc]
                if wanted_id is None or can_id == wanted_id:
                    return can_id, data
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)

    def _wait_flow_control(self, timeout: Optional[float] = None) -> tuple[int, float]:
        """Wait for ISO-TP FlowControl and return (block_size, stmin_seconds)."""
        wait_timeout = self.timeout if timeout is None else timeout
        while True:
            _, fc = self.recv_can(self.rx_id, timeout=wait_timeout)
            if not fc or (fc[0] >> 4) != 0x3:
                # Ignore echoes/stale non-FC frames while waiting for FC.
                continue
            fs = fc[0] & 0x0F
            if fs == 0x1:
                # Wait frame: give ECU/server another moment, then keep waiting.
                time.sleep(0.05)
                continue
            if fs != 0x0:
                raise RuntimeError(f"FlowControl not CTS: {fc.hex()}")
            bs = fc[1] if len(fc) > 1 else 0
            st = fc[2] if len(fc) > 2 else 0
            if st <= 0x7F:
                stmin = st / 1000.0
            elif 0xF1 <= st <= 0xF9:
                stmin = (st - 0xF0) / 10000.0
            else:
                stmin = 0.0
            return bs, stmin

    def send_isotp(self, payload: bytes, tx_id: Optional[int] = None) -> None:
        tx = self.tx_id if tx_id is None else tx_id
        n = len(payload)
        if n <= 7:
            self.send_can(tx, bytes([n]) + payload)
            return
        if n > 0xFFF:
            raise ValueError("This minimal ISO-TP sender only supports <= 4095 byte payloads")
        self.send_can(tx, bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6])
        block_size, stmin = self._wait_flow_control()
        off = 6
        sn = 1
        sent_in_block = 0
        while off < n:
            chunk = payload[off:off + 7]
            self.send_can(tx, bytes([0x20 | (sn & 0x0F)]) + chunk)
            off += len(chunk)
            sn = (sn + 1) & 0x0F
            sent_in_block += 1
            if stmin > 0:
                time.sleep(stmin)
            # If ECU/server requested a finite block size, try to wait for the next FC.
            # Some simple ECU-server emulators incorrectly send BS=1 once and never send
            # follow-up FC frames. In that case, continue in a logged compatibility mode
            # instead of hanging forever. A real ECU that truly enforces BS should send
            # the next FC promptly.
            if off < n and block_size and sent_in_block >= block_size:
                try:
                    block_size, stmin = self._wait_flow_control(timeout=0.75)
                    sent_in_block = 0
                except TimeoutError:
                    self.log("WARNING: finite ISO-TP block size requested but no follow-up FlowControl arrived; continuing stream in compatibility mode")
                    block_size = 0
                    sent_in_block = 0

    def recv_isotp(self, timeout: Optional[float] = None) -> bytes:
        deadline = time.time() + (timeout or self.timeout)
        while True:
            _, data = self.recv_can(self.rx_id, timeout=max(0.001, deadline - time.time()))
            if not data:
                raise RuntimeError("empty CAN frame")
            pci = data[0]
            typ = pci >> 4
            # FlowControl is not an application response; it can be left over on some links.
            # Ignore it while waiting for the real UDS response.
            if typ == 0x3:
                self.log(f"Ignored stale FlowControl while waiting response: {data.hex(' ').upper()}")
                if time.time() >= deadline:
                    raise TimeoutError("Only FlowControl frames seen while waiting for ISO-TP response")
                continue
            if typ == 0x0:
                ln = pci & 0x0F
                return data[1:1 + ln]
            if typ == 0x1:
                total = ((pci & 0x0F) << 8) | data[1]
                buf = bytearray(data[2:])
                self.send_can(self.tx_id, bytes([0x30, 0x00, 0x00]))
                expect_sn = 1
                while len(buf) < total:
                    _, cf = self.recv_can(self.rx_id, timeout=max(0.001, deadline - time.time()))
                    if not cf or (cf[0] >> 4) != 0x2:
                        continue
                    # tolerate SN mismatch; server testing is more important than strictness here
                    buf.extend(cf[1:])
                    expect_sn = (expect_sn + 1) & 0x0F
                return bytes(buf[:total])
            raise RuntimeError(f"Unexpected ISO-TP PCI: {data.hex()}")

    def request(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        self.send_isotp(payload)
        resp = self.recv_isotp(timeout=timeout)
        self.log(f"TX {payload.hex(' ').upper()}  ->  RX {resp.hex(' ').upper()}")
        return resp


# -----------------------------
# J2534/OpenPort raw-CAN ISO-TP minimal transport
# -----------------------------

class J2534RawCanIsoTp:
    """
    Windows J2534 raw-CAN backend. This manually sends the same ISO-TP CAN frames
    as SocketCAN, but through a J2534 DLL such as OpenPort 2.0's op20pt32.dll.

    Important: Python bitness must match the DLL bitness. OpenPort's common DLL is
    often 32-bit, so 32-bit Python may be required.
    """
    def __init__(self, dll_path: str, tx_id: int, rx_id: int, log: Callable[[str], None],
                 baud: int = 500000, timeout: float = 2.0, pad: int = 0x00):
        self.dll_path = dll_path
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.log = log
        self.baud = baud
        self.timeout = timeout
        self.pad = pad & 0xFF
        self.dll = None
        self.dev_id = c_ulong(0)
        self.chan_id = c_ulong(0)

    def _check(self, code: int, where: str) -> None:
        if code == J2534_STATUS_NOERROR:
            return
        err_text = ""
        try:
            buf = create_string_buffer(256)
            self.dll.PassThruGetLastError(buf)
            err_text = buf.value.decode(errors="ignore")
        except Exception:
            pass
        raise RuntimeError(f"J2534 {where} failed: code={code} {err_text}")

    def open(self) -> None:
        self.dll = CDLL(self.dll_path)
        ret = self.dll.PassThruOpen(c_void_p(0), byref(self.dev_id))
        self._check(ret, "PassThruOpen")
        ret = self.dll.PassThruConnect(
            self.dev_id,
            c_ulong(J2534_CAN),
            c_ulong(0),
            c_ulong(self.baud),
            byref(self.chan_id),
        )
        self._check(ret, "PassThruConnect(CAN)")

        # OpenPort/J2534 raw-CAN behavior varies. Some DLLs return all CAN
        # frames without an explicit filter; others require a PASS_FILTER.
        # Try to install a permissive 11-bit pass filter for RX ID, but do not
        # fail the whole connection if this DLL rejects it.
        try:
            filt_id = c_ulong(0)
            mask = make_pt_msg(J2534_CAN, (0xFFFFFFFF).to_bytes(4, "big"))
            pattern = make_pt_msg(J2534_CAN, self.rx_id.to_bytes(4, "big"))
            retf = self.dll.PassThruStartMsgFilter(
                self.chan_id,
                c_ulong(J2534_PASS_FILTER),
                byref(mask),
                byref(pattern),
                None,
                byref(filt_id),
            )
            if retf == J2534_STATUS_NOERROR:
                self.log(f"Installed J2534 PASS_FILTER for RX 0x{self.rx_id:X} filter_id={filt_id.value}")
            else:
                self.log(f"J2534 PASS_FILTER not installed ret={retf}; continuing unfiltered")
        except Exception as e:
            self.log(f"J2534 PASS_FILTER setup skipped: {e}")

        self.log(f"Opened J2534 raw CAN DLL={self.dll_path}, baud={self.baud}, TX=0x{self.tx_id:X}, RX=0x{self.rx_id:X}")

    def close(self) -> None:
        if self.dll is not None:
            try:
                if self.chan_id.value:
                    self.dll.PassThruDisconnect(self.chan_id)
            finally:
                try:
                    if self.dev_id.value:
                        self.dll.PassThruClose(self.dev_id)
                finally:
                    self.dll = None

    @staticmethod
    def _j2534_can_data(can_id: int, frame: bytes) -> bytes:
        return can_id.to_bytes(4, "big") + frame[:8].ljust(8, b"\x00")

    def _parse_j2534_can(self, data: bytes) -> Tuple[int, bytes]:
        """Parse a J2534 raw-CAN message.

        Most DLLs return: 4-byte big-endian CAN ID + CAN payload.
        Some OpenPort raw-CAN reads appear to return only the 8-byte CAN
        payload. If no CAN ID is present, infer TX/RX from the ISO-TP/UDS
        payload so 02 50 85 ... is accepted as RX 0x7E8 instead of being
        mis-parsed as CAN ID 0x02508500.
        """
        if not data:
            return 0, b""

        # Normal J2534 CAN format: 4-byte ID + 0..8 data bytes.
        if len(data) > 8:
            cid = int.from_bytes(data[:4], "big") & 0x1FFFFFFF
            payload = data[4:12]
            return cid, payload

        # Some DLLs return just the CAN payload. Infer the ID.
        payload = data[:8]
        pci = payload[0] if payload else 0
        uds_sid = None
        if (pci >> 4) == 0x0:
            ln = pci & 0x0F
            if len(payload) >= 2 and ln >= 1:
                uds_sid = payload[1]
        elif (pci >> 4) == 0x1:
            # Multi-frame response from ECU/server. Treat as RX.
            return self.rx_id, payload
        elif (pci >> 4) == 0x2:
            # Consecutive response frame during RX. Treat as RX.
            return self.rx_id, payload
        elif (pci >> 4) == 0x3:
            # Flow control from ECU/server. Treat as RX.
            return self.rx_id, payload

        # Positive/negative UDS response SIDs seen in this project.
        if uds_sid in (0x50, 0x67, 0x71, 0x74, 0x76, 0x77, 0x7E, 0x7F, 0x63):
            return self.rx_id, payload

        # Otherwise it is probably an echo of our TX frame.
        return self.tx_id, payload

    def send_can(self, can_id: int, data: bytes) -> None:
        if self.dll is None:
            raise RuntimeError("J2534 not open")
        if len(data) > 8:
            raise ValueError("CAN frame data > 8")
        msg = make_pt_msg(J2534_CAN, self._j2534_can_data(can_id, data))
        num = c_ulong(1)
        ret = self.dll.PassThruWriteMsgs(self.chan_id, byref(msg), byref(num), c_ulong(int(self.timeout * 1000)))
        self._check(ret, "PassThruWriteMsgs")
        if num.value != 1:
            raise RuntimeError("J2534 wrote zero messages")

    def recv_can(self, wanted_id: Optional[int] = None, timeout: Optional[float] = None) -> Tuple[int, bytes]:
        if self.dll is None:
            raise RuntimeError("J2534 not open")
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        last_error = None
        while time.time() < deadline:
            msg = PASSTHRU_MSG()
            num = c_ulong(1)
            remain_ms = max(1, int((deadline - time.time()) * 1000))
            ret = self.dll.PassThruReadMsgs(self.chan_id, byref(msg), byref(num), c_ulong(remain_ms))
            if ret != J2534_STATUS_NOERROR or num.value == 0:
                last_error = ret
                continue
            if int(msg.ProtocolID) != J2534_CAN:
                continue
            raw = pt_msg_data(msg)
            can_id, payload = self._parse_j2534_can(raw)
            # Log the first few ignored frames while debugging OpenPort formats.
            if wanted_id is not None and can_id != wanted_id:
                self.log(f"J2534 ignored RX raw={raw.hex(' ').upper()} parsed_id=0x{can_id:X} payload={payload[:8].hex(' ').upper()} wanted=0x{wanted_id:X}")
                continue
            return can_id, payload[:8]
        raise TimeoutError(f"Timeout waiting for CAN ID 0x{wanted_id:X}; last J2534 ret={last_error}" if wanted_id is not None else "Timeout waiting for CAN")

    def _wait_flow_control(self, timeout: Optional[float] = None) -> tuple[int, float]:
        """Wait for ISO-TP FlowControl and return (block_size, stmin_seconds)."""
        wait_timeout = self.timeout if timeout is None else timeout
        while True:
            _, fc = self.recv_can(self.rx_id, timeout=wait_timeout)
            if not fc or (fc[0] >> 4) != 0x3:
                # Ignore echoes/stale non-FC frames while waiting for FC.
                continue
            fs = fc[0] & 0x0F
            if fs == 0x1:
                # Wait frame: give ECU/server another moment, then keep waiting.
                time.sleep(0.05)
                continue
            if fs != 0x0:
                raise RuntimeError(f"FlowControl not CTS: {fc.hex()}")
            bs = fc[1] if len(fc) > 1 else 0
            st = fc[2] if len(fc) > 2 else 0
            if st <= 0x7F:
                stmin = st / 1000.0
            elif 0xF1 <= st <= 0xF9:
                stmin = (st - 0xF0) / 10000.0
            else:
                stmin = 0.0
            return bs, stmin

    def send_isotp(self, payload: bytes, tx_id: Optional[int] = None) -> None:
        tx = self.tx_id if tx_id is None else tx_id
        n = len(payload)
        if n <= 7:
            self.send_can(tx, bytes([n]) + payload + bytes([self.pad]) * (7 - n))
            return
        if n > 0xFFF:
            raise ValueError("This minimal ISO-TP sender only supports <= 4095 byte payloads")
        self.send_can(tx, bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6])
        block_size, stmin = self._wait_flow_control()
        off = 6
        sn = 1
        sent_in_block = 0
        while off < n:
            chunk = payload[off:off + 7]
            self.send_can(tx, bytes([0x20 | (sn & 0x0F)]) + chunk + bytes([self.pad]) * (7 - len(chunk)))
            off += len(chunk)
            sn = (sn + 1) & 0x0F
            sent_in_block += 1
            # Always leave a tiny gap for OpenPort/raw-CAN stability.
            time.sleep(max(0.001, stmin))
            # If ECU/server requested a finite block size, try to wait for the next FC.
            # Some simple ECU-server emulators incorrectly send BS=1 once and never send
            # follow-up FC frames. In that case, continue in a logged compatibility mode
            # instead of hanging forever. A real ECU that truly enforces BS should send
            # the next FC promptly.
            if off < n and block_size and sent_in_block >= block_size:
                try:
                    block_size, stmin = self._wait_flow_control(timeout=0.75)
                    sent_in_block = 0
                except TimeoutError:
                    self.log("WARNING: finite ISO-TP block size requested but no follow-up FlowControl arrived; continuing stream in compatibility mode")
                    block_size = 0
                    sent_in_block = 0

    def recv_isotp(self, timeout: Optional[float] = None) -> bytes:
        deadline = time.time() + (timeout or self.timeout)
        while True:
            _, data = self.recv_can(self.rx_id, timeout=max(0.001, deadline - time.time()))
            if not data:
                raise RuntimeError("empty CAN frame")
            pci = data[0]
            typ = pci >> 4
            # FlowControl is not a UDS application response. Some J2534/OpenPort
            # reads leave FC frames in the queue; ignore them and keep waiting.
            if typ == 0x3:
                self.log(f"Ignored stale FlowControl while waiting response: {data.hex(' ').upper()}")
                if time.time() >= deadline:
                    raise TimeoutError("Only FlowControl frames seen while waiting for ISO-TP response")
                continue
            if typ == 0x0:
                ln = pci & 0x0F
                return data[1:1 + ln]
            if typ == 0x1:
                total = ((pci & 0x0F) << 8) | data[1]
                buf = bytearray(data[2:])
                self.send_can(self.tx_id, bytes([0x30, 0x00, 0x00]) + bytes([self.pad]) * 5)
                while len(buf) < total:
                    _, cf = self.recv_can(self.rx_id, timeout=max(0.001, deadline - time.time()))
                    if not cf or (cf[0] >> 4) != 0x2:
                        continue
                    buf.extend(cf[1:])
                return bytes(buf[:total])
            raise RuntimeError(f"Unexpected ISO-TP PCI: {data.hex()}")

    def request(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        self.send_isotp(payload)
        resp = self.recv_isotp(timeout=timeout)
        self.log(f"TX {payload.hex(' ').upper()}  ->  RX {resp.hex(' ').upper()}")
        return resp

# -----------------------------
# Flash session sequence
# -----------------------------

def parse_hex_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


class FlashProtocolError(RuntimeError):
    """Raised when the ECU response does not match the required flash sequence."""


NRC_NAMES = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceived_ResponsePending",
}


def describe_response(resp: bytes) -> str:
    if not resp:
        return "<empty>"
    h = resp.hex(" ").upper()
    if len(resp) >= 3 and resp[0] == 0x7F:
        nrc = resp[2]
        return f"{h}  NEGATIVE_RESPONSE service=0x{resp[1]:02X} NRC=0x{nrc:02X} {NRC_NAMES.get(nrc, 'unknownNRC')}"
    return h


def calc_security_key_algorithm(seed: int) -> int:
    """Recovered dynamic Nissan/G37 SecurityAccess 27 81 / 27 82 key transform.

    This replaces the earlier small seed/key table. It handles fresh ECU seeds
    such as the real-car B7E1C2EC seed instead of aborting before flashing.
    """
    hi = (seed >> 16) & 0xFFFF
    lo = seed & 0xFFFF

    r6 = u32(lo + 0x917B)
    r2 = u32(u16(r6) << 2)
    r7 = u32((r2 >> 16) + r2 + r6 - 1)
    first_mix = u16(r7 ^ hi)

    local_c = lo
    local_8 = first_mix

    r5 = u32(local_8 + 0x43A8)
    r6 = u32(u16(r5) << 1)
    r7 = u32((r6 >> 16) + r6 + r5 - 1)
    r1 = u32(u16(r7) << 4)
    out_hi = u16(((r1 >> 16) + r1) ^ r7 ^ local_c)

    return u32((out_hi << 16) | local_8)


def calc_security_key(seed: int, override: str = "") -> int:
    override = override.strip()
    if override:
        return parse_hex_int(override) & 0xFFFFFFFF
    return calc_security_key_algorithm(seed)


def expect(resp: bytes, prefix: bytes, what: str) -> None:
    if not resp.startswith(prefix):
        raise FlashProtocolError(
            f"Unexpected {what} response: {describe_response(resp)}, "
            f"expected prefix {prefix.hex(' ').upper()}"
        )

def run_flash(
    rom_path: Path,
    base_path: Optional[Path],
    backend: str,
    iface: str,
    j2534_dll: str,
    baud: int,
    tx_id: int,
    rx_id: int,
    mode: str,
    patch_checksums: bool,
    dry_run: bool,
    enable_send: bool,
    manual_key: str,
    skip_security: bool,
    out_dir: Path,
    log: Callable[[str], None],
) -> None:
    data = rom_path.read_bytes()
    if len(data) != ROM_SIZE:
        raise ValueError(f"BIN must be 0x{ROM_SIZE:X} bytes; got 0x{len(data):X}")

    if patch_checksums:
        patched = patch_bin_checksums(data)
        patched_path = out_dir / (rom_path.stem + f"_{mode}_checksum_patched.bin")
        patched_path.write_bytes(patched)
        data = patched
        c = compute_bin_checksums(data)
        log(f"Patched checksum BIN saved: {patched_path}")
        log(f"Checksums: 8200={c['8200']:04X} 20000={c['20000']:04X} 95F0={c['95F0']:08X} 95F8={c['95F8']:08X}")
    else:
        log("WARNING: checksum patching is disabled. Use only for controlled server/debug tests.")

    log(checksum_status_text(data))
    analyze_base_vs_target(base_path, data, log)

    # Build all records first. This catches encoder/CRC problems before any CAN write.
    records: List[FlashRecord] = []
    for r in iter_flash_records(data, mode, log):
        records.append(r)
    final83 = build_final83_payload()

    records_txt = out_dir / (rom_path.stem + f"_{mode}_records_preview.txt")
    with records_txt.open("w") as f:
        f.write(f"mode={mode}\n")
        f.write(f"records={len(records)}\n")
        f.write(f"final83={final83.hex().upper()}\n")
        for r in records[:20]:
            f.write(f"{r.subtype:02X} addr=0x{r.address:06X} payload={r.payload.hex().upper()}\n")
        if len(records) > 20:
            f.write(f"... {len(records)-20} more records omitted from preview ...\n")
    log(f"Built {len(records)} records. Preview saved: {records_txt}")

    if dry_run or not enable_send:
        log("Dry-run/build only selected. No CAN frames sent.")
        return

    if not messagebox.askyesno(
        "Confirm ECU server write",
        "This will transmit the HPT-style flash sequence over CAN.\n\n"
        "Use this on your ECU server/emulator first. Do NOT use on a real ECU unless you are ready.\n\n"
        f"Mode: {mode}\nRecords: {len(records)}\nBackend: {backend}\nInterface/DLL: {iface if backend == 'socketcan' else j2534_dll}\n\nProceed?",
    ):
        log("User cancelled before CAN transmit.")
        return

    if backend == "socketcan":
        t = SocketCanIsoTp(iface, tx_id, rx_id, log, timeout=BASE_RESPONSE_TIMEOUT)
    elif backend == "j2534_rawcan":
        if not j2534_dll:
            raise RuntimeError("J2534 DLL path is required for Windows/OpenPort raw CAN backend")
        t = J2534RawCanIsoTp(j2534_dll, tx_id, rx_id, log, baud=baud, timeout=BASE_RESPONSE_TIMEOUT)
    else:
        raise RuntimeError(f"Unknown backend: {backend}")
    phase = "opening transport"
    sent_records = 0
    attempted_records = 0
    flash_armed = False
    final83_sent = False
    cleanup_sent = False

    try:
        t.open()

        # Session / tester present / session again, matching HPT logs.
        phase = "entering 10 85 session"
        expect(t.request(bytes([0x10, 0x85]), timeout=SESSION_TIMEOUT), bytes([0x50, 0x85]), "10 85")
        try:
            phase = "sending tester present 3E 01"
            t.request(bytes([0x3E, 0x01]), timeout=SESSION_TIMEOUT)
        except Exception as exc:
            log(f"Tester-present response ignored: {exc}")
        phase = "re-entering 10 85 session"
        expect(t.request(bytes([0x10, 0x85]), timeout=SESSION_TIMEOUT), bytes([0x50, 0x85]), "10 85 second")

        if skip_security:
            log("SecurityAccess 27 unlock skipped by user option. Use only with emulator/server.")
        else:
            phase = "requesting 27 81 security seed"
            seed_resp = t.request(bytes([0x27, 0x81]), timeout=SECURITY_TIMEOUT)
            expect(seed_resp[:2], bytes([0x67, 0x81]), "27 81 seed")
            if len(seed_resp) < 6:
                raise FlashProtocolError(f"Seed response too short: {describe_response(seed_resp)}")
            seed = int.from_bytes(seed_resp[2:6], "big")
            key = calc_security_key(seed, manual_key)
            log(f"Security seed=0x{seed:08X}, key=0x{key:08X}")
            phase = "sending 27 82 security key"
            key_resp = t.request(bytes([0x27, 0x82]) + key.to_bytes(4, "big"), timeout=SECURITY_TIMEOUT)
            expect(key_resp, bytes([0x67, 0x82]), "27 82 key")

        mode_byte = 0x81 if mode == "partial" else 0x82
        prep = bytes([0x31, 0x81, mode_byte, 0xF0, 0x5A])
        phase = f"arming flash routine 31 81 {mode_byte:02X} F0 5A"
        resp = t.request(prep, timeout=PREPARE_START_TIMEOUT)
        expect(resp[:3], bytes([0x71, 0x81, 0x01]), "prepare")
        flash_armed = True

        prepare_deadline = time.time() + PREPARE_MAX_SECONDS
        prep_poll_count = 0
        while time.time() < prepare_deadline:
            prep_poll_count += 1
            phase = "polling prepare 31 81 01"
            resp = t.request(bytes([0x31, 0x81, 0x01]), timeout=PREPARE_POLL_TIMEOUT)
            if resp.startswith(bytes([0x71, 0x81, 0x02])):
                log(f"Prepare/poll is ready after {prep_poll_count} polls: 71 81 02")
                break
            if resp.startswith(bytes([0x71, 0x81, 0x01])):
                if prep_poll_count == 1 or prep_poll_count % 10 == 0:
                    log(f"Prepare still pending after {prep_poll_count} polls: 71 81 01")
                time.sleep(0.25)
                continue
            raise FlashProtocolError(f"Unexpected prepare poll response: {describe_response(resp)}")
        else:
            raise TimeoutError(f"Prepare polling never returned 71 81 02 within {PREPARE_MAX_SECONDS:.0f}s")

        for idx, rec in enumerate(records, 1):
            if idx == 1 or idx % 50 == 0 or idx == len(records):
                log(f"Sending record {idx}/{len(records)} subtype=0x{rec.subtype:02X} addr=0x{rec.address:06X}")
            phase = f"sending 34 record {idx}/{len(records)} addr=0x{rec.address:06X}"
            # Count as attempted before transmitting. If the ECU receives the full
            # record but our receive path times out/mis-parses the ACK, the flash
            # state may still have changed. Failure handling must treat this as
            # a potentially active programming attempt, not a pre-write abort.
            attempted_records = idx
            resp = t.request(rec.payload, timeout=RECORD_ACK_TIMEOUT)
            expect(resp, bytes([0x74, 0x02]), f"record {idx}")
            sent_records = idx

        # Finalize/check sequence from HPT logs. 31 82 00 may return 71 82 01
        # first, then 31 82 01 polling eventually returns 71 82 02.
        phase = "starting finalize 31 82 00"
        resp = t.request(bytes([0x31, 0x82, 0x00]), timeout=FINALIZE_START_TIMEOUT)
        if not resp.startswith(bytes([0x71, 0x82])):
            raise FlashProtocolError(f"Unexpected 31 82 00 response: {describe_response(resp)}")
        if resp.startswith(bytes([0x71, 0x82, 0x02])):
            log("Finalize accepted immediately: 71 82 02")
        else:
            finalize_deadline = time.time() + FINALIZE_MAX_SECONDS
            final_poll_count = 0
            while time.time() < finalize_deadline:
                final_poll_count += 1
                phase = "polling finalize 31 82 01"
                resp = t.request(bytes([0x31, 0x82, 0x01]), timeout=FINALIZE_POLL_TIMEOUT)
                if resp.startswith(bytes([0x71, 0x82, 0x02])):
                    log(f"Finalize/poll is ready after {final_poll_count} polls: 71 82 02")
                    break
                if resp.startswith(bytes([0x71, 0x82, 0x01])):
                    if final_poll_count == 1 or final_poll_count % 10 == 0:
                        log(f"Finalize still pending after {final_poll_count} polls: 71 82 01")
                    time.sleep(0.25)
                    continue
                raise FlashProtocolError(f"Unexpected finalize poll response: {describe_response(resp)}")
            else:
                raise TimeoutError(f"Finalize polling never returned 71 82 02 within {FINALIZE_MAX_SECONDS:.0f}s")

        phase = "sending final 34 83 record"
        resp = t.request(final83, timeout=FINAL83_TIMEOUT)
        expect(resp, bytes([0x74, 0x02]), "34 83")
        final83_sent = True

        # HPT-like post-flash ignition cycle. HPT prompts the user and then sends the
        # final cleanup/default-session command after the user clicks OK.
        log("Flash transfer/finalization finished. HPT-style ignition cycle required before final cleanup.")
        messagebox.showwarning(
            "Ignition cycle required",
            "Flash transfer/finalization finished.\n\n"
            "Turn the ignition/key OFF for at least 3 seconds.\n"
            "Then turn the ignition/key back ON.\n\n"
            "Click OK only after the key is back ON.\n\n"
            "Do not start the engine yet."
        )
        log("User acknowledged HPT-style key OFF/ON cycle. Waiting 3 seconds before final CAN cleanup...")
        time.sleep(3.0)

        phase = "sending final cleanup/default session 10 81 after key cycle"
        resp = t.request(bytes([0x10, 0x81]), timeout=CLEANUP_TIMEOUT)
        expect(resp[:2], bytes([0x50, 0x81]), "10 81 final cleanup")
        cleanup_sent = True
        log("ECU accepted final cleanup/default-session request after key cycle: 10 81 -> 50 81")

        # Optional sanity check after cleanup. This is NOT the final HPT message; it is our
        # check so the tool does not report complete if the ECU is not responsive.
        phase = "post-cleanup communication verify 10 85"
        verify = t.request(bytes([0x10, 0x85]), timeout=KEY_CYCLE_VERIFY_TIMEOUT)
        expect(verify[:2], bytes([0x50, 0x85]), "post-cleanup 10 85 verify")
        log("Post-key-cycle ECU communication verified: 10 85 -> 50 85")
        try:
            phase = "returning ECU to default session after verify"
            t.request(bytes([0x10, 0x81]), timeout=CLEANUP_TIMEOUT)
            log("Returned ECU to default session after verification.")
        except Exception as exc:
            log(f"Post-verify 10 81 cleanup warning: {exc}")
        log("Flash sequence completed after HPT-style ignition cycle, final cleanup, and communication verify.")

    except Exception as exc:
        log("")
        log("================ FLASH FAILURE / ABORT ================")
        log(f"Failure phase: {phase}")
        log(f"Records attempted: {attempted_records}/{len(records)}")
        log(f"Records ACKed: {sent_records}/{len(records)}")
        log(f"Flash armed: {flash_armed}; final83_sent: {final83_sent}; cleanup_sent: {cleanup_sent}")
        log(f"Error: {exc}")

        # Best-effort safe cleanup only when no data records were successfully accepted.
        # Once records have been accepted, avoid guessing a recovery sequence. The safest
        # instruction is stable power + complete recovery with HPT/known-good full write.
        if attempted_records == 0 and sent_records == 0 and not final83_sent:
            try:
                log("No 34 data records were attempted. Attempting best-effort 10 81 cleanup...")
                cleanup_resp = t.request(bytes([0x10, 0x81]), timeout=CLEANUP_TIMEOUT)
                log(f"Best-effort cleanup response: {describe_response(cleanup_resp)}")
            except Exception as cleanup_exc:
                log(f"Best-effort cleanup failed/ignored: {cleanup_exc}")
        else:
            log("IMPORTANT: At least one 34 data record was transmitted/attempted, ACKed, or finalization was in progress.")
            log("Do NOT start the vehicle. Do NOT disconnect power if avoidable.")
            log("Keep battery support connected and recover by completing a known-good write/finalization, or use HPT recovery/full write.")

        messagebox.showerror(
            "Flash failed / aborted",
            "The flash sequence stopped because the ECU returned an unexpected response, timed out, or another error occurred.\n\n"
            f"Failure phase: {phase}\n"
            f"Records attempted: {attempted_records}/{len(records)}\n"
            f"Records ACKed: {sent_records}/{len(records)}\n\n"
            "If this happened before any 34 records were attempted, the tool attempted a safe cleanup.\n"
            "If any 34 record was attempted or ACKed, DO NOT start the vehicle. Keep power stable and recover with a known-good write/HPT."
        )
        raise

    finally:
        t.close()


# -----------------------------
# Combined GUI helpers: transport, probes, info reads, ROM dump
# -----------------------------

def make_transport(backend: str, iface: str, j2534_dll: str, baud: int, tx_id: int, rx_id: int,
                   log: Callable[[str], None], timeout: float = BASE_RESPONSE_TIMEOUT):
    if backend == "socketcan":
        return SocketCanIsoTp(iface, tx_id, rx_id, log, timeout=timeout)
    if backend == "j2534_rawcan":
        if not j2534_dll:
            raise RuntimeError("J2534 DLL path is required for Windows/OpenPort raw CAN backend")
        return J2534RawCanIsoTp(j2534_dll, tx_id, rx_id, log, baud=baud, timeout=timeout)
    raise RuntimeError(f"Unknown backend: {backend}")


def safe_request(t, payload: bytes, log: Callable[[str], None], timeout: float = 3.0) -> Optional[bytes]:
    try:
        return t.request(payload, timeout=timeout)
    except Exception as exc:
        log(f"TX {payload.hex(' ').upper()} -> ERROR/TIMEOUT: {exc}")
        return None


def ascii_clean(data: bytes) -> str:
    s = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    return s.strip('\x00\xff .') or s


def parse_positive_ascii(resp: Optional[bytes], expected_prefix: bytes) -> str:
    if not resp:
        return "<no response>"
    if resp.startswith(expected_prefix):
        return f"{resp.hex(' ').upper()} | ASCII='{ascii_clean(resp[len(expected_prefix):])}'"
    return describe_response(resp)


def run_probe_unlock(backend: str, iface: str, j2534_dll: str, baud: int, tx_id: int, rx_id: int,
                     send_key: bool, manual_key: str, out_dir: Path, log: Callable[[str], None]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    t = make_transport(backend, iface, j2534_dll, baud, tx_id, rx_id, log, timeout=BASE_RESPONSE_TIMEOUT)
    try:
        t.open()
        log("Probe: entering 10 85 session")
        r = t.request(bytes([0x10, 0x85]), timeout=SESSION_TIMEOUT)
        expect(r, bytes([0x50, 0x85]), "10 85")
        try:
            t.request(bytes([0x3E, 0x01]), timeout=SESSION_TIMEOUT)
        except Exception as exc:
            log(f"Tester-present ignored during probe: {exc}")
        log("Probe: requesting 27 81 seed")
        seed_resp = t.request(bytes([0x27, 0x81]), timeout=SECURITY_TIMEOUT)
        expect(seed_resp[:2], bytes([0x67, 0x81]), "27 81 seed")
        if len(seed_resp) < 6:
            raise FlashProtocolError(f"Seed response too short: {describe_response(seed_resp)}")
        seed = int.from_bytes(seed_resp[2:6], "big")
        key = calc_security_key(seed, manual_key)
        log(f"27 probe result: seed=0x{seed:08X}, computed key=0x{key:08X}")
        if send_key:
            log("Probe: sending 27 82 key. This does not arm flash; it only tests SecurityAccess.")
            key_resp = t.request(bytes([0x27, 0x82]) + key.to_bytes(4, "big"), timeout=SECURITY_TIMEOUT)
            expect(key_resp, bytes([0x67, 0x82]), "27 82 key")
            log("27 unlock probe: PASS")
        else:
            log("27 seed-only probe complete. Key was calculated but not sent.")
        try:
            t.request(bytes([0x10, 0x81]), timeout=CLEANUP_TIMEOUT)
        except Exception as exc:
            log(f"Cleanup 10 81 after probe failed/ignored: {exc}")
    finally:
        t.close()


def run_info_read(backend: str, iface: str, j2534_dll: str, baud: int, tx_id: int, rx_id: int,
                  do_unlock: bool, manual_key: str, log: Callable[[str], None]) -> None:
    t = make_transport(backend, iface, j2534_dll, baud, tx_id, rx_id, log, timeout=BASE_RESPONSE_TIMEOUT)
    try:
        t.open()
        log("Info: entering 10 85 session")
        safe_request(t, bytes([0x10, 0x85]), log, SESSION_TIMEOUT)
        safe_request(t, bytes([0x3E, 0x01]), log, SESSION_TIMEOUT)
        if do_unlock:
            seed_resp = safe_request(t, bytes([0x27, 0x81]), log, SECURITY_TIMEOUT)
            if seed_resp and seed_resp.startswith(bytes([0x67, 0x81])) and len(seed_resp) >= 6:
                seed = int.from_bytes(seed_resp[2:6], "big")
                key = calc_security_key(seed, manual_key)
                log(f"Info unlock: seed=0x{seed:08X}, key=0x{key:08X}")
                safe_request(t, bytes([0x27, 0x82]) + key.to_bytes(4, "big"), log, SECURITY_TIMEOUT)
            else:
                log("Info unlock skipped: seed request failed")

        # Standard UDS DID candidates. Nissan/Hitachi may not answer all; negative responses are OK.
        dids = [
            ("VIN", 0xF190),
            ("ECU HW number", 0xF191),
            ("System supplier ECU HW number", 0xF193),
            ("System supplier ECU SW number", 0xF195),
            ("Vehicle manufacturer ECU SW number", 0xF188),
            ("Vehicle manufacturer ECU SW version", 0xF189),
            ("ECU serial number", 0xF18C),
            ("Repair shop code / programming date", 0xF198),
            ("ECU installation date", 0xF19D),
        ]
        log("--- UDS 22 DID info probes ---")
        for name, did in dids:
            resp = safe_request(t, bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), log, 3.0)
            prefix = bytes([0x62, (did >> 8) & 0xFF, did & 0xFF])
            log(f"{name} DID 0x{did:04X}: {parse_positive_ascii(resp, prefix)}")
            time.sleep(0.03)

        # KWP-ish 1A ECU identification candidates.
        log("--- KWP/Nissan 1A identification probes ---")
        for ident in [0x80, 0x81, 0x82, 0x83, 0x87, 0x88, 0x90, 0x91, 0x92, 0x94, 0x9A]:
            resp = safe_request(t, bytes([0x1A, ident]), log, 3.0)
            log(f"1A {ident:02X}: {parse_positive_ascii(resp, bytes([0x5A, ident]))}")
            time.sleep(0.03)

        # LocalIdentifier probes used in old dumper prep flows. These are read-only style probes.
        log("--- Nissan local ID 21 probes commonly relevant to this ECU ---")
        for lid in [0x80, 0x81, 0x82, 0x83, 0x90, 0x91, 0x92, 0x9A]:
            resp = safe_request(t, bytes([0x21, lid]), log, 3.0)
            log(f"21 {lid:02X}: {parse_positive_ascii(resp, bytes([0x61, lid]))}")
            time.sleep(0.03)
        try:
            safe_request(t, bytes([0x10, 0x81]), log, CLEANUP_TIMEOUT)
        except Exception:
            pass
    finally:
        t.close()


def run_safe_capability_probe(backend: str, iface: str, j2534_dll: str, baud: int, tx_id: int, rx_id: int,
                              manual_key: str, log: Callable[[str], None]) -> None:
    """Read-only/low-risk probe for compatibility across G37/370Z OS variants.

    This intentionally does NOT send 31 81 F0 5A, 34, 36, 37, erase, write, or reset.
    """
    t = make_transport(backend, iface, j2534_dll, baud, tx_id, rx_id, log, timeout=BASE_RESPONSE_TIMEOUT)
    try:
        t.open()
        log("--- Safe compatibility probe started; no write/erase/finalize services will be sent. ---")
        for sess in [0x81, 0x85, 0xC0, 0xFB]:
            resp = safe_request(t, bytes([0x10, sess]), log, 3.0)
            log(f"Session 10 {sess:02X}: {describe_response(resp or b'')}")
            time.sleep(0.05)
        # Return to 85 for security and info probes.
        resp = safe_request(t, bytes([0x10, 0x85]), log, SESSION_TIMEOUT)
        if resp and resp.startswith(bytes([0x50, 0x85])):
            seed_resp = safe_request(t, bytes([0x27, 0x81]), log, SECURITY_TIMEOUT)
            if seed_resp and seed_resp.startswith(bytes([0x67, 0x81])) and len(seed_resp) >= 6:
                seed = int.from_bytes(seed_resp[2:6], "big")
                key = calc_security_key(seed, manual_key)
                log(f"SecurityAccess 27 81 supported. seed=0x{seed:08X}, computed key=0x{key:08X}")
                key_resp = safe_request(t, bytes([0x27, 0x82]) + key.to_bytes(4, "big"), log, SECURITY_TIMEOUT)
                log(f"27 82 key test: {describe_response(key_resp or b'')}")
            else:
                log(f"SecurityAccess seed probe failed: {describe_response(seed_resp or b'')}")
        log("Safe capability probe complete. Running info read next...")
    finally:
        try:
            safe_request(t, bytes([0x10, 0x81]), log, CLEANUP_TIMEOUT)
        except Exception:
            pass
        t.close()
    run_info_read(backend, iface, j2534_dll, baud, tx_id, rx_id, False, manual_key, log)


def read_memory_chunk(t, addr: int, size: int, fmt: str, log: Callable[[str], None]) -> Tuple[Optional[bytes], str]:
    if fmt == "a4_s2":
        payload = bytes([0x23]) + addr.to_bytes(4, "big") + size.to_bytes(2, "big")
    elif fmt == "a3_s2":
        payload = bytes([0x23]) + (addr & 0xFFFFFF).to_bytes(3, "big") + size.to_bytes(2, "big")
    elif fmt == "a3_s1":
        if size > 0xFF:
            return None, "skip-size"
        payload = bytes([0x23]) + (addr & 0xFFFFFF).to_bytes(3, "big") + bytes([size & 0xFF])
    else:
        raise ValueError(fmt)
    resp = safe_request(t, payload, log, 5.0)
    if not resp:
        return None, "timeout"
    if len(resp) >= 3 and resp[0] == 0x7F:
        return None, f"7F {resp[1]:02X} {resp[2]:02X} {NRC_NAMES.get(resp[2], '')}"
    if resp[0] == 0x63:
        return resp[1:], "ok"
    return None, f"unexpected {describe_response(resp)}"


def prep_dump_mode(t, prep: str, manual_key: str, log: Callable[[str], None]) -> bool:
    def session(s: int) -> bool:
        r = safe_request(t, bytes([0x10, s]), log, 3.0)
        return bool(r and r.startswith(bytes([0x50, s])))
    def local(lid: int) -> bool:
        r = safe_request(t, bytes([0x21, lid]), log, 3.0)
        return bool(r and r.startswith(bytes([0x61, lid])))
    def unlock85() -> bool:
        if not session(0x85):
            return False
        safe_request(t, bytes([0x3E, 0x01]), log, 1.0)
        r = safe_request(t, bytes([0x27, 0x81]), log, SECURITY_TIMEOUT)
        if not r or not r.startswith(bytes([0x67, 0x81])) or len(r) < 6:
            return False
        seed = int.from_bytes(r[2:6], "big")
        key = calc_security_key(seed, manual_key)
        log(f"Dump unlock: seed=0x{seed:08X}, key=0x{key:08X}")
        kr = safe_request(t, bytes([0x27, 0x82]) + key.to_bytes(4, "big"), log, SECURITY_TIMEOUT)
        return bool(kr and kr.startswith(bytes([0x67, 0x82])))

    log(f"--- Dump prep mode: {prep} ---")
    if prep == "none": return True
    if prep == "unlock85": return unlock85()
    if prep == "fb_only": return session(0xFB)
    if prep == "c0_only": return session(0xC0)
    if prep == "unlock85_fb":
        unlock85(); time.sleep(0.03); return session(0xFB)
    if prep == "c0_83_fb":
        session(0xC0); time.sleep(0.03); local(0x83); time.sleep(0.03); return session(0xFB)
    if prep == "c0_83_81_fb":
        session(0xC0); time.sleep(0.03); local(0x83); time.sleep(0.03); local(0x81); time.sleep(0.03); return session(0xFB)
    if prep == "c0_83_fb_unlock_no_restore":
        session(0xC0); time.sleep(0.03); local(0x83); time.sleep(0.03); session(0xFB); time.sleep(0.03); return unlock85()
    if prep == "c0_83_unlock85":
        session(0xC0); time.sleep(0.03); local(0x83); time.sleep(0.03); return unlock85()
    raise ValueError(prep)


def run_rom_dump(backend: str, iface: str, j2534_dll: str, baud: int, tx_id: int, rx_id: int,
                 start: int, total: int, section_size: int, chunk: int, out_dir: Path,
                 manual_key: str, prep_modes: List[str], formats: List[str], log: Callable[[str], None],
                 cancel_check: Callable[[], bool]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    dump_dir = out_dir / ("dump_" + time.strftime("%Y%m%d_%H%M%S"))
    dump_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = dump_dir / "manifest.json"
    combined_path = dump_dir / "combined.bin"
    t = make_transport(backend, iface, j2534_dll, baud, tx_id, rx_id, log, timeout=BASE_RESPONSE_TIMEOUT)

    manifest = {
        "start": start, "total": total, "section_size": section_size, "chunk": chunk,
        "working_prep": None, "working_fmt": None, "sections": []
    }
    for pos in range(0, total, section_size):
        addr = start + pos
        ln = min(section_size, total - pos)
        manifest["sections"].append({"start": addr, "length": ln, "file": f"section_{addr:06X}_{addr+ln:06X}.bin", "status": "pending", "bytes_done": 0})
    manifest_path.write_text(json.dumps(manifest, indent=2))

    def save_manifest():
        manifest_path.write_text(json.dumps(manifest, indent=2))

    working_prep = None
    working_fmt = None
    try:
        t.open()
        log(f"Dump started: start=0x{start:06X}, total=0x{total:X}, section=0x{section_size:X}, chunk=0x{chunk:X}")
        for sec in manifest["sections"]:
            if cancel_check():
                log("Dump cancelled by user.")
                break
            sec_start = sec["start"]
            sec_len = sec["length"]
            sec_path = dump_dir / sec["file"]
            log(f"=== Dump section 0x{sec_start:06X}-0x{sec_start+sec_len:06X} ===")
            if not working_prep or not working_fmt:
                for prep in prep_modes:
                    if not prep_dump_mode(t, prep, manual_key, log):
                        continue
                    for fmt in formats:
                        for test_size in [chunk, 0x3F, 0x20, 0x10, 0x08, 0x04, 0x01]:
                            n = min(test_size, chunk, sec_len)
                            if n <= 0: continue
                            data, status = read_memory_chunk(t, sec_start, n, fmt, log)
                            log(f"Dump probe prep={prep} fmt={fmt} size=0x{n:X}: {status}")
                            if status == "ok" and data is not None:
                                working_prep, working_fmt, chunk = prep, fmt, n
                                manifest["working_prep"] = working_prep
                                manifest["working_fmt"] = working_fmt
                                manifest["chunk"] = chunk
                                save_manifest()
                                # Write the probe bytes as the start of this section.
                                sec_path.write_bytes(data)
                                sec["bytes_done"] = len(data)
                                log(f"WORKING DUMP MODE: prep={working_prep} fmt={working_fmt} chunk=0x{chunk:X}")
                                break
                        if working_prep: break
                    if working_prep: break
                if not working_prep:
                    sec["status"] = f"failed finding read mode at 0x{sec_start:X}"
                    save_manifest()
                    raise RuntimeError(f"No working read mode found at 0x{sec_start:X}")
            else:
                prep_dump_mode(t, working_prep, manual_key, log)

            done = sec_path.stat().st_size if sec_path.exists() else 0
            with sec_path.open("ab") as f:
                while done < sec_len:
                    if cancel_check():
                        log("Dump cancelled by user.")
                        save_manifest()
                        return
                    addr = sec_start + done
                    n = min(chunk, sec_len - done)
                    ok = False
                    for attempt in range(1, 5):
                        log(f"READ 0x{addr:06X} +0x{n:X} ({done}/{sec_len}) attempt {attempt} prep={working_prep} fmt={working_fmt}")
                        data, status = read_memory_chunk(t, addr, n, working_fmt, log)
                        if status == "ok" and data is not None:
                            f.write(data); f.flush()
                            done += len(data)
                            sec["bytes_done"] = done
                            save_manifest()
                            ok = True
                            time.sleep(0.01)
                            break
                        log(f"Read failed: {status}; re-prepping")
                        prep_dump_mode(t, working_prep, manual_key, log)
                        time.sleep(0.1)
                    if not ok:
                        # Drop current mode and force rediscovery at current address.
                        log("Current read mode failed repeatedly; rediscovering at current address")
                        working_prep = working_fmt = None
                        manifest["working_prep"] = None
                        manifest["working_fmt"] = None
                        save_manifest()
                        raise RuntimeError(f"Dump stopped at 0x{addr:X}; resume support can be added using manifest {manifest_path}")
            sec["status"] = "complete"
            sec["bytes_done"] = sec_len
            save_manifest()
            log(f"Completed {sec['file']}")

        # Combine complete sections in order.
        with combined_path.open("wb") as out:
            for sec in manifest["sections"]:
                p = dump_dir / sec["file"]
                if p.exists():
                    out.write(p.read_bytes())
        log(f"Dump combined output: {combined_path}")
        if combined_path.stat().st_size == total:
            log(f"Dump complete: {combined_path} size=0x{combined_path.stat().st_size:X}")
        else:
            log(f"Dump partial: {combined_path} size=0x{combined_path.stat().st_size:X}, expected 0x{total:X}")
    finally:
        try:
            safe_request(t, bytes([0x10, 0x81]), log, CLEANUP_TIMEOUT)
        except Exception:
            pass
        t.close()

# -----------------------------
# Combined GUI
# -----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("G37 / 370Z ECU Tool v13 - Flasher, ROM Dump, Probe/Info")
        self.geometry("1120x780")
        self._thread: Optional[threading.Thread] = None
        self._dump_cancel = False
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}
        cfg = load_config()
        self.base_var = tk.StringVar(value=cfg.get("base_bin_path", ""))
        self.bin_var = tk.StringVar()
        self.out_var = tk.StringVar(value=str(Path.cwd()))
        self.backend_var = tk.StringVar(value="j2534_rawcan" if os.name == "nt" else "socketcan")
        self.iface_var = tk.StringVar(value="can0")
        self.j2534_dll_var = tk.StringVar(value=cfg.get("j2534_dll", r"C:\Windows\SysWOW64\op20pt32.dll"))
        self.baud_var = tk.StringVar(value="500000")
        self.tx_var = tk.StringVar(value="0x7E0")
        self.rx_var = tk.StringVar(value="0x7E8")
        self.key_var = tk.StringVar(value="")

        top = ttk.LabelFrame(self, text="Connection / project")
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Backend").grid(row=0, column=0, **pad)
        ttk.Combobox(top, textvariable=self.backend_var, values=["j2534_rawcan", "socketcan"], width=14, state="readonly").grid(row=0, column=1, **pad)
        ttk.Label(top, text="SocketCAN iface").grid(row=0, column=2, **pad)
        ttk.Entry(top, textvariable=self.iface_var, width=10).grid(row=0, column=3, **pad)
        ttk.Label(top, text="J2534/OpenPort DLL").grid(row=0, column=4, **pad)
        ttk.Entry(top, textvariable=self.j2534_dll_var, width=48).grid(row=0, column=5, **pad)
        ttk.Button(top, text="Browse DLL", command=self.browse_j2534).grid(row=0, column=6, **pad)
        ttk.Label(top, text="Baud").grid(row=1, column=0, **pad)
        ttk.Entry(top, textvariable=self.baud_var, width=10).grid(row=1, column=1, **pad)
        ttk.Label(top, text="TX ID").grid(row=1, column=2, **pad)
        ttk.Entry(top, textvariable=self.tx_var, width=10).grid(row=1, column=3, **pad)
        ttk.Label(top, text="RX ID").grid(row=1, column=4, **pad)
        ttk.Entry(top, textvariable=self.rx_var, width=10).grid(row=1, column=5, sticky="w", **pad)
        ttk.Label(top, text="Manual 27 key override").grid(row=2, column=0, columnspan=2, sticky="w", **pad)
        ttk.Entry(top, textvariable=self.key_var, width=18).grid(row=2, column=2, **pad)
        ttk.Label(top, text="Blank = dynamic seed/key algorithm").grid(row=2, column=3, columnspan=4, sticky="w", **pad)
        top.columnconfigure(5, weight=1)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=4)
        self.flash_tab = ttk.Frame(nb)
        self.dump_tab = ttk.Frame(nb)
        self.probe_tab = ttk.Frame(nb)
        nb.add(self.flash_tab, text="Flash")
        nb.add(self.dump_tab, text="ROM Dump")
        nb.add(self.probe_tab, text="Probe / VIN / OS")
        self._build_flash_tab(self.flash_tab)
        self._build_dump_tab(self.dump_tab)
        self._build_probe_tab(self.probe_tab)

        self.log_text = tk.Text(self, height=18, wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=6)
        self.log("Loaded combined ECU tool. Default is safe/dry-run unless you enable transmit.")

    def _build_flash_tab(self, frm):
        pad = {"padx": 6, "pady": 4}
        self.mode_var = tk.StringVar(value="partial")
        self.patch_var = tk.BooleanVar(value=True)
        self.dry_var = tk.BooleanVar(value=True)
        self.enable_var = tk.BooleanVar(value=False)
        self.skip_security_var = tk.BooleanVar(value=False)
        ttk.Label(frm, text="Base/reference BIN:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.base_var, width=92).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse/Set Base", command=self.browse_base).grid(row=0, column=2, **pad)
        ttk.Label(frm, text="Target full 0x180000 BIN:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.bin_var, width=92).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse", command=self.browse_bin).grid(row=1, column=2, **pad)
        ttk.Label(frm, text="Output folder:").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.out_var, width=92).grid(row=2, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse", command=self.browse_out).grid(row=2, column=2, **pad)
        box = ttk.LabelFrame(frm, text="Flash options")
        box.grid(row=3, column=0, columnspan=3, sticky="ew", **pad)
        ttk.Label(box, text="Mode").grid(row=0, column=0, **pad)
        ttk.Combobox(box, textvariable=self.mode_var, values=["partial", "full"], width=10, state="readonly").grid(row=0, column=1, **pad)
        ttk.Checkbutton(box, text="Patch BIN checksums before building records", variable=self.patch_var).grid(row=0, column=2, sticky="w", **pad)
        ttk.Checkbutton(box, text="Dry-run/build only", variable=self.dry_var).grid(row=0, column=3, sticky="w", **pad)
        ttk.Checkbutton(box, text="Enable CAN transmit", variable=self.enable_var).grid(row=0, column=4, sticky="w", **pad)
        ttk.Checkbutton(box, text="Skip 27 unlock (server only)", variable=self.skip_security_var).grid(row=1, column=0, columnspan=2, sticky="w", **pad)
        ttk.Button(box, text="Build / Flash", command=self.start_flash).grid(row=1, column=4, **pad)
        ttk.Label(frm, text="Partial writes fixed HPT-style 0x008200-0x020000. Full writes 0x008200-0x180000. Do not use real ECU until server test passes.", foreground="red").grid(row=4, column=0, columnspan=3, sticky="w", **pad)
        frm.columnconfigure(1, weight=1)

    def _build_dump_tab(self, frm):
        pad = {"padx": 6, "pady": 4}
        self.dump_start_var = tk.StringVar(value="0x000000")
        self.dump_total_var = tk.StringVar(value="0x180000")
        self.dump_section_var = tk.StringVar(value="0x10000")
        self.dump_chunk_var = tk.StringVar(value="0x3F")
        self.dump_prep_var = tk.StringVar(value="none,unlock85,c0_83_fb,c0_83_81_fb,fb_only,c0_only,unlock85_fb,c0_83_fb_unlock_no_restore,c0_83_unlock85")
        self.dump_fmt_var = tk.StringVar(value="a4_s2,a3_s2,a3_s1")
        ttk.Label(frm, text="Dump start").grid(row=0, column=0, **pad)
        ttk.Entry(frm, textvariable=self.dump_start_var, width=12).grid(row=0, column=1, **pad)
        ttk.Label(frm, text="Total bytes").grid(row=0, column=2, **pad)
        ttk.Entry(frm, textvariable=self.dump_total_var, width=12).grid(row=0, column=3, **pad)
        ttk.Label(frm, text="Section size").grid(row=0, column=4, **pad)
        ttk.Entry(frm, textvariable=self.dump_section_var, width=12).grid(row=0, column=5, **pad)
        ttk.Label(frm, text="Chunk").grid(row=0, column=6, **pad)
        ttk.Entry(frm, textvariable=self.dump_chunk_var, width=10).grid(row=0, column=7, **pad)
        ttk.Label(frm, text="Output folder").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.out_var, width=92).grid(row=1, column=1, columnspan=6, sticky="ew", **pad)
        ttk.Button(frm, text="Browse", command=self.browse_out).grid(row=1, column=7, **pad)
        ttk.Label(frm, text="Prep modes").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.dump_prep_var, width=105).grid(row=2, column=1, columnspan=7, sticky="ew", **pad)
        ttk.Label(frm, text="Read formats").grid(row=3, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.dump_fmt_var, width=105).grid(row=3, column=1, columnspan=7, sticky="ew", **pad)
        ttk.Button(frm, text="Start ROM Dump", command=self.start_dump).grid(row=4, column=0, **pad)
        ttk.Button(frm, text="Cancel Dump", command=self.cancel_dump).grid(row=4, column=1, **pad)
        ttk.Label(frm, text="Dump uses read-only 0x23 ReadMemoryByAddress with adaptive prep modes. It does not arm/write flash.", foreground="blue").grid(row=5, column=0, columnspan=8, sticky="w", **pad)
        frm.columnconfigure(6, weight=1)

    def _build_probe_tab(self, frm):
        pad = {"padx": 6, "pady": 4}
        self.info_unlock_var = tk.BooleanVar(value=False)
        ttk.Button(frm, text="Probe 27 seed only", command=lambda: self.start_probe(send_key=False)).grid(row=0, column=0, **pad)
        ttk.Button(frm, text="Probe 27 unlock", command=lambda: self.start_probe(send_key=True)).grid(row=0, column=1, **pad)
        ttk.Button(frm, text="Safe compatibility probe", command=self.start_safe_probe).grid(row=0, column=2, **pad)
        ttk.Checkbutton(frm, text="Unlock before VIN/OS read", variable=self.info_unlock_var).grid(row=1, column=0, columnspan=2, sticky="w", **pad)
        ttk.Button(frm, text="Read VIN / OS / ECU IDs", command=self.start_info_read).grid(row=1, column=2, **pad)
        ttk.Label(frm, text="Safe probe avoids write/erase services. It checks sessions, 27 unlock, and common read-only ID services for G37/370Z OS variants.", foreground="blue").grid(row=2, column=0, columnspan=4, sticky="w", **pad)

    def browse_base(self):
        p = filedialog.askopenfilename(title="Select base/reference full 0x180000 BIN", filetypes=[("BIN files", "*.bin"), ("All files", "*.*")])
        if p:
            bp = Path(p)
            self.base_var.set(str(bp))
            cfg = load_config(); cfg["base_bin_path"] = str(bp); cfg["j2534_dll"] = self.j2534_dll_var.get().strip()
            try: cfg["base_bin_sha256"] = sha256_file(bp)
            except Exception: pass
            save_config(cfg); self.log(f"Saved base/reference BIN: {bp}")

    def browse_bin(self):
        p = filedialog.askopenfilename(title="Select target full 0x180000 BIN", filetypes=[("BIN files", "*.bin"), ("All files", "*.*")])
        if p:
            self.bin_var.set(p); self.out_var.set(str(Path(p).parent))

    def browse_out(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p: self.out_var.set(p)

    def browse_j2534(self):
        p = filedialog.askopenfilename(title="Select J2534 DLL", filetypes=[("DLL files", "*.dll"), ("All files", "*.*")])
        if p:
            self.j2534_dll_var.set(p)
            cfg = load_config(); cfg["j2534_dll"] = p; cfg["base_bin_path"] = self.base_var.get().strip(); save_config(cfg)

    def log(self, msg: str):
        def append():
            self.log_text.insert("end", time.strftime("%H:%M:%S ") + msg + "\n")
            self.log_text.see("end")
        self.after(0, append)

    def _common_args(self):
        return (self.backend_var.get().strip(), self.iface_var.get().strip(), self.j2534_dll_var.get().strip(),
                int(self.baud_var.get().strip(), 0), parse_hex_int(self.tx_var.get()), parse_hex_int(self.rx_var.get()))

    def _start_thread(self, target, args):
        if self._thread and self._thread.is_alive():
            messagebox.showwarning("Busy", "A task is already running.")
            return
        self._thread = threading.Thread(target=self._worker, args=(target, args), daemon=True)
        self._thread.start()

    def _worker(self, target, args):
        try:
            target(*args)
        except Exception as exc:
            self.log("ERROR: " + str(exc))
            self.log(traceback.format_exc())
            self.after(0, lambda: messagebox.showerror("Error", str(exc)))

    def start_flash(self):
        try:
            rom = Path(self.bin_var.get())
            out = Path(self.out_var.get())
            if not rom.exists(): raise ValueError("Select a target BIN file")
            out.mkdir(parents=True, exist_ok=True)
            backend, iface, dll, baud, tx, rx = self._common_args()
            base = Path(self.base_var.get().strip()) if self.base_var.get().strip() else None
            cfg = load_config(); cfg["base_bin_path"] = self.base_var.get().strip(); cfg["j2534_dll"] = self.j2534_dll_var.get().strip(); save_config(cfg)
            args = (rom, base, backend, iface, dll, baud, tx, rx, self.mode_var.get(), self.patch_var.get(),
                    self.dry_var.get(), self.enable_var.get(), self.key_var.get(), bool(self.skip_security_var.get()), out, self.log)
            self._start_thread(run_flash, args)
        except Exception as exc:
            messagebox.showerror("Input error", str(exc))

    def start_dump(self):
        try:
            out = Path(self.out_var.get()); out.mkdir(parents=True, exist_ok=True)
            backend, iface, dll, baud, tx, rx = self._common_args()
            start = parse_hex_int(self.dump_start_var.get()); total = parse_hex_int(self.dump_total_var.get())
            section = parse_hex_int(self.dump_section_var.get()); chunk = parse_hex_int(self.dump_chunk_var.get())
            prep_modes = [x.strip() for x in self.dump_prep_var.get().split(',') if x.strip()]
            fmts = [x.strip() for x in self.dump_fmt_var.get().split(',') if x.strip()]
            self._dump_cancel = False
            args = (backend, iface, dll, baud, tx, rx, start, total, section, chunk, out, self.key_var.get(), prep_modes, fmts, self.log, lambda: self._dump_cancel)
            self._start_thread(run_rom_dump, args)
        except Exception as exc:
            messagebox.showerror("Input error", str(exc))

    def cancel_dump(self):
        self._dump_cancel = True
        self.log("Cancel requested for ROM dump.")

    def start_probe(self, send_key: bool):
        try:
            out = Path(self.out_var.get()); out.mkdir(parents=True, exist_ok=True)
            backend, iface, dll, baud, tx, rx = self._common_args()
            args = (backend, iface, dll, baud, tx, rx, send_key, self.key_var.get(), out, self.log)
            self._start_thread(run_probe_unlock, args)
        except Exception as exc:
            messagebox.showerror("Input error", str(exc))

    def start_info_read(self):
        try:
            backend, iface, dll, baud, tx, rx = self._common_args()
            args = (backend, iface, dll, baud, tx, rx, bool(self.info_unlock_var.get()), self.key_var.get(), self.log)
            self._start_thread(run_info_read, args)
        except Exception as exc:
            messagebox.showerror("Input error", str(exc))

    def start_safe_probe(self):
        try:
            backend, iface, dll, baud, tx, rx = self._common_args()
            args = (backend, iface, dll, baud, tx, rx, self.key_var.get(), self.log)
            self._start_thread(run_safe_capability_probe, args)
        except Exception as exc:
            messagebox.showerror("Input error", str(exc))

if __name__ == "__main__":
    App().mainloop()
