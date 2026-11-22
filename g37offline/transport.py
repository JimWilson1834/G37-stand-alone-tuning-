"""Strict classic-CAN normal-addressing ISO-TP for recorded files only."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re

HEADER = r"\s*(?:\((?P<timestamp>\d+(?:\.\d+)?)\)\s+)?(?P<channel>[\w.-]+)\s+(?:(?P<direction>RX|TX)\s+)?(?P<id>[0-9A-Fa-f]{3,8})"
COMPACT = re.compile(HEADER + r"#(?P<data>[0-9a-fA-F]*)\s*")
SPACED = re.compile(HEADER + r"\s+\[(?P<dlc>\d+)\]\s*(?P<data>(?:[0-9a-fA-F]{2}(?:\s+|$))*)\s*")
MESSAGE = re.compile(HEADER + r"\s+PDU\s+(?P<data>(?:[0-9a-fA-F]{2})+)\s*")


@dataclass
class Frame:
    line: int
    order: int
    channel: str
    can_id: int
    direction: str
    session: str
    timestamp: str | None
    data: bytes

    @property
    def key(self):
        return self.session, self.channel, self.direction, self.can_id

    def reference(self):
        return {"line": self.line, "order": self.order, "channel": self.channel,
                "can_id": f"0x{self.can_id:X}", "direction": self.direction, "session": self.session,
                "timestamp": self.timestamp,
                "timestamp_decimal_places": len(self.timestamp.split(".")[1]) if self.timestamp and "." in self.timestamp else 0}


@dataclass
class Message:
    frames: list[Frame]
    data: bytes

    @property
    def first(self):
        return self.frames[0]

    @property
    def last(self):
        return self.frames[-1]

    def reference(self):
        return {**self.first.reference(), "last_line": self.last.line,
                "frame_lines": [f.line for f in self.frames], "message_bytes": len(self.data)}


class Capture:
    def __init__(self):
        self.counts = Counter()
        self.diagnostics = []
        self.frames = []
        self.messages = []

    def issue(self, kind, lines, detail):
        self.counts[kind] += 1
        self.diagnostics.append({"kind": kind, "lines": lines, "detail": detail})


def parse(text: str, reassembled: bool = False, progress=None, cancelled=None) -> Capture:
    c = Capture()
    session = "default"
    patterns = [MESSAGE] if reassembled else [COMPACT, SPACED]
    for line, raw in enumerate(text.splitlines(), 1):
        if line % 4096 == 0:
            if cancelled and cancelled():
                raise InterruptedError("Import cancelled")
            if progress:
                progress(f"Parsing line {line:,}")
        if raw.startswith("# session "):
            session = raw[10:].strip() or f"line-{line}"
            c.counts["session_markers"] += 1
            continue
        if not raw.strip() or raw.lstrip().startswith("#"):
            c.counts["blank_or_comment_lines"] += 1
            continue
        matches = [m for p in patterns if (m := p.fullmatch(raw))]
        if len(matches) != 1:
            c.issue("ambiguous_lines" if matches else "malformed_lines", [line], "Expected a complete supported line; inspect format, DLC and hex")
            continue
        m = matches[0]
        try:
            data = bytes.fromhex(m["data"])
            can_id = int(m["id"], 16)
            if can_id > 0x1FFFFFFF or not data or (not reassembled and len(data) > 8):
                raise ValueError("CAN identifier or classic CAN data length out of range")
            if "dlc" in m.groupdict() and int(m["dlc"]) != len(data):
                raise ValueError("DLC differs from actual byte count")
        except ValueError as ex:
            c.issue("malformed_lines", [line], str(ex))
            continue
        f = Frame(line, len(c.frames), m["channel"], can_id, m["direction"] or "unknown", session, m["timestamp"], data)
        c.frames.append(f)
        if reassembled:
            c.messages.append(Message([f], data))
    c.counts["raw_frames" if not reassembled else "message_lines"] = len(c.frames)
    if not reassembled:
        reassemble(c)
    c.counts["complete_messages"] = len(c.messages)
    return c


def reassemble(c: Capture):
    active = {}

    def interrupt(key, line, kind="interrupted_messages"):
        if key in active:
            s = active.pop(key)
            c.issue(kind, [s["frames"][0].line, line], f"Received {len(s['data'])}/{s['length']} diagnostic bytes")

    for f in c.frames:
        d, key = f.data, f.key
        kind = d[0] >> 4
        if kind == 0:
            interrupt(key, f.line)
            length = d[0] & 15
            if not 1 <= length <= 7 or length > len(d) - 1:
                c.issue("truncated_messages", [f.line], "Invalid or truncated single-frame length")
            else:
                c.messages.append(Message([f], d[1:1 + length]))
        elif kind == 1:
            interrupt(key, f.line)
            length = ((d[0] & 15) << 8) | d[1] if len(d) >= 2 else 0
            if length <= 7 or len(d) != 8:
                c.issue("truncated_messages", [f.line], "Invalid classic first-frame length; extended lengths unsupported")
                continue
            active[key] = {"length": length, "data": bytearray(d[2:]), "frames": [f], "next": 1, "previous": None}
        elif kind == 2:
            if key not in active:
                c.issue("orphan_frames", [f.line], "Consecutive frame without an active first frame")
                continue
            s = active[key]
            seq = d[0] & 15
            if seq == ((s["next"] - 1) & 15) and s["previous"] == d:
                c.issue("duplicate_frames", [f.line], "Ignored identical immediate consecutive-frame retransmission")
                s["frames"].append(f)
                continue
            if seq != s["next"] or len(d) < 2:
                why = "conflicting_frames" if seq == ((s["next"] - 1) & 15) else "sequence_errors"
                interrupt(key, f.line, why)
                continue
            remaining = s["length"] - len(s["data"])
            if len(d) - 1 < min(7, remaining):
                interrupt(key, f.line, "truncated_messages")
                continue
            s["data"].extend(d[1:1 + remaining])
            s["frames"].append(f)
            s["next"] = (seq + 1) & 15
            s["previous"] = d
            if len(s["data"]) == s["length"]:
                c.messages.append(Message(s["frames"], bytes(s["data"])))
                del active[key]
        elif kind == 3:
            if len(d) < 3 or (d[0] & 15) > 2:
                c.issue("malformed_flow_control", [f.line], "Invalid flow-control frame")
            else:
                c.counts["flow_control_frames"] += 1
        else:
            c.counts["unrelated_frames"] += 1
    for key in list(active):
        interrupt(key, active[key]["frames"][-1].line, "truncated_messages")
    c.messages.sort(key=lambda m: m.first.order)
