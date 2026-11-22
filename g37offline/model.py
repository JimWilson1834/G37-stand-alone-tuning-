"""Bounded sparse ROM, with provenance independent of byte values."""
from __future__ import annotations

from array import array
from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path

from . import ROM_SIZE

STATES = {0: "missing", 1: "observed", 2: "verified_decoded", 3: "base", 4: "filled", 5: "conflicting"}
RECOVERED = {1, 2}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(path: str | Path) -> dict:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return {"file": p.name, "sha256": h.hexdigest(), "bytes": p.stat().st_size}


def bounds(start: int, length: int, size: int = ROM_SIZE):
    if not isinstance(start, int) or not isinstance(length, int) or start < 0 or length <= 0 or start + length > size:
        raise ValueError(f"Invalid extent [{start!r}, +{length!r}) within {size:#x}")


def runs(indices):
    """Contiguous half-open ranges from ascending distinct indices."""
    start = prev = None
    for i in indices:
        if prev is not None and i != prev + 1:
            yield [start, prev + 1]
            start = None
        if start is None:
            start = i
        prev = i
    if start is not None:
        yield [start, prev + 1]


@dataclass
class Segment:
    offset: int
    data: bytes
    source: dict
    state: int = 1


class Image:
    def __init__(self, size: int = ROM_SIZE):
        if size <= 0 or size > ROM_SIZE:
            raise ValueError("Image size must be in [1, 0x180000]")
        self.size = size
        self.data = bytearray(size)
        self.state = bytearray(size)
        self.owner = array("i", [-1]) * size
        self.segments: list[Segment] = []
        self.conflicts: list[dict] = []
        self.identical_overlap_bytes = 0

    def add(self, segment: Segment):
        bounds(segment.offset, len(segment.data), self.size)
        if segment.state not in {1, 2, 3, 4}:
            raise ValueError("Invalid source state")
        number = len(self.segments)
        self.segments.append(segment)
        bad = []
        previous = set()
        for i, value in enumerate(segment.data, segment.offset):
            if self.state[i] == 0:
                self.data[i] = value
                self.state[i] = segment.state
                self.owner[i] = number
            elif self.state[i] == 5 or self.data[i] != value:
                previous.add(self.owner[i])
                self.state[i] = 5
                bad.append(i)
            else:
                self.identical_overlap_bytes += 1
        if bad:
            self.conflicts.append({"ranges": list(runs(bad)), "incoming_segment": number,
                                   "previous_segments": sorted(previous)})

    def read(self, start: int, length: int, recovered_only: bool = False) -> bytes | None:
        bounds(start, length, self.size)
        accepted = RECOVERED if recovered_only else {1, 2, 3, 4}
        if any(s not in accepted for s in self.state[start:start + length]):
            return None
        return bytes(self.data[start:start + length])

    def provenance(self, start: int, length: int) -> list[dict]:
        bounds(start, length, self.size)
        # Include all overlapping observations, including identical retransmissions.
        candidates = (range(len(self.segments)) if self.identical_overlap_bytes or self.conflicts
                      else sorted(set(self.owner[start:start + length]) - {-1}))
        return [{"segment": n, "range": [max(start, s.offset), min(start + length, s.offset + len(s.data))],
                 "state": STATES[s.state], "source": s.source}
                for n in candidates for s in [self.segments[n]]
                if s.offset < start + length and start < s.offset + len(s.data)]

    def coverage(self) -> dict:
        counts = Counter(self.state)
        spans = []
        start = 0
        for i in range(1, self.size + 1):
            if i == self.size or self.state[i] != self.state[start]:
                spans.append({"range": [start, i], "state": STATES[self.state[start]]})
                start = i
        return {"rom_range": [0, self.size], "state_bytes": {v: counts[k] for k, v in STATES.items()},
                "recovered_bytes": sum(counts[k] for k in RECOVERED), "spans": spans,
                "identical_overlap_bytes": self.identical_overlap_bytes,
                "first_conflicting_address": next((i for i, s in enumerate(self.state) if s == 5), None),
                "conflicts": self.conflicts}

    def overlay(self, base: bytes, source: dict) -> Image:
        if len(base) != self.size:
            raise ValueError("Base must have the exact ROM size")
        if 5 in self.state:
            raise ValueError("Cannot overlay conflicting observations")
        out = Image(self.size)
        for s in self.segments:
            out.add(s)
        for a, b in runs(i for i, s in enumerate(self.state) if s == 0):
            out.add(Segment(a, base[a:b], source, 3))
        return out


def compare(a: Image, b: Image, start: int = 0, end: int | None = None) -> dict:
    end = max(a.size, b.size) if end is None else end
    if start < 0 or end <= start or end > max(a.size, b.size):
        raise ValueError("Invalid comparison range")
    changed, excluded, tails = [], [], []
    for i in range(start, end):
        if i >= a.size or i >= b.size:
            tails.append(i)
        elif a.state[i] in {0, 5} or b.state[i] in {0, 5}:
            excluded.append(i)
        elif a.data[i] != b.data[i]:
            changed.append(i)
    return {"range": [start, end], "changed_bytes": len(changed), "diff_runs": list(runs(changed)),
            "unmatched_tail_bytes": len(tails), "unmatched_tails": list(runs(tails)),
            "excluded_bytes": len(excluded), "coverage_exclusions": list(runs(excluded))}
