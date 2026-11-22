"""Content dispatch, request correlation and addressed saved-data imports."""
from __future__ import annotations

from collections import Counter
import csv
from dataclasses import dataclass, field
import io
import json
from pathlib import Path
import re

from . import ROM_SIZE
from .model import Image, Segment, bounds, digest, identity, runs
from .transport import Capture, COMPACT, SPACED, MESSAGE, parse


def integer(value):
    return int(str(value), 16 if str(value).lower().startswith("0x") else 10)


def checked_hash(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Expected a lowercase SHA-256 digest")
    return value


@dataclass
class Analysis:
    image: Image = field(default_factory=Image)
    format: str = "unsupported"
    sources: list[dict] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    diagnostics: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    inventory: list[dict] = field(default_factory=list)
    requested_ranges: list[list[int]] = field(default_factory=list)
    input_bindings: dict[str, str] = field(default_factory=dict)
    capture: Capture | None = None

    def issue(self, kind, lines, detail):
        self.counts[kind] += 1
        self.diagnostics.append({"kind": kind, "lines": lines, "detail": detail})


def detect(path: Path, raw: bytes) -> str:
    if path.suffix.lower() == ".hpt":
        return "unsupported_hpt"
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "binary_requires_declaration"
    lines = [s for s in text.splitlines()[:128] if s.strip() and not s.lstrip().startswith("#")]
    if not lines:
        return "unsupported"
    header = next(csv.reader([lines[0]]))
    if {"rom_offset_hex", "length", "data_hex"}.issubset(header):
        return "segments_csv"
    if {"variant", "record_class", "rom_extent_bytes", "raw_log_envelope_sha256"}.issubset(header):
        return "envelope_inventory"
    frame_lines = sum(bool(COMPACT.fullmatch(s) or SPACED.fullmatch(s)) for s in lines)
    message_lines = sum(bool(MESSAGE.fullmatch(s)) for s in lines)
    if frame_lines and message_lines:
        return "ambiguous"
    if frame_lines:
        return "can_frames"
    if message_lines:
        return "messages"
    return "unsupported"


def rows(path: Path):
    return list(csv.DictReader(path.read_text(encoding="utf-8-sig").splitlines()))


def read_associations(path: Path):
    if path.suffix.lower() == ".json":
        obj = json.loads(path.read_text())
        return [{"rom_offset_hex": r.get("rom_offset_hex", str(r["rom_offset"])), "length": r["length"],
                 "data_hex": r.get("data_hex"), "first_exported_frame_line": r["excerpt_first_line"],
                 "last_exported_frame_line": r["excerpt_last_line"],
                 "source_request_line": r.get("source_read_request_line"),
                 "original_source": {"file": obj.get("source"), "sha256": obj.get("source_sha256")}}
                for r in obj["responses"]]
    return rows(path)


def segments_from_csv(a: Analysis, path: Path):
    source = a.sources[0]
    for row_number, row in enumerate(rows(path), 2):
        try:
            offset, length = integer(row["rom_offset_hex"]), integer(row["length"])
            bounds(offset, length)
            data = bytes.fromhex(row["data_hex"])
            if len(data) != length:
                raise ValueError("Data length differs from declared length")
            a.requested_ranges.append([offset, offset + length])
            a.image.add(Segment(offset, data, {**source, "row": row_number,
                               "association": row, "origin": "normalized_decoded_segments"}))
            a.counts["data_records"] += 1
        except (ValueError, KeyError) as ex:
            a.issue("invalid_segments", [row_number], str(ex))


def attach_responses(a: Analysis, sidecar: Path):
    source = identity(sidecar)
    a.input_bindings[str(sidecar.resolve())] = source["sha256"]
    a.sources.append(source)
    by_span = {(m.first.line, m.last.line): m for m in a.capture.messages if m.data[:1] == b"\x63"}
    used = set()
    for number, row in enumerate(read_associations(sidecar), 2):
        try:
            offset, length = integer(row["rom_offset_hex"]), integer(row["length"])
            bounds(offset, length)
            first, last = integer(row["first_exported_frame_line"]), integer(row["last_exported_frame_line"])
            if first <= 0 or last < first or (first, last) in used:
                raise ValueError("Invalid or duplicate response span association")
            a.requested_ranges.append([offset, offset + length])
            used.add((first, last))
            m = by_span.get((first, last))
            if m is None:
                a.issue("unresolved_associations", [first, last], f"Sidecar row {number}: no complete data response; {length} ROM bytes unavailable at {offset:#x}")
                continue
            data = m.data[1:]
            if len(data) != length:
                raise ValueError(f"Response has {len(data)} data bytes, expected {length}")
            # Deliberately read frames first. This expected column never supplies output bytes.
            if row.get("data_hex") is not None and bytes.fromhex(row["data_hex"]) != data:
                a.issue("sidecar_data_disagreements", [first, last], f"Sidecar row {number} differs from reassembled frames at {offset:#x}; extent excluded")
                continue
            a.image.add(Segment(offset, data, {**a.sources[0], **m.reference(), "origin": "captured_response_frames",
                               "address_provenance": {**source, "row": number, "record": row}}))
            a.counts["data_records"] += 1
            a.counts[f"records_with_{length}_data_bytes"] += 1
        except (ValueError, KeyError) as ex:
            a.issue("invalid_associations", [number], str(ex))
    a.counts["unassociated_data_responses"] = len(set(by_span) - used)


def envelope(message: bytes) -> dict:
    if not message or message[0] != 0x34:
        raise ValueError("Not a write-family envelope")
    if len(message) < 6:
        raise ValueError("Truncated record header")
    subtype, offset, length = message[1], int.from_bytes(message[2:5], "big"), message[5]
    result = {"envelope_sha256": digest(message), "message_bytes": len(message), "subtype": subtype,
              "integrity": "unverified_envelope_scope", "status": "opaque"}
    if len(message) == 136 and subtype == 0x81 and length == 128:
        bounds(offset, 128)
        return {**result, "record_class": "normal", "rom_offset": offset, "rom_extent_bytes": 128}
    # Terminal identity is evidence-bound, not inferred from length alone.
    if len(message) == 56 and digest(message) == "e97e2f7f84c0493748d087cdc5072494ce6a1ac1cb6f2da23273d72b4a594878":
        return {**result, "record_class": "terminal", "rom_offset": None, "rom_extent_bytes": 0}
    raise ValueError("Unknown record subtype/length/terminal identity; no claimed extent")


def classify(a: Analysis, request_id: int, response_id: int, correlate: bool):
    pending = {}
    for m in a.capture.messages:
        p, f = m.data, m.first
        key = f.session, f.channel
        if p[0] in {0x27, 0x67} or p[:2] == b"\x7f\x27":
            # Exports intentionally omit identifiers, challenge/response bytes and message digest.
            if p[:2] == b"\x7f\x27":
                event = "reported_rejection" if len(p) >= 3 and p[2] != 0x78 else "pending_or_truncated"
            elif len(p) < 2:
                event = "truncated_access_event"
            elif p[0] == 0x67:
                event = "challenge" if p[1] & 1 else "reported_acceptance"
            else:
                event = "challenge_request" if p[1] & 1 else "response"
            a.events.append({"kind": "SecurityAccess", "event": event, "lines": [f.line, m.last.line], "rom_bytes": 0})
            continue
        if p[0] == 0x34:
            try:
                a.inventory.append({**envelope(p), "source": {**a.sources[0], **m.reference()}})
            except ValueError as ex:
                a.issue("unknown_envelopes", [f.line, m.last.line], str(ex))
        if not correlate:
            continue
        if f.can_id == request_id and p[0] == 0x23:
            if key in pending:
                a.issue("outstanding_requests", [pending[key][2].first.line if pending[key] else f.line, f.line], "New read request replaced unresolved request; association invalidated")
                # An overlapping request makes later replies ambiguous. Keep neither.
                pending[key] = None
                continue
            try:
                if len(p) == 7:
                    offset, length = int.from_bytes(p[1:5], "big"), int.from_bytes(p[5:7], "big")
                else:
                    na, nl = p[1] & 15, p[1] >> 4
                    if na == 0 or nl == 0 or len(p) != 2 + na + nl:
                        raise ValueError("Unrecognized recorded read-address layout")
                    offset, length = int.from_bytes(p[2:2 + na], "big"), int.from_bytes(p[2 + na:], "big")
                bounds(offset, length)
                a.requested_ranges.append([offset, offset + length])
                pending[key] = offset, length, m
                a.counts["read_requests"] += 1
            except (ValueError, IndexError) as ex:
                a.issue("invalid_requests", [f.line], str(ex))
        elif f.can_id == response_id and p[:1] == b"\x63":
            req = pending.pop(key, None)
            if req is None:
                a.issue("orphan_data_responses", [f.line], "No unambiguous same-channel/session request")
                continue
            offset, length, request = req
            if len(p) - 1 != length:
                a.issue("response_length_mismatches", [request.first.line, f.line], f"Expected {length}, received {len(p) - 1} ROM bytes")
                continue
            a.image.add(Segment(offset, p[1:], {**a.sources[0], **m.reference(), "origin": "paired_capture",
                               "request": request.reference()}))
            a.counts["data_records"] += 1
            a.counts[f"records_with_{length}_data_bytes"] += 1
        elif f.can_id == response_id and p[:1] == b"\x7f":
            a.counts["negative_responses"] += 1
            if len(p) != 3:
                a.issue("truncated_negative_replies", [f.line], "Negative reply must contain service and response code")
            elif p[1] == 0x23 and p[2] != 0x78:
                pending.pop(key, None)
    for req in pending.values():
        if req:
            a.issue("outstanding_requests", [req[2].first.line], f"No complete response for {req[0]:#x}, length {req[1]}")


def inventory_csv(a: Analysis, path: Path):
    for number, r in enumerate(rows(path), 2):
        try:
            extent = integer(r["rom_extent_bytes"])
            if r["record_class"] == "terminal":
                if extent != 0 or r["rom_offset_hex"]:
                    raise ValueError("Terminal must have zero extent and no ROM offset")
                offset = None
            elif r["record_class"] == "normal" and extent == 128:
                offset = integer(r["rom_offset_hex"])
                bounds(offset, extent)
            else:
                raise ValueError("Unknown inventory record class or extent")
            raw_hash, msg_hash = checked_hash(r["raw_log_envelope_sha256"]), checked_hash(r["message_log_envelope_sha256"])
            if (r["envelope_equal"].lower() == "true") != (raw_hash == msg_hash):
                raise ValueError("Envelope equality column disagrees with digests")
            a.inventory.append({"variant": r["variant"], "record_class": r["record_class"],
                                "rom_offset": offset, "rom_extent_bytes": extent, "status": "hash_inventory_only",
                                "raw_envelope_sha256": raw_hash, "message_envelope_sha256": msg_hash,
                                "envelope_equal": raw_hash == msg_hash, "source_row": number})
        except (KeyError, ValueError) as ex:
            a.issue("invalid_inventory_rows", [number], str(ex))


def summarize_inventory(records):
    result = {}
    for variant in sorted({r.get("variant", "capture") for r in records}):
        group = [r for r in records if r.get("variant", "capture") == variant]
        ordinary = [r for r in group if r["record_class"] == "normal"]
        occupied = set()
        for r in ordinary:
            occupied.update(range(r["rom_offset"], r["rom_offset"] + r["rom_extent_bytes"]))
        result[variant] = {"ordinary_records": len(ordinary), "terminal_records": sum(r["record_class"] == "terminal" for r in group),
                           "claimed_extent_bytes": len(occupied), "claimed_ranges": list(runs(sorted(occupied))),
                           "different_ordinary_envelopes": sum(r.get("envelope_equal") is False for r in ordinary),
                           "recovered_bytes_from_envelopes": 0}
    return result


def load(path, *, sidecar=None, binary=None, offset=None, request_id=0x7E0, response_id=0x7E8,
         progress=None, cancelled=None) -> Analysis:
    path = Path(path)
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Input exceeds the supported 256 MiB bound")
    raw = path.read_bytes()
    source = {"file": path.name, "sha256": digest(raw), "bytes": len(raw)}
    a = Analysis(sources=[source], input_bindings={str(path.resolve()): source["sha256"]})
    a.format = detect(path, raw)
    if binary:
        if path.suffix.lower() == ".hpt":
            raise ValueError("A proprietary HPT container is not a declared raw BIN")
        if binary == "full":
            if len(raw) != ROM_SIZE or offset not in (None, 0):
                raise ValueError("Declared full BIN must contain exactly 0x180000 bytes at offset zero")
            offset = 0
        elif binary == "interval":
            if offset is None:
                raise ValueError("Interval BIN requires an explicit ROM offset")
        else:
            raise ValueError("Unknown binary interpretation")
        bounds(offset, len(raw))
        a.requested_ranges.append([offset, offset + len(raw)])
        a.format = f"{binary}_bin"
        a.image.add(Segment(offset, raw, {**a.sources[0], "origin": "explicit_binary_import", "rom_offset": offset,
                                        "capture_provenance": "not_established_by_binary_alone"}))
    elif a.format in {"can_frames", "messages"}:
        a.capture = parse(raw.decode("utf-8-sig"), a.format == "messages", progress, cancelled)
        a.counts.update(a.capture.counts)
        a.diagnostics.extend(a.capture.diagnostics)
        classify(a, request_id, response_id, correlate=sidecar is None)
        if sidecar:
            attach_responses(a, Path(sidecar))
    elif a.format == "segments_csv":
        if sidecar:
            raise ValueError("Normalized segments are already addressed; sidecar is for raw responses")
        segments_from_csv(a, path)
    elif a.format == "envelope_inventory":
        inventory_csv(a, path)
    else:
        a.issue("unsupported_input", [], f"Detected {a.format}; no recovered data. Raw BIN requires full/interval declaration; response frames require an address sidecar. Message logs use '<channel> <id> PDU <hex>'. HPT containers are unsupported.")
    return a


def import_decoded(a: Analysis, manifest_path: Path):
    """Verify an artifact AND its association; never invoke an encoded-payload decoder."""
    m = json.loads(manifest_path.read_text())
    if m.get("schema") != "g37-decoded-interval-v1" or m["input_sha256"] != a.sources[0]["sha256"]:
        raise ValueError("Decoded manifest schema/input binding mismatch")
    variant = m["variant"]
    inventory = summarize_inventory(a.inventory).get(variant)
    if not inventory or [m["rom_offset"], m["rom_offset"] + m["length"]] not in inventory["claimed_ranges"]:
        raise ValueError("Decoded interval must match the chosen run's claimed range")
    checked_hash(m["capture_sha256"])
    evidence_path = None
    if a.format == "envelope_inventory":
        evidence_path = (manifest_path.parent / m["capture_evidence_file"]).resolve()
        evidence_raw = evidence_path.read_bytes()
        if digest(evidence_raw) != m["capture_evidence_sha256"]:
            raise ValueError("Capture evidence file digest mismatch")
        evidence = json.loads(evidence_raw)
        index_evidence = evidence["write_record_envelope_index"]
        if index_evidence["sha256"] != m["input_sha256"]:
            raise ValueError("Capture evidence does not identify this envelope inventory")
        raw_log_name = index_evidence["pairs"][variant]["raw_log"]
        run = next((r for r in evidence["write_capture_structure"] if r["source_file"] == raw_log_name), None)
        if not run or run["variant"] != variant or run["sha256"] != m["capture_sha256"]:
            raise ValueError("Capture identity differs from the bound run evidence")
        if run["expected_address_interval"] != [m["rom_offset"], m["rom_offset"] + m["length"]]:
            raise ValueError("Decoded interval differs from the bound capture's recorded range")
    elif m["capture_sha256"] != a.sources[0]["sha256"]:
        raise ValueError("Capture hash does not match the supplied capture")
    if not m.get("decoder", {}).get("name") or not m["decoder"].get("version"):
        raise ValueError("Decoder/artifact producer name and version are required")
    decoded_path = (manifest_path.parent / m["decoded_file"]).resolve()
    reference_path = (manifest_path.parent / m["reference_file"]).resolve()
    data, ref = decoded_path.read_bytes(), reference_path.read_bytes()
    if len(data) != m["length"] or digest(data) != m["decoded_sha256"] or digest(ref) != m["reference_sha256"] or len(ref) != ROM_SIZE:
        raise ValueError("Decoded artifact/reference identity or length mismatch")
    offset = m["rom_offset"]
    bounds(offset, len(data))
    if data != ref[offset:offset + len(data)]:
        raise ValueError("Decoded artifact does not equal the bound reference interval")
    a.sources.extend([identity(manifest_path), identity(decoded_path), identity(reference_path)])
    for p in [manifest_path, decoded_path, reference_path]:
        a.input_bindings[str(p.resolve())] = identity(p)["sha256"]
    if evidence_path:
        a.sources.append(identity(evidence_path))
        a.input_bindings[str(evidence_path)] = digest(evidence_raw)
    a.image.add(Segment(offset, data, {"origin": "verified_decoded_artifact", "association": m,
                                    "manifest": identity(manifest_path), "source": identity(decoded_path),
                                    "qualification": "Artifact equality verified; capture identity is declared by sidecar; transform not rerun"}, 2))
