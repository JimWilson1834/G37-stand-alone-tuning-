"""The shared GUI/CLI analysis and collision-safe export workflow."""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import tempfile

from . import ROM_SIZE, __version__
from .checksums import verify
from .inputs import import_decoded, load, summarize_inventory
from .model import RECOVERED, STATES, Segment, compare, digest, identity, runs
from .xdf import Definition, compatibility


@dataclass
class Options:
    input: str
    sidecar: str | None = None
    binary: str | None = None
    offset: int | None = None
    xdf: str | None = None
    compare: str | None = None
    base: str | None = None
    decoded_manifest: str | None = None
    derivative_manifest: str | None = None
    request_id: int = 0x7E0
    response_id: int = 0x7E8


@dataclass
class Result:
    analysis: object
    view: object
    report: dict
    maps: list
    definition: object
    options: Options


def analyze(options: Options, progress=None, cancelled=None):
    def checkpoint(message):
        if cancelled and cancelled():
            raise InterruptedError("Analysis cancelled")
        if progress:
            progress(message)

    input_paths = [getattr(options, name) for name in ["input", "sidecar", "xdf", "compare", "base", "decoded_manifest", "derivative_manifest"] if getattr(options, name)]
    initial_bindings = {str(Path(p).resolve()): identity(p)["sha256"] for p in input_paths}
    checkpoint("Reading saved input")
    a = load(options.input, sidecar=options.sidecar, binary=options.binary, offset=options.offset,
             request_id=options.request_id, response_id=options.response_id, progress=progress, cancelled=cancelled)
    if options.decoded_manifest:
        import_decoded(a, Path(options.decoded_manifest))
    view = a.image
    if options.base:
        checkpoint("Checking selected base")
        base = Path(options.base)
        if base.stat().st_size != ROM_SIZE:
            raise ValueError("Base must contain exactly 0x180000 bytes")
        view = a.image.overlay(base.read_bytes(), {**identity(base), "origin": "explicitly_selected_base",
                                                 "compatibility": "operator_selected; exact size alone is insufficient"})
        a.sources.append(identity(base))
    checkpoint("Calculating coverage and checksums")
    full = view.read(0, view.size)
    requested = []
    for start, end in sorted(a.requested_ranges):
        if requested and start <= requested[-1][1]:
            requested[-1][1] = max(requested[-1][1], end)
        else:
            requested.append([start, end])
    requested_states = Counter()
    for start, end in requested:
        requested_states.update(a.image.state[start:end])
    report = {"schema": "g37-offline-analysis-v1", "tool_version": __version__, "interval_convention": "half-open ROM byte ranges",
              "format": a.format, "sources": a.sources, "counts": dict(a.counts),
              "captured_coverage": a.image.coverage(), "view_coverage": view.coverage(),
              "requested_coverage": {"ranges": requested, "bytes": sum(b - s for s, b in requested),
                                     "state_bytes": {v: requested_states[k] for k, v in STATES.items()}},
              "rom_sha256": digest(full) if full is not None else None,
              "diagnostics": a.diagnostics, "events": a.events,
              "inventory": summarize_inventory(a.inventory), "inventory_records": a.inventory,
              "checksums": verify(view), "unresolved_terms": ["all UPC"],
              "provenance_segments": [{"rom_range": [s.offset, s.offset + len(s.data)], "source": s.source,
                                        "state": STATES[s.state], "data_sha256": digest(s.data)} for s in view.segments]}
    definition, maps = None, []
    if options.xdf:
        checkpoint("Interpreting XDF cells")
        definition = Definition(options.xdf)
        report["definition"] = definition.summary()
        derivative = json.loads(Path(options.derivative_manifest).read_text()) if options.derivative_manifest else None
        report["compatibility"] = compatibility(view, definition, derivative)
        maps = list(definition.cells(view))
    if options.compare:
        checkpoint("Comparing observed ranges")
        comparison = load(options.compare, binary="full")
        report["comparison"] = {"source": comparison.sources[0], **compare(comparison.image, view)}
        if definition:
            report["map_differences"] = definition.compare(comparison.image, view)
    checkpoint("Analysis ready")
    if any(a.input_bindings[p] != sha for p, sha in initial_bindings.items() if p in a.input_bindings):
        raise ValueError("Source snapshot changed while reading; analyze again")
    a.input_bindings.update(initial_bindings)
    for path, sha in a.input_bindings.items():
        if identity(path)["sha256"] != sha:
            raise ValueError(f"Source changed during analysis: {Path(path).name}; analyze again")
    return Result(a, view, report, maps, definition, options)


def summary(report):
    captured = report["captured_coverage"]["state_bytes"]
    view = report["view_coverage"]["state_bytes"]
    lines = [f"G37 offline analysis {report['tool_version']}", f"Detected format: {report['format']}"]
    lines += [f"{key}: {value:,} {'frames' if 'frames' in key else 'messages' if 'messages' in key else 'records' if 'records' in key else 'events/lines'}"
              for key, value in report["counts"].items()]
    lines += [f"Recovered: {report['captured_coverage']['recovered_bytes']:,} bytes",
              f"Missing within requested ranges: {report['requested_coverage']['state_bytes']['missing']:,} bytes",
              f"Missing from capture: {captured['missing']:,} bytes; conflicting: {captured['conflicting']:,} bytes",
              f"View base: {view['base']:,} bytes; deliberate fill: {view['filled']:,} bytes",
              f"ROM SHA-256: {report['rom_sha256'] or 'unavailable (incomplete/conflicting view)'}"]
    for c in report["checksums"]:
        values = f"stored={c['stored']:#x}, calculated={c['calculated']:#x}" if c['calculated'] is not None else "required coverage unavailable"
        lines.append(f"Checksum {c['field']}: {c['status']} ({values})")
    for name, group in report["inventory"].items():
        lines.append(f"{name}: {group['ordinary_records']:,} ordinary records, {group['terminal_records']} terminal records; "
                     f"{group['claimed_extent_bytes']:,} claimed extent bytes; 0 recovered bytes from envelopes")
    if "comparison" in report:
        c = report["comparison"]
        lines.append(f"Comparison: {c['changed_bytes']:,} changed bytes in {len(c['diff_runs']):,} runs; {c['excluded_bytes']:,} excluded bytes")
    if "definition" in report:
        lines.append(f"Definition: {report['definition']['object_counts']}; {report['definition']['unresolved_objects']} unresolved objects")
        lines.append(f"Calibration identity: {report['compatibility']['state']}")
    if report["diagnostics"]:
        lines.append("Diagnostics (first 20; all retained in JSON):")
        lines += [f"  {d['kind']} lines {d['lines']}: {d['detail']}" for d in report["diagnostics"][:20]]
    return "\n".join(lines) + "\n"


def export(result: Result, destination, mode="segments", cancelled=None):
    """Publish a new run directory atomically. Never replace an existing output."""
    if mode not in {"observed", "segments", "overlay"}:
        raise ValueError("Unknown export mode")
    a, view = result.analysis, result.view
    for path, sha in a.input_bindings.items():
        if identity(path)["sha256"] != sha:
            raise ValueError(f"Source changed since analysis: {Path(path).name}; analyze again before exporting")
    if mode == "observed" and a.image.read(0, ROM_SIZE, True) is None:
        raise ValueError("Fully observed BIN refused: missing, conflicting, base-supplied or filled bytes")
    if mode == "overlay" and (not result.options.base or view.read(0, ROM_SIZE) is None):
        raise ValueError("Overlay requires an explicitly selected exact-size base and conflict-free coverage")
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(f"Output already exists: {destination}; choose a new run directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock = destination.with_name(f".{destination.name}.lock")
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    staging = None
    try:
        if destination.exists():
            raise FileExistsError(destination)
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent))
        outputs = []

        def write(name, data):
            if cancelled and cancelled():
                raise InterruptedError("Export cancelled")
            p = staging / name
            with p.open("xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            outputs.append({"file": name, "bytes": len(data), "sha256": digest(data)})

        if mode == "observed":
            write("observed.bin", a.image.read(0, ROM_SIZE, True))
        elif mode == "overlay":
            write("base-overlay.bin", view.read(0, ROM_SIZE))
        else:
            for start, end in runs(i for i, s in enumerate(a.image.state) if s in RECOVERED):
                write(f"segment-{start:06X}-{end:06X}.bin", a.image.read(start, end - start, True))
        report = {**result.report, "export": {"mode": mode, "outputs": list(outputs),
                                             "base_spans": [s for s in result.report["view_coverage"]["spans"] if s["state"] == "base"] if mode == "overlay" else []}}
        write("report.json", json.dumps(report, indent=2, allow_nan=False).encode())
        write("maps.json", json.dumps(result.maps, indent=2, allow_nan=False).encode())
        write("summary.txt", summary(report).encode())
        write("SHA256SUMS.txt", "".join(f"{o['sha256']}  {o['file']}\n" for o in outputs).encode())
        if cancelled and cancelled():
            raise InterruptedError("Export cancelled")
        for path, sha in a.input_bindings.items():
            if identity(path)["sha256"] != sha:
                raise ValueError(f"Source changed during export: {Path(path).name}; analyze again")
        if destination.exists():
            raise FileExistsError(destination)
        staging.rename(destination)
        staging = None
    finally:
        if staging is not None:
            shutil.rmtree(staging)
        lock.unlink(missing_ok=True)
    return destination
