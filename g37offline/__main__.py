"""python -m g37offline: file analysis without importing any vehicle code."""
import argparse
from dataclasses import fields
import sys

from . import __version__
from .workflow import Options, analyze, export, summary


def main(argv=None):
    p = argparse.ArgumentParser(description="G37 saved-file reconstruction and map analysis")
    p.add_argument("input", nargs="?")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--gui", action="store_true")
    p.add_argument("--sidecar")
    p.add_argument("--binary", choices=["full", "interval"])
    p.add_argument("--offset", type=lambda x: int(x, 0))
    p.add_argument("--xdf")
    p.add_argument("--compare", help="Explicit full comparison BIN")
    p.add_argument("--base", help="Explicit full base for an overlay view")
    p.add_argument("--decoded-manifest")
    p.add_argument("--derivative-manifest")
    p.add_argument("--request-id", type=lambda x: int(x, 0), default=0x7E0)
    p.add_argument("--response-id", type=lambda x: int(x, 0), default=0x7E8)
    p.add_argument("--mode", choices=["observed", "segments", "overlay"], default="segments")
    p.add_argument("--output", help="New run directory; existing paths are never replaced")
    args = p.parse_args(argv)
    if args.gui:
        from .gui import launch
        return launch()
    if not args.input:
        p.error("input is required unless --gui is used")
    try:
        options = Options(**{f.name: getattr(args, f.name) for f in fields(Options)})
        result = analyze(options)
        print(summary(result.report), end="")
        if args.output:
            out = export(result, args.output, args.mode)
            print(f"Exported new run: {out}")
        if result.analysis.format in {"unsupported", "ambiguous", "unsupported_hpt", "binary_requires_declaration"}:
            return 2
        if args.mode == "observed" and result.analysis.image.read(0, result.analysis.image.size, True) is None:
            return 2
        return 0
    except (ValueError, OSError, KeyError) as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled; no final output published", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
