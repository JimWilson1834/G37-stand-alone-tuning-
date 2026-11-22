# Infiniti G37 ECU research tools

This project documents work on a 2009 Infiniti G37 and its 1,572,864-byte VQ37 ROM image. The checkout includes the v13 desktop application, a standalone checksum utility, a reference image, and a TunerPro XDF. Compatibility with another vehicle or calibration needs independent verification.

## Files in this checkout

| File | Purpose |
| --- | --- |
| `ACTUAL TOOL/g37_370z_ecu_tool_v13_combined_gui.py` | Historical Tk desktop application with Windows J2534 and Linux SocketCAN backends. |
| [VQ37 checksum utility](ACTUAL%20TOOL/g37_vq37_checksum_gui.py) | Reads and compares four stored checksum fields. The `--check` mode reads a file without opening the GUI or changing the image. |
| [Reference image directory](ACTUAL%20TOOL/DEF) | Contains `Original.bin` and `TESTED.xdf`. The second `Original.bin` beside the desktop application is the same Git blob. Both paths are retained for existing users. |
| [Map index](docs/map-index.csv) | Lists every XDF object, including entries with unknown addresses. |
| [Reference audit](docs/reference-audit.md) | Image and XDF fingerprints, map counts, examples and validation limits. |
| [Archive index](archive/README.md) | Original project overview, historical release snapshot and version guide. |

## Check a local image

Run this from the repository root with Python 3.10 or later and Tk available. This file operation works without a vehicle adapter.

```shell
python "ACTUAL TOOL/g37_vq37_checksum_gui.py" --check "ACTUAL TOOL/DEF/Original.bin"
```

The bundled image prints `Status: PASS` and exits with code 0. Exit code 2 indicates a checksum mismatch. Validate an exact-size full image. The historical checker accepts larger inputs and computes over the defined ROM ranges. A checksum result by itself cannot establish byte coverage, ROM identity, or suitability for a vehicle.

## Project background

Development used the Infiniti G37, Windows J2534, Linux SocketCAN, captured diagnostic traffic and offline ROM comparison. Historical research also used a PEAK-compatible CAN interface, Tactrix OpenPort, HP Tuners MPVI3 and Ghidra. The public release and the earlier experiments have different contents. The archive records what actually shipped.

This is experimental software. ECU programming can damage hardware or cause unsafe operation. The original author's intended-use statement, precautions and disclaimer are preserved in the [original project overview](archive/README-before-cleanup.md). The repository includes an [MIT license](LICENSE).

To support the original author's work, use Cash App `$xchempychx` or [PayPal](https://paypal.me/crank187star).
