"""Tk callback integration; requires a display, optionally the private evidence."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from g37offline import ROM_SIZE, STOCK_SHA256
from g37offline.model import digest
from g37offline.workflow import Options, analyze, export


@unittest.skipUnless(os.environ.get("DISPLAY"), "Tk integration requires DISPLAY")
class GuiTests(unittest.TestCase):
    def test_normal_file_workflow_matches_cli_engine(self):
        from g37offline.gui import App
        root = Path(__file__).resolve().parents[1]
        evidence = Path(os.environ.get("G37_EVIDENCE", "/nonexistent-g37-evidence"))
        fixtures = evidence / "historical/fixtures"
        use_evidence = (fixtures / "read-data-responses.log").exists()
        inp = fixtures / "read-data-responses.log" if use_evidence else root / "ACTUAL TOOL/DEF/Original.bin"
        app = App()
        self.addCleanup(app.destroy)
        errors = []

        def wait_ready():
            deadline = time.monotonic() + 90
            while app.busy and time.monotonic() < deadline:
                app.update()
                time.sleep(0.02)
            app.update()
            self.assertFalse(app.busy, "GUI operation timed out")
            self.assertEqual(errors, [])

        with tempfile.TemporaryDirectory() as tmp, patch("g37offline.gui.messagebox.showerror", side_effect=lambda title, text, **kw: errors.append(text)):
            tmp = Path(tmp)
            with patch("g37offline.gui.filedialog.askopenfilename", return_value=str(inp)):
                app._browse("input")
            if use_evidence:
                with patch("g37offline.gui.filedialog.askopenfilename", return_value=str(fixtures / "read-segments.csv")):
                    app._browse("sidecar")
            else:
                app.fields["binary"].set("full")
            app.fields["compare"].set(str(root / "ACTUAL TOOL/DEF/Original.bin"))
            app.analyze_button.invoke()
            wait_ready()
            self.assertIsNotNone(app.result)
            self.assertEqual(app.result.report["rom_sha256"], STOCK_SHA256)
            self.assertEqual(len(app.objects.get_children()), 197)
            # Inspect a real cell through the tree callbacks.
            app.objects.selection_set("0")
            app._select_object()
            app.cells.selection_set("0")
            app._select_cell()
            self.assertIn("raw_hex", app.details.get("1.0", "end"))
            app.mode.set("observed")
            gui_out = tmp / "gui"
            with patch("g37offline.gui.filedialog.asksaveasfilename", return_value=str(gui_out)):
                app.export_button.invoke()
            wait_ready()
            cli_out = tmp / "cli"
            export(analyze(app.options()), cli_out, "observed")
            self.assertEqual((gui_out / "observed.bin").read_bytes(), (cli_out / "observed.bin").read_bytes())
            self.assertEqual(digest((gui_out / "observed.bin").read_bytes()), STOCK_SHA256)
            self.assertEqual(json.loads((gui_out / "report.json").read_text()), json.loads((cli_out / "report.json").read_text()))
            app.fields["input"].set(str(root / "ACTUAL TOOL/DEF/Original.bin"))
            self.assertIsNone(app.result)
            self.assertEqual(str(app.export_button["state"]), "disabled")
