"""Small Tk saved-file workspace over the same headless analysis engine."""
from __future__ import annotations

import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .workflow import Options, analyze, export, summary


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("G37 Offline Capture Analysis")
        self.geometry("1180x850")
        self.minsize(900, 650)
        self.fields = {name: tk.StringVar() for name in
                       ["input", "sidecar", "base", "xdf", "compare", "decoded_manifest", "derivative_manifest", "binary", "offset"]}
        self.fields["xdf"].set(str(Path(__file__).resolve().parents[1] / "ACTUAL TOOL" / "DEF" / "TESTED.xdf"))
        self.mode = tk.StringVar(value="segments")
        self.status = tk.StringVar(value="Choose a saved capture or an explicitly declared BIN")
        self.result = None
        self.busy = False
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.generation = 0
        self._build()
        for value in self.fields.values():
            value.trace_add("write", self._invalidate)
        self.after(100, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build(self):
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)
        inputs = ttk.LabelFrame(outer, text="Saved files", padding=8)
        inputs.pack(fill="x")
        for row, (key, label) in enumerate([
                ("input", "Capture / segments / BIN"), ("sidecar", "Response address sidecar (optional)"),
                ("base", "Full base BIN (optional)"), ("xdf", "XDF definition (optional)"),
                ("compare", "Full comparison BIN (optional)"), ("decoded_manifest", "Decoded artifact manifest (optional)"),
                ("derivative_manifest", "Derivative lineage manifest (optional)")]):
            ttk.Label(inputs, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=2)
            ttk.Entry(inputs, textvariable=self.fields[key]).grid(row=row, column=1, sticky="ew", padx=4, pady=2)
            ttk.Button(inputs, text="Browse…", command=lambda k=key: self._browse(k)).grid(row=row, column=2, padx=4)
        inputs.columnconfigure(1, weight=1)
        declarations = ttk.Frame(inputs)
        declarations.grid(row=7, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Label(declarations, text="BIN interpretation:").pack(side="left")
        ttk.Combobox(declarations, textvariable=self.fields["binary"], values=["", "full", "interval"], state="readonly", width=12).pack(side="left", padx=6)
        ttk.Label(declarations, text="Interval ROM offset:").pack(side="left")
        ttk.Entry(declarations, textvariable=self.fields["offset"], width=16).pack(side="left", padx=6)
        ttk.Label(declarations, text="e.g. 0x8200; leave interpretation blank for text captures").pack(side="left")
        actions = ttk.Frame(outer, padding=(0, 8))
        actions.pack(fill="x")
        self.analyze_button = ttk.Button(actions, text="Analyze files", command=self.start_analysis)
        self.analyze_button.pack(side="left")
        ttk.Button(actions, text="Cancel", command=self.cancel_event.set).pack(side="left", padx=6)
        ttk.Label(actions, text="Export:").pack(side="left", padx=(12, 4))
        ttk.Combobox(actions, textvariable=self.mode, values=["segments", "observed", "overlay"], state="readonly", width=12).pack(side="left")
        self.export_button = ttk.Button(actions, text="Export new run…", command=self.choose_export, state="disabled")
        self.export_button.pack(side="left", padx=6)
        ttk.Label(outer, textvariable=self.status, wraplength=1100).pack(fill="x", pady=(0, 6))
        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        self.summary_text = self._text_tab(notebook, "Coverage and checksums")
        map_tab = ttk.Frame(notebook)
        notebook.add(map_tab, text="Maps")
        panes = ttk.Panedwindow(map_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left, right = ttk.Frame(panes), ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=3)
        self.objects = ttk.Treeview(left, columns=("address",), show="tree headings")
        self.objects.heading("#0", text="Object ID / original title")
        self.objects.heading("address", text="ROM offset")
        self.objects.column("address", width=85)
        self.objects.pack(fill="both", expand=True)
        self.objects.bind("<<TreeviewSelect>>", self._select_object)
        self.cells = ttk.Treeview(right, columns=("row", "col", "offset", "raw", "value", "status"), show="headings", height=10)
        for col in self.cells["columns"]:
            self.cells.heading(col, text=col)
            self.cells.column(col, width=90 if col != "status" else 160)
        self.cells.pack(fill="both", expand=True)
        self.cells.bind("<<TreeviewSelect>>", self._select_cell)
        self.details = tk.Text(right, height=12, wrap="word")
        self.details.pack(fill="both", expand=True)
        self.diff_text = self._text_tab(notebook, "Differences")
        self.event_text = self._text_tab(notebook, "Events and diagnostics")

    @staticmethod
    def _text_tab(notebook, label):
        panel = ttk.Frame(notebook)
        notebook.add(panel, text=label)
        text = tk.Text(panel, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(panel, command=text.yview)
        scroll.pack(side="right", fill="y")
        text.configure(yscrollcommand=scroll.set)
        text.pack(fill="both", expand=True)
        return text

    @staticmethod
    def _show(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def _browse(self, key):
        path = filedialog.askopenfilename(title=f"Choose {key.replace('_', ' ')}")
        if path:
            self.fields[key].set(path)

    def _invalidate(self, *args):
        self.generation += 1
        self.result = None
        self.export_button.configure(state="disabled")
        self.status.set("Inputs changed; analyze before exporting")

    def options(self):
        values = {k: v.get().strip() or None for k, v in self.fields.items()}
        if not values["input"]:
            raise ValueError("Choose an input file")
        if values["offset"] is not None:
            values["offset"] = int(values["offset"], 0)
        return Options(**values)

    def start_analysis(self):
        if self.busy:
            return
        try:
            options = self.options()
        except ValueError as ex:
            messagebox.showerror("Input", str(ex), parent=self)
            return
        self.result = None
        self.export_button.configure(state="disabled")
        generation = self.generation
        self._start(lambda: analyze(options, self._progress, self.cancel_event.is_set), "analysis", generation)

    def _progress(self, message):
        self.events.put(("progress", None, message))

    def _start(self, operation, kind, generation):
        self.busy = True
        self.cancel_event.clear()
        self.analyze_button.configure(state="disabled")
        self.export_button.configure(state="disabled")

        def work():
            try:
                self.events.put((kind, generation, operation()))
            except Exception as ex:
                self.events.put(("error", generation, ex))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                kind, generation, value = self.events.get_nowait()
                if kind == "progress":
                    self.status.set(value)
                    continue
                self.busy = False
                self.analyze_button.configure(state="normal")
                if kind == "error":
                    self.status.set(str(value))
                    messagebox.showerror("Offline analysis", str(value), parent=self)
                elif kind == "analysis":
                    if generation != self.generation:
                        self.status.set("Inputs changed during analysis; analyze again before exporting")
                        continue
                    self.result = value
                    self._render()
                    self.status.set("Analysis ready. Inspect coverage, differences and maps, then export a new run.")
                elif kind == "export":
                    self.status.set(f"Exported {value}")
                self.export_button.configure(state="normal" if self.result is not None else "disabled")
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _render(self):
        self._show(self.summary_text, summary(self.result.report))
        self._show(self.diff_text, json.dumps({k: self.result.report.get(k) for k in ["comparison", "map_differences"]}, indent=2))
        self._show(self.event_text, json.dumps({k: self.result.report[k] for k in ["events", "diagnostics", "inventory"]}, indent=2))
        self.objects.delete(*self.objects.get_children())
        self.cells.delete(*self.cells.get_children())
        self._show(self.details, "Select an object, then a cell to inspect source lines, raw bytes and formula.")
        for i, obj in enumerate(self.result.maps):
            off = obj["cells"][0].get("address") if obj["cells"] else None
            self.objects.insert("", "end", iid=str(i), text=f"{obj['object_id']} {obj['title']}",
                                values=(f"0x{off:X}" if off is not None else "unresolved",))

    def _select_object(self, event=None):
        selected = self.objects.selection()
        if not selected or self.result is None:
            return
        obj = self.result.maps[int(selected[0])]
        self.current_object = obj
        self.cells.delete(*self.cells.get_children())
        for i, cell in enumerate(obj["cells"]):
            off = cell.get("address")
            self.cells.insert("", "end", iid=str(i), values=(cell["row"], cell["column"], f"0x{off:X}" if off is not None else "?",
                              cell.get("raw_hex", ""), cell.get("value") if cell.get("value") is not None else "unavailable", cell["status"]))
        self._show(self.details, json.dumps({k: v for k, v in obj.items() if k != "cells"}, indent=2))

    def _select_cell(self, event=None):
        selected = self.cells.selection()
        if selected:
            self._show(self.details, json.dumps(self.current_object["cells"][int(selected[0])], indent=2))

    def choose_export(self):
        destination = filedialog.asksaveasfilename(title="Choose a NEW run directory name", initialfile="g37-analysis-run")
        if destination:
            self.start_export(destination)

    def start_export(self, destination):
        if self.busy or self.result is None:
            return
        result, mode = self.result, self.mode.get()
        self._start(lambda: export(result, destination, mode, self.cancel_event.is_set), "export", self.generation)

    def _close(self):
        self.cancel_event.set()
        self.destroy()


def launch():
    App().mainloop()
    return 0
