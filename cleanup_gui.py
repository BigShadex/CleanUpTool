import os
import re
import platform
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional


class FileScanner:
    """Scan directories and return files sorted by size"""

    def scan(self, directory: str, min_size_bytes: int = 0):
        files = []
        for root, _, filenames in os.walk(directory):
            for name in filenames:
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                    if size >= min_size_bytes:
                        files.append((path, size))
                except (OSError, PermissionError):
                    continue
        files.sort(key=lambda x: x[1], reverse=True)
        return files

    def count_files(self, directory: str) -> int:
        """Count total files under directory (best-effort)."""
        total = 0
        for _, _, filenames in os.walk(directory):
            total += len(filenames)
        return total


class MultiFolderDialog(tk.Toplevel):
    """Simple multi-folder picker using a Treeview with Shift/Ctrl selection."""

    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self.title("Select Folders")
        self.geometry("900x560")
        self.result = None  # type: Optional[list[str]]
        self.transient(master)
        self.resizable(True, True)

        info = ttk.Label(self, text="Select one or more folders (Shift/Ctrl for multi-select)")
        info.pack(anchor="w", padx=12, pady=(10, 6))

        # Tree + scrollbars
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.tree = ttk.Treeview(container, columns=("path",), selectmode="extended")
        ysb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)

        self.tree.heading("#0", text="Folder")
        self.tree.heading("path", text="Path")
        self.tree.column("#0", width=300)
        self.tree.column("path", width=560)

        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        # Buttons
        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=12, pady=(0, 12))
        ttk.Button(btns, text="Cancel", command=self._on_cancel, width=12).pack(side="right")
        ttk.Button(btns, text="Select", command=self._on_select, width=12).pack(side="right", padx=(0, 8))

        # Populate roots
        self._populate_roots()
        self.tree.bind("<<TreeviewOpen>>", self._on_open)

        # Modal behavior
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _populate_roots(self) -> None:
        system = platform.system()
        if system == "Windows":
            for drive in self._windows_drives():
                node = self.tree.insert("", "end", text=drive, values=(drive,))
                self._add_dummy(node)
        else:
            node = self.tree.insert("", "end", text="/", values=("/",))
            self._add_dummy(node)

    @staticmethod
    def _windows_drives() -> list:
        import string
        drives = []
        for letter in string.ascii_uppercase:
            d = f"{letter}:\\"
            try:
                if os.path.isdir(d):
                    drives.append(d)
            except Exception:
                continue
        return drives

    def _add_dummy(self, parent):
        # Add a placeholder so the expand arrow appears
        self.tree.insert(parent, "end", text="…", values=("",), tags=("dummy",))

    def _on_open(self, _event=None):
        item = self.tree.focus()
        if not item:
            return
        # If first child is dummy, populate
        children = self.tree.get_children(item)
        if children and "dummy" in self.tree.item(children[0], "tags"):
            # Remove dummy
            for c in children:
                self.tree.delete(c)
            path = self.tree.set(item, "path") or self.tree.item(item, "text")
            self._populate_children(item, path)

    def _populate_children(self, parent, path: str) -> None:
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            child = self.tree.insert(parent, "end", text=entry.name, values=(entry.path,))
                            # Add dummy if it likely has children
                            if self._dir_has_subdir(entry.path):
                                self._add_dummy(child)
                    except PermissionError:
                        continue
        except Exception:
            # Ignore unreadable directories
            pass

    @staticmethod
    def _dir_has_subdir(path: str) -> bool:
        try:
            with os.scandir(path) as it:
                for sub in it:
                    try:
                        if sub.is_dir(follow_symlinks=False):
                            return True
                    except Exception:
                        continue
        except Exception:
            return False
        return False

    def _on_select(self) -> None:
        sels = self.tree.selection()
        if not sels:
            self.result = []
        else:
            # Deduplicate paths while preserving order
            seen = set()
            res = []
            for iid in sels:
                p = self.tree.set(iid, "path") or self.tree.item(iid, "text")
                if p and p not in seen and os.path.isdir(p):
                    res.append(p)
                    seen.add(p)
            self.result = res
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.destroy()


def select_folders_windows_native(parent_hwnd: int | None = None):
    """Use Windows' native FileOpenDialog to select multiple folders.
    Returns list of selected folder paths, or None on failure/cancel.
    """
    if platform.system() != "Windows":
        return None
    try:
        # Lazy import to avoid hard dependency when not on Windows
        from comtypes.client import CreateObject  # type: ignore
    except Exception:
        return None  # trigger fallback

    # Flags
    FOS_PICKFOLDERS = 0x00000020
    FOS_ALLOWMULTISELECT = 0x00000200
    SIGDN_FILESYSPATH = 0x80058000

    try:
        dlg = CreateObject("FileOpenDialog")
        try:
            dlg.SetTitle("Select Folders")
        except Exception:
            pass
        opts = dlg.GetOptions()
        dlg.SetOptions(int(opts) | FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT)
        dlg.Show(int(parent_hwnd or 0))
        results = dlg.GetResults()
        count = results.GetCount()
        paths = []
        for i in range(count):
            item = results.GetItemAt(i)
            paths.append(item.GetDisplayName(SIGDN_FILESYSPATH))
        return paths
    except Exception:
        # If the dialog fails or is cancelled, do not force the custom picker
        return []


def open_file_location(path: str) -> None:
    """Open the directory containing the given file in the OS file explorer."""
    directory = os.path.dirname(path)
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(directory)
        elif system == "Darwin":  # macOS
            subprocess.Popen(["open", directory])
        else:  # Linux and others
            subprocess.Popen(["xdg-open", directory])
    except Exception as exc:
        messagebox.showerror("Error", f"Unable to open location: {exc}")


class CleanupGUI(tk.Tk):
    """Graphical interface for scanning and managing files"""

    def __init__(self) -> None:
        super().__init__()
        self.title("CleanUpTool")
        self.geometry("1000x720")
        self.scanner = FileScanner()
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Directory selection
        path_frame = ttk.Frame(self)
        path_frame.pack(fill="x", padx=12, pady=10)
        self.dir_var = tk.StringVar()
        ttk.Label(path_frame, text="Directories:").pack(side="left", padx=(0,8))
        self.path_entry = ttk.Entry(path_frame, textvariable=self.dir_var)
        self.path_entry.pack(side="left", fill="x", expand=True)
        self.browse_btn = ttk.Button(path_frame, text="Select Folders", command=self.browse_dir)
        self.browse_btn.pack(side="left", padx=8)
        self.clear_btn = ttk.Button(path_frame, text="Clear", command=lambda: self.dir_var.set(""))
        self.clear_btn.pack(side="left")
        # Live selected-folders indicator
        self.roots_count_var = tk.StringVar(value="0 folders selected")
        ttk.Label(path_frame, textvariable=self.roots_count_var).pack(side="left", padx=8)

        # Filters
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill="x", padx=12, pady=(0,8))
        ttk.Label(filter_frame, text="Min size:").pack(side="left", padx=(0,6))
        self.min_size_var = tk.StringVar(value="10")  # default 10 MB
        self.size_unit_var = tk.StringVar(value="MB")
        self.min_size_entry = ttk.Entry(filter_frame, width=8, textvariable=self.min_size_var)
        self.min_size_entry.pack(side="left", padx=(0,6))
        self.unit_combo = ttk.Combobox(filter_frame, width=5, textvariable=self.size_unit_var, values=["KB","MB","GB"], state="readonly")
        self.unit_combo.pack(side="left", padx=(0,16))

        ttk.Label(filter_frame, text="Show top:").pack(side="left", padx=(0,6))
        self.max_items_var = tk.StringVar(value="100")
        self.max_items_entry = ttk.Entry(filter_frame, width=6, textvariable=self.max_items_var)
        self.max_items_entry.pack(side="left", padx=(0,16))

        self.scan_btn = ttk.Button(path_frame, text="Scan", command=self.scan)
        self.scan_btn.pack(side="left", padx=8)

        # Update count when directories change (manual edits or programmatic changes)
        self.dir_var.trace_add("write", lambda *_: self._update_roots_count())
        self._update_roots_count()

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=12, pady=(0,6))

        # Progress bar and status
        # Progress + status area (two rows for breathing room)
        progress_outer = ttk.Frame(self)
        progress_outer.pack(fill="x", padx=12, pady=(0,8))
        row1 = ttk.Frame(progress_outer)
        row1.pack(fill="x", pady=(0,6))
        self.status_var = tk.StringVar(value="Idle")
        self.status_label = ttk.Label(row1, textvariable=self.status_var)
        self.status_label.pack(side="left", fill="x", expand=True)
        self.cancel_btn = ttk.Button(row1, text="Cancel", command=self.cancel_scan, state="disabled", width=10)
        self.cancel_btn.pack(side="right")
        row2 = ttk.Frame(progress_outer)
        row2.pack(fill="x")
        self.progress = ttk.Progressbar(row2, mode="determinate")
        self.progress.pack(fill="x")

        # Results treeview
        columns = ("path", "size")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="extended")
        # Column headings with sort commands
        self.tree.heading("path", text="File Path", command=lambda c="path": self.sort_by(c))
        self.tree.heading("size", text="Size (MB)", command=lambda c="size": self.sort_by(c))
        self.tree.column("path", width=740)
        self.tree.column("size", width=140, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=12, pady=8)
        self.tree.bind("<Double-1>", self.open_selected)
        # Context menu for quick actions
        self._build_context_menu()

        # Action buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=12, pady=10)
        ttk.Button(btn_frame, text="Open File", command=self.open_file).pack(side="left")
        ttk.Button(btn_frame, text="Open Location", command=self.open_selected).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Copy Path", command=self.copy_path).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side="right")

    def browse_dir(self) -> None:
        # Try native Windows multiple-folder picker first (Explorer style)
        selection = None
        if platform.system() == "Windows":
            try:
                hwnd = self.winfo_id()
                selection = select_folders_windows_native(hwnd)
            except Exception:
                selection = None
        # If native picker isn't available, fall back to single-folder dialog
        if selection is None:
            directory = filedialog.askdirectory()
            if not directory:
                return
            selection = [directory]
        if selection:
            current = self.dir_var.get().strip()
            roots = self._parse_roots(current)
            roots.extend(selection)
            # de-duplicate while preserving order
            seen = set()
            unique = []
            for r in roots:
                if r and r not in seen:
                    unique.append(r)
                    seen.add(r)
            self.dir_var.set(";".join(unique))

    def scan(self) -> None:
        raw_dirs = self.dir_var.get()
        roots = self._parse_roots(raw_dirs)
        if not roots:
            messagebox.showwarning("No directory", "Please select one or more directories to scan.")
            return

        # Avoid concurrent scans
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to finish or cancel it.")
            return

        self.tree.delete(*self.tree.get_children())
        # Parse min size
        try:
            min_size_val = float(self.min_size_var.get().strip() or 0)
            unit = (self.size_unit_var.get() or "MB").upper()
            multiplier = 1
            if unit == "KB":
                multiplier = 1024
            elif unit == "MB":
                multiplier = 1024 ** 2
            elif unit == "GB":
                multiplier = 1024 ** 3
            min_size_bytes = int(min_size_val * multiplier)
        except ValueError:
            messagebox.showerror("Invalid size", "Please enter a valid number for minimum size.")
            return

        # Prepare UI for scanning
        self._set_scanning_ui(True)
        self.status_var.set(f"Counting files in {len(roots)} folder(s)...")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)
        self.stop_event.clear()

        # Launch background scan
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(roots, min_size_bytes), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, roots, min_size_bytes: int) -> None:
        try:
            # First pass: count files
            total_files = 0
            for root_dir in roots:
                if self.stop_event.is_set():
                    break
                total_files += self.scanner.count_files(root_dir)
            if self.stop_event.is_set():
                self._finish_scan([])
                return

            # Switch to determinate mode now that we know total
            self.after(0, lambda: self._setup_determinate_progress(total_files))

            # Second pass: scan and collect
            found = []
            processed = 0
            last_update = time.time()
            for root_dir in roots:
                for root, _, filenames in os.walk(root_dir):
                    if self.stop_event.is_set():
                        break
                    for name in filenames:
                        if self.stop_event.is_set():
                            break
                        path = os.path.join(root, name)
                        try:
                            size = os.path.getsize(path)
                            if size >= min_size_bytes:
                                found.append((path, size))
                        except (OSError, PermissionError):
                            pass
                        finally:
                            processed += 1
                        # Throttle UI updates to avoid overload
                        if time.time() - last_update > 0.1:
                            pct = 0 if total_files == 0 else min(100.0, (processed / max(1, total_files)) * 100.0)
                            self.after(0, lambda p=processed, t=total_files, f=len(found), pc=pct: self._update_progress(p, t, f, pc))
                            last_update = time.time()

            # Final update and finish
            found.sort(key=lambda x: x[1], reverse=True)
            self.after(0, lambda: self._finalize_results(found, processed, total_files))
        except Exception as exc:
            self.after(0, lambda e=exc: messagebox.showerror("Error", f"Scan failed: {e}"))
            self.after(0, lambda: self._set_scanning_ui(False))

    def _setup_determinate_progress(self, total_files: int) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(1, total_files), value=0)
        self.status_var.set(f"Scanning... 0/{total_files} files (found 0)")

    def _update_progress(self, processed: int, total: int, found_count: int, pct: float) -> None:
        self.progress['value'] = min(processed, self.progress['maximum'])
        self.status_var.set(f"Scanning... {processed}/{total} files ({pct:.1f}%) — found {found_count}")

    def _finalize_results(self, files, processed: int, total: int) -> None:
        self.progress['value'] = self.progress['maximum']
        total_bytes = sum(s for _, s in files)
        self.status_var.set(f"Done. {processed}/{total} files scanned — {len(files)} matches, {total_bytes/1_073_741_824:.2f} GB total")
        self.last_results = files[:]  # keep for export
        # Apply results limit
        limit = self._parse_int(self.max_items_var.get(), default=100)
        for path, size in files[:max(1, limit)]:
            self.tree.insert("", "end", values=(path, f"{size / 1_048_576:.2f}"))
        self._set_scanning_ui(False)

    def _set_scanning_ui(self, scanning: bool) -> None:
        # Enable/disable controls during scanning
        state = "disabled" if scanning else "normal"
        self.path_entry.config(state=state)
        self.browse_btn.config(state=state)
        self.clear_btn.config(state=state)
        self.scan_btn.config(state=state)
        self.min_size_entry.config(state=state)
        # Combobox uses special states
        self.unit_combo.config(state=("disabled" if scanning else "readonly"))
        self.cancel_btn.config(state=("normal" if scanning else "disabled"))

    def cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.status_var.set("Cancelling...")

    def _parse_roots(self, text: str) -> list:
        # Accept separators ; , or newlines; trim and validate existing directories
        if not text:
            return []
        parts = [p.strip().strip('"') for p in re.split(r"[;\n,]+", text) if p.strip()]
        # Deduplicate while preserving order
        seen = set()
        roots = []
        for p in parts:
            if p and p not in seen and os.path.isdir(p):
                roots.append(p)
                seen.add(p)
        return roots

    def _finish_scan(self, files) -> None:
        # Called when a scan ends early (e.g., cancelled during counting)
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.status_var.set("Cancelled.")
        self._set_scanning_ui(False)

    def _update_roots_count(self) -> None:
        count = len(self._parse_roots(self.dir_var.get()))
        label = f"{count} folder{'s' if count != 1 else ''} selected"
        self.roots_count_var.set(label)

    # --- Helpers & new actions ---
    def _parse_int(self, text: str, default: int = 0) -> int:
        try:
            return int(float((text or '').strip()))
        except Exception:
            return default

    def _build_context_menu(self) -> None:
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Open File", command=self.open_file)
        self.menu.add_command(label="Open Location", command=self.open_selected)
        self.menu.add_command(label="Copy Path", command=self.copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="Delete Selected", command=self.delete_selected)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event) -> None:
        try:
            row = self.tree.identify_row(event.y)
            if row:
                # If the right-clicked row is not selected, select only it.
                if row not in self.tree.selection():
                    self.tree.selection_set(row)
        except Exception:
            pass
        finally:
            self.menu.tk_popup(event.x_root, event.y_root)

    def get_selected_paths(self):
        sels = self.tree.selection()
        paths = []
        for iid in sels:
            vals = self.tree.item(iid, "values")
            if vals:
                paths.append(vals[0])
        return paths

    def open_file(self) -> None:
        for path in self.get_selected_paths()[:1]:  # open first only
            try:
                system = platform.system()
                if system == "Windows":
                    os.startfile(path)
                elif system == "Darwin":
                    subprocess.Popen(["open", path])
                else:
                    subprocess.Popen(["xdg-open", path])
            except Exception as exc:
                messagebox.showerror("Error", f"Unable to open file: {exc}")

    def copy_path(self) -> None:
        paths = self.get_selected_paths()
        if not paths:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(paths))
            self.status_var.set(f"Copied {len(paths)} path(s) to clipboard")
        except Exception as exc:
            messagebox.showerror("Error", f"Unable to copy path(s): {exc}")

    def delete_selected(self) -> None:
        paths = self.get_selected_paths()
        if not paths:
            return
        if not messagebox.askyesno("Delete", f"Delete {len(paths)} selected file(s)?"):
            return
        removed = 0
        for iid in list(self.tree.selection()):
            vals = self.tree.item(iid, "values")
            if not vals:
                continue
            path = vals[0]
            try:
                os.remove(path)
                self.tree.delete(iid)
                removed += 1
            except Exception as exc:
                messagebox.showerror("Error", f"Unable to delete {path}: {exc}")
        self.status_var.set(f"Deleted {removed} file(s)")

    def export_csv(self) -> None:
        import csv
        from tkinter.filedialog import asksaveasfilename
        if not getattr(self, 'last_results', None):
            messagebox.showinfo("Export", "No results to export yet.")
            return
        filename = asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files","*.csv")])
        if not filename:
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["path","size_bytes","size_mb"])
                for path, size in self.last_results:
                    writer.writerow([path, size, f"{size/1_048_576:.2f}"])
            self.status_var.set(f"Exported {len(self.last_results)} rows to {filename}")
        except Exception as exc:
            messagebox.showerror("Error", f"Export failed: {exc}")

    def sort_by(self, column: str) -> None:
        # Toggle sort order per column
        if not hasattr(self, '_sort_reverse'):
            self._sort_reverse = {"path": False, "size": True}
        self._sort_reverse[column] = not self._sort_reverse[column]
        reverse = self._sort_reverse[column]
        items = list(self.tree.get_children(""))
        def key_func(iid):
            vals = self.tree.item(iid, "values")
            if column == "size":
                try:
                    return float(vals[1])
                except Exception:
                    return 0.0
            return (vals[0] or "").lower()
        items.sort(key=key_func, reverse=reverse)
        for index, iid in enumerate(items):
            self.tree.move(iid, "", index)

    def open_selected(self, event=None) -> None:
        paths = self.get_selected_paths()
        if paths:
            open_file_location(paths[0])


if __name__ == "__main__":
    app = CleanupGUI()
    app.mainloop()
