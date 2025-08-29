import os
import platform
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional


class FileScanner:
    """Scan directories and return files sorted by size"""

    def scan(self, directory: str):
        files = []
        for root, _, filenames in os.walk(directory):
            for name in filenames:
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                    files.append((path, size))
                except (OSError, PermissionError):
                    continue
        files.sort(key=lambda x: x[1], reverse=True)
        return files


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
        self.geometry("800x600")
        self.scanner = FileScanner()

        # Directory selection
        path_frame = ttk.Frame(self)
        path_frame.pack(fill="x", padx=5, pady=5)
        self.dir_var = tk.StringVar()
        ttk.Entry(path_frame, textvariable=self.dir_var).pack(side="left", fill="x", expand=True)
        ttk.Button(path_frame, text="Browse", command=self.browse_dir).pack(side="left", padx=5)
        ttk.Button(path_frame, text="Scan", command=self.scan).pack(side="left")

        # Results treeview
        columns = ("path", "size")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        self.tree.heading("path", text="File Path")
        self.tree.heading("size", text="Size (MB)")
        self.tree.column("path", width=600)
        self.tree.column("size", width=100, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        self.tree.bind("<Double-1>", self.open_selected)

        # Action buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="Open Location", command=self.open_selected).pack(side="left")
        ttk.Button(btn_frame, text="Delete File", command=self.delete_selected).pack(side="left", padx=5)

    def browse_dir(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)

    def scan(self) -> None:
        directory = self.dir_var.get()
        if not directory:
            messagebox.showwarning("No directory", "Please select a directory to scan.")
            return

        self.tree.delete(*self.tree.get_children())
        files = self.scanner.scan(directory)
        for path, size in files[:100]:  # show top 100 largest files
            self.tree.insert("", "end", values=(path, f"{size / 1_048_576:.2f}"))

    def get_selected_path(self) -> Optional[str]:
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")[0]

    def open_selected(self, event=None) -> None:
        path = self.get_selected_path()
        if path:
            open_file_location(path)

    def delete_selected(self) -> None:
        path = self.get_selected_path()
        if path and messagebox.askyesno("Delete", f"Delete {path}?"):
            try:
                os.remove(path)
                self.tree.delete(self.tree.selection()[0])
            except Exception as exc:
                messagebox.showerror("Error", f"Unable to delete file: {exc}")


if __name__ == "__main__":
    app = CleanupGUI()
    app.mainloop()
