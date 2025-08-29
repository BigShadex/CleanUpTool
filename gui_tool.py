import os
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class DiskUsageViewer:
    """Simple GUI to scan directories and manage large files."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CleanUpTool - Disk Usage Viewer")

        top_frame = tk.Frame(root)
        top_frame.pack(fill=tk.X)

        scan_btn = tk.Button(top_frame, text="Scan Directory", command=self.scan_directory)
        scan_btn.pack(side=tk.LEFT, padx=5, pady=5)

        delete_btn = tk.Button(top_frame, text="Delete Selected", command=self.delete_selected)
        delete_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.tree = ttk.Treeview(root, columns=("path", "size"), show="headings")
        self.tree.heading("path", text="Path")
        self.tree.heading("size", text="Size (MB)")
        self.tree.column("path", width=500)
        self.tree.column("size", width=100, anchor=tk.E)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.open_selected)

    def scan_directory(self) -> None:
        directory = filedialog.askdirectory()
        if not directory:
            return
        file_items = []
        for root_dir, _dirs, files in os.walk(directory):
            for name in files:
                path = os.path.join(root_dir, name)
                try:
                    size = os.path.getsize(path) / (1024 * 1024)  # size in MB
                    file_items.append((path, size))
                except OSError:
                    continue
        file_items.sort(key=lambda x: x[1], reverse=True)
        self.tree.delete(*self.tree.get_children())
        for path, size in file_items[:100]:  # show top 100 largest files
            self.tree.insert("", tk.END, values=(path, f"{size:.2f}"))

    def open_selected(self, _event) -> None:
        item = self.tree.focus()
        if not item:
            return
        path = self.tree.item(item, "values")[0]
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def delete_selected(self) -> None:
        item = self.tree.focus()
        if not item:
            return
        path = self.tree.item(item, "values")[0]
        if messagebox.askyesno("Delete", f"Delete {path}?"):
            try:
                os.remove(path)
                self.tree.delete(item)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))


if __name__ == "__main__":
    root = tk.Tk()
    app = DiskUsageViewer(root)
    root.mainloop()
