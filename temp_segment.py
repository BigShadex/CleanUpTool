        ttk.Button(btn_frame, text="Copy Path", command=self.copy_path).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side="right")

    def browse_dir(self) -> None:
        # Prefer a multi-folder picker (Treeview-based) for Windows,
        # fallback to standard single-folder picker elsewhere.
        dlg = MultiFolderDialog(self)
        self.wait_window(dlg)
        selection = dlg.result
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
