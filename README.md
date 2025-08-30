# CleanUpTool

A utility tool for cleaning up files and directories.

## Features

- File cleanup utilities
- Directory management
- Automated cleanup tasks
- GUI for scanning directories, viewing large files, and opening their locations

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from cleanup_tool import Cleaner

cleaner = Cleaner()
cleaner.cleanup_directory("path/to/directory")
```

### GUI Usage

```bash
python cleanup_gui.py
```

The GUI allows scanning a directory for the largest files. Double-click a file or use the **Open Location** button to open its folder in your file explorer. You can also delete files directly from the interface.

#### Filters & Controls
- Min size filter with units (KB/MB/GB).
- "Show top" limit for how many results to list.
- Progress bar with status and Cancel button.
- Multiple roots: Click "Select Folders" to pick multiple directories at once; you can also paste a semicolon-separated list into the field.

#### Table Actions
- Multi-select rows (Shift/Ctrl) and delete selected.
- Open file or open containing folder.
- Copy path(s) to clipboard.
- Click column headers to sort by path or size.
- Export full results to CSV.

#### Windows native folder picker
- The Browse button opens the native Explorer dialog that supports multi-selecting folders.
- Requires `comtypes` (installed via requirements). If unavailable, the app falls back to a built‑in picker.

#### GUI Filters and Progress

- Min size filter: Set a minimum file size and choose units (KB/MB/GB) before scanning; only files at least this size are listed.
- Progress bar: Shows determinate progress while scanning large folders, with a cancel button to stop.

## License

MIT License
