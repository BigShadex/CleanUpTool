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

## License

MIT License
