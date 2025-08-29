"""
CleanUpTool - A utility for cleaning up files and directories
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional


class Cleaner:
    """Main cleaner class for file and directory operations"""

    def __init__(self):
        self.deleted_files = []
        self.deleted_dirs = []

    def cleanup_directory(self, directory_path: str, extensions: Optional[List[str]] = None) -> bool:
        """
        Clean up a directory by removing specified file types

        Args:
            directory_path: Path to the directory to clean
            extensions: List of file extensions to remove (e.g., ['.tmp', '.log'])

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            path = Path(directory_path)
            if not path.exists() or not path.is_dir():
                print(f"Directory {directory_path} does not exist or is not a directory")
                return False

            if extensions:
                for ext in extensions:
                    for file_path in path.rglob(f"*{ext}"):
                        if file_path.is_file():
                            file_path.unlink()
                            self.deleted_files.append(str(file_path))
                            print(f"Deleted: {file_path}")

            return True

        except Exception as e:
            print(f"Error cleaning directory: {e}")
            return False

    def remove_empty_directories(self, directory_path: str) -> bool:
        """
        Remove empty directories recursively

        Args:
            directory_path: Path to the directory to clean

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            path = Path(directory_path)
            if not path.exists() or not path.is_dir():
                print(f"Directory {directory_path} does not exist or is not a directory")
                return False

            for dir_path in sorted(path.rglob("*"), reverse=True):
                if dir_path.is_dir() and not any(dir_path.iterdir()):
                    dir_path.rmdir()
                    self.deleted_dirs.append(str(dir_path))
                    print(f"Removed empty directory: {dir_path}")

            return True

        except Exception as e:
            print(f"Error removing empty directories: {e}")
            return False

    def get_cleanup_summary(self) -> dict:
        """Get summary of cleanup operations"""
        return {
            "deleted_files": len(self.deleted_files),
            "deleted_directories": len(self.deleted_dirs),
            "files_list": self.deleted_files,
            "directories_list": self.deleted_dirs
        }


def main():
    """Main function for command line usage"""
    import argparse

    parser = argparse.ArgumentParser(description="CleanUpTool - File and directory cleanup utility")
    parser.add_argument("directory", help="Directory to clean")
    parser.add_argument("--extensions", nargs="+", help="File extensions to remove (e.g., .tmp .log)")
    parser.add_argument("--remove-empty", action="store_true", help="Remove empty directories")

    args = parser.parse_args()

    cleaner = Cleaner()

    if args.extensions:
        cleaner.cleanup_directory(args.directory, args.extensions)

    if args.remove_empty:
        cleaner.remove_empty_directories(args.directory)

    summary = cleaner.get_cleanup_summary()
    print(f"Cleanup complete!")
    print(f"Files deleted: {summary['deleted_files']}")
    print(f"Directories removed: {summary['deleted_directories']}")


if __name__ == "__main__":
    main()
