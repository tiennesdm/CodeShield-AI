"""
ZIP file extraction and validation for CodeShield AI.

Handles secure extraction of uploaded ZIP files with path traversal protection.
"""

import os
import zipfile
from pathlib import Path
from typing import List, Tuple

from utils.config import get_settings
from utils.helpers import sanitize_path
from utils.logger import get_logger

logger = get_logger(__name__)


class ZipHandler:
    """
    Handles ZIP file upload extraction securely.

    Prevents path traversal attacks and limits extraction size.
    """

    def __init__(self) -> None:
        """Initialize the ZIP handler."""
        self.settings = get_settings()

    def process_upload(self, zip_path: str, scan_id: str) -> Tuple[str, int, List[str]]:
        """
        Process an uploaded ZIP file.

        Args:
            zip_path: Path to the uploaded ZIP file
            scan_id: Scan identifier for temp directory naming

        Returns:
            Tuple of (extract_dir, file_count, extracted_files)

        Raises:
            ValueError: If ZIP is invalid or contains path traversal
            zipfile.BadZipFile: If not a valid ZIP file
        """
        # Validate ZIP file
        if not zipfile.is_zipfile(zip_path):
            raise ValueError("Uploaded file is not a valid ZIP archive")

        # Create extraction directory
        extract_dir = self.settings.temp_dir / f"zip_{scan_id}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Extract safely
            file_count, extracted_files = self._safe_extract(zip_path, str(extract_dir))

            if file_count == 0:
                raise ValueError("ZIP file contains no extractable files")

            logger.info(
                "Extracted %d files from ZIP to %s", file_count, extract_dir
            )

            # Find the actual project root (skip single top-level directory if present)
            project_root = self._find_project_root(str(extract_dir))

            return project_root, file_count, extracted_files

        except Exception:
            # Clean up on error
            import shutil

            shutil.rmtree(extract_dir, ignore_errors=True)
            raise

    def _safe_extract(self, zip_path: str, extract_to: str) -> Tuple[int, List[str]]:
        """
        Safely extract ZIP file contents.

        Prevents path traversal attacks by validating each member.

        Args:
            zip_path: Path to the ZIP file
            extract_to: Destination directory

        Returns:
            Tuple of (file_count, list of extracted file paths)
        """
        extracted_files: List[str] = []
        count = 0
        max_files = self.settings.max_files_per_scan
        max_size = self.settings.max_upload_size_mb * 1024 * 1024
        total_size = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                # Skip directories and macOS metadata
                if member.endswith("/") or "__MACOSX" in member or member.startswith("."):
                    continue

                # Check file count limit
                if count >= max_files:
                    logger.warning("ZIP contains more than %d files, truncating", max_files)
                    break

                # Check total size
                info = zf.getinfo(member)
                total_size += info.file_size
                if total_size > max_size:
                    logger.warning("ZIP exceeds max size of %d MB", self.settings.max_upload_size_mb)
                    break

                # Validate path (prevent path traversal)
                try:
                    target_path = sanitize_path(member, extract_to)
                except ValueError as e:
                    logger.warning("Skipping unsafe ZIP entry %s: %s", member, e)
                    continue

                # Extract using the validated target path
                # Use extract with member name (Python's zipfile handles traversal in 3.4+)
                # but verify the resulting path is within extract_to
                try:
                    zf.extract(member, extract_to)
                    # Verify the extracted file is actually within extract_to
                    extracted_path = os.path.join(extract_to, member)
                    abs_extracted = os.path.abspath(os.path.normpath(extracted_path))
                    abs_extract_to = os.path.abspath(os.path.normpath(extract_to))
                    # Ensure extract_to ends with separator for proper prefix check
                    if not abs_extract_to.endswith(os.sep):
                        abs_extract_to_prefix = abs_extract_to + os.sep
                    else:
                        abs_extract_to_prefix = abs_extract_to
                    if abs_extracted == abs_extract_to or abs_extracted.startswith(abs_extract_to_prefix):
                        extracted_files.append(target_path)
                        count += 1
                    else:
                        logger.warning("Skipping ZIP entry that escaped extraction dir: %s", member)
                        # Try to remove the escaped file
                        try:
                            os.remove(abs_extracted)
                        except OSError:
                            pass
                except Exception as e:
                    logger.warning("Failed to extract %s: %s", member, e)

        return count, extracted_files

    def _find_project_root(self, extract_dir: str) -> str:
        """
        Find the actual project root within extracted contents.

        If the ZIP contains a single top-level directory, return that.
        Otherwise return the extract directory itself.

        Args:
            extract_dir: Extraction directory path

        Returns:
            Path to the project root
        """
        entries = [
            e for e in os.listdir(extract_dir)
            if not e.startswith(".") and not e.startswith("__")
        ]

        if len(entries) == 1:
            single_path = os.path.join(extract_dir, entries[0])
            if os.path.isdir(single_path):
                return single_path

        return extract_dir

    def validate_zip(self, zip_path: str) -> Tuple[bool, str]:
        """
        Validate a ZIP file before extraction.

        Args:
            zip_path: Path to the ZIP file

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            if not os.path.exists(zip_path):
                return False, "File not found"

            if not zipfile.is_zipfile(zip_path):
                return False, "Not a valid ZIP file"

            with zipfile.ZipFile(zip_path, "r") as zf:
                # Check for potential zip bomb
                total_size = sum(info.file_size for info in zf.infolist())
                compressed_size = sum(info.compress_size for info in zf.infolist())

                if compressed_size > 0 and total_size / compressed_size > 100:
                    return False, "Potential ZIP bomb detected"

                if total_size > self.settings.max_upload_size_mb * 1024 * 1024:
                    return False, f"ZIP contents exceed {self.settings.max_upload_size_mb}MB"

                # Check member count
                file_count = sum(1 for m in zf.namelist() if not m.endswith("/"))
                if file_count > self.settings.max_files_per_scan:
                    return False, f"ZIP contains too many files (max {self.settings.max_files_per_scan})"

            return True, ""

        except zipfile.BadZipFile:
            return False, "Corrupted ZIP file"
        except Exception as e:
            return False, f"Validation error: {str(e)}"
