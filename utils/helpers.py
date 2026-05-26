"""
Utility helpers for CodeShield AI.

Provides file operations, path sanitization, temp directory management,
and other common utilities.
"""

import os
import re
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional, Set, Tuple

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)

# Allowed file extensions for scanning
ALLOWED_EXTENSIONS: Set[str] = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".rs",
    ".html",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".sh",
    ".sql",
    ".md",
    ".env",
    ".dockerfile",
    ".tf",
    ".cfg",
    ".ini",
    ".properties",
    ".gradle",
    ".sbt",
}

# Binary file extensions to skip
BINARY_EXTENSIONS: Set[str] = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".o",
    ".a",
    ".pyc",
    ".pyo",
}


def sanitize_path(file_path: str, base_dir: Optional[str] = None) -> str:
    """
    Sanitize a file path to prevent path traversal attacks.

    Args:
        file_path: The path to sanitize
        base_dir: Optional base directory to constrain the path

    Returns:
        Sanitized absolute path

    Raises:
        ValueError: If path traversal is detected
    """
    # Normalize the path - resolve . and .. components
    normalized = os.path.normpath(file_path)

    # Check for path traversal attempts after normalization
    # A normalized path containing .. means it escapes the root
    if normalized.startswith("..") or "/../" in normalized or "\\..\\" in normalized:
        raise ValueError(f"Path traversal detected: {file_path}")

    # If base_dir is provided, ensure the path is within it
    if base_dir:
        abs_base = os.path.abspath(os.path.realpath(base_dir))
        # Join and resolve the target path
        abs_path = os.path.abspath(os.path.join(abs_base, normalized))
        abs_path = os.path.realpath(abs_path)

        # Ensure base_dir ends with separator for proper prefix check
        if not abs_base.endswith(os.sep):
            abs_base_prefix = abs_base + os.sep
        else:
            abs_base_prefix = abs_base

        # Check if resolved path is within base_dir
        if abs_path != abs_base and not abs_path.startswith(abs_base_prefix):
            raise ValueError(f"Path escapes base directory: {file_path}")
        return abs_path

    return os.path.abspath(normalized)


@contextmanager
def get_temp_dir(prefix: str = "codeshield_") -> Generator[Path, None, None]:
    """
    Create a temporary directory that is automatically cleaned up.

    Args:
        prefix: Prefix for the temp directory name

    Yields:
        Path to the temporary directory
    """
    settings = get_settings()
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(settings.temp_dir)))
    try:
        logger.debug("Created temp directory: %s", temp_dir)
        yield temp_dir
    finally:
        cleanup_temp_dir(temp_dir)


def cleanup_temp_dir(temp_dir: Path) -> None:
    """
    Safely remove a temporary directory.

    Args:
        temp_dir: Path to the directory to remove
    """
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug("Cleaned up temp directory: %s", temp_dir)
    except Exception as e:
        logger.warning("Failed to cleanup temp directory %s: %s", temp_dir, e)


def count_lines(file_path: str) -> int:
    """
    Count the number of lines in a text file.

    Args:
        file_path: Path to the file

    Returns:
        Number of lines, or 0 if file cannot be read
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception as e:
        logger.debug("Could not count lines in %s: %s", file_path, e)
        return 0


def get_file_extension(file_path: str) -> str:
    """Get the lowercase file extension."""
    return Path(file_path).suffix.lower()


def is_binary_file(file_path: str) -> bool:
    """
    Check if a file is binary based on extension.

    Args:
        file_path: Path to the file

    Returns:
        True if the file appears to be binary
    """
    ext = get_file_extension(file_path)
    return ext in BINARY_EXTENSIONS


def is_scannable_file(file_path: str) -> bool:
    """
    Check if a file should be scanned based on extension.

    Args:
        file_path: Path to the file

    Returns:
        True if the file should be scanned
    """
    ext = get_file_extension(file_path)
    if ext in BINARY_EXTENSIONS:
        return False
    # Allow files without extension (e.g., Dockerfile, Makefile)
    if ext == "":
        basename = Path(file_path).name.lower()
        return basename in {"dockerfile", "makefile", "gemfile", "rakefile"}
    return True


def find_files(
    directory: str,
    extensions: Optional[Set[str]] = None,
    max_size_mb: Optional[int] = None,
) -> List[str]:
    """
    Find all scannable files in a directory.

    Args:
        directory: Root directory to search
        extensions: Optional set of extensions to filter by
        max_size_mb: Maximum file size in MB

    Returns:
        List of file paths
    """
    files: List[str] = []
    max_size_bytes = (max_size_mb or get_settings().max_file_size_mb) * 1024 * 1024

    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(root, filename)

            # Skip binary files
            if is_binary_file(file_path):
                continue

            # Check extension filter
            if extensions:
                ext = get_file_extension(file_path)
                if ext not in extensions:
                    continue

            # Check file size
            try:
                if os.path.getsize(file_path) > max_size_bytes:
                    logger.debug("Skipping oversized file: %s", file_path)
                    continue
            except OSError:
                continue

            # Check if scannable
            if is_scannable_file(file_path):
                files.append(file_path)

    return files


def extract_zip(zip_path: str, extract_to: str) -> Tuple[int, List[str]]:
    """
    Safely extract a ZIP file.

    Args:
        zip_path: Path to the ZIP file
        extract_to: Directory to extract to

    Returns:
        Tuple of (number of files extracted, list of extracted file paths)

    Raises:
        ValueError: If ZIP contains path traversal
        zipfile.BadZipFile: If file is not a valid ZIP
    """
    extracted_files: List[str] = []
    count = 0

    # Resolve and validate extraction directory
    abs_extract_to = os.path.abspath(os.path.realpath(extract_to))
    if not abs_extract_to.endswith(os.sep):
        abs_extract_to_prefix = abs_extract_to + os.sep
    else:
        abs_extract_to_prefix = abs_extract_to

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            # Skip directories
            if member.endswith("/"):
                continue

            # Skip macOS metadata and hidden files
            if "__MACOSX" in member or member.startswith("."):
                continue

            # Check for path traversal in ZIP member name
            normalized_member = os.path.normpath(member)
            if normalized_member.startswith("..") or "/../" in normalized_member:
                logger.warning("Skipping malicious ZIP entry with traversal: %s", member)
                continue

            # Compute the target path and verify it's within extract_to
            target_path = os.path.join(extract_to, normalized_member)
            abs_target = os.path.abspath(os.path.realpath(target_path))

            if abs_target != abs_extract_to and not abs_target.startswith(abs_extract_to_prefix):
                logger.warning("Skipping malicious ZIP entry that escapes extract dir: %s", member)
                continue

            # Skip binary and oversized files during extraction
            try:
                zf.extract(member, extract_to)
                extracted_files.append(abs_target)
                count += 1
            except Exception as e:
                logger.warning("Failed to extract %s: %s", member, e)

    return count, extracted_files


def read_file_snippet(file_path: str, line_number: int, context: int = 3) -> Optional[str]:
    """
    Read a snippet of code around a specific line.

    Args:
        file_path: Path to the file
        line_number: The target line (1-indexed)
        context: Number of lines of context on each side

    Returns:
        Code snippet string or None if file cannot be read
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:4d}: {lines[i].rstrip()}")

        return "\n".join(snippet_lines)
    except Exception as e:
        logger.debug("Could not read snippet from %s: %s", file_path, e)
        return None


def truncate_string(s: str, max_length: int = 500) -> str:
    """Truncate a string to max_length characters."""
    if len(s) <= max_length:
        return s
    return s[:max_length] + "... [truncated]"
