"""
Language and framework detection for CodeShield AI.

Analyzes file extensions and content patterns to identify programming languages
and frameworks used in a codebase.
"""

import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.constants import FRAMEWORK_PATTERNS, SUPPORTED_LANGUAGES
from utils.helpers import get_file_extension
from utils.logger import get_logger

logger = get_logger(__name__)


class LanguageDetector:
    """
    Detects programming languages and frameworks in a codebase.

    Uses file extension analysis and content pattern matching.
    """

    def __init__(self) -> None:
        """Initialize the language detector."""
        self.language_extensions: Dict[str, Set[str]] = {
            lang: data["extensions"]
            for lang, data in SUPPORTED_LANGUAGES.items()
        }

    def detect_languages(
        self, root_dir: str, files: Optional[List[str]] = None
    ) -> List[str]:
        """
        Detect programming languages used in the codebase.

        Args:
            root_dir: Root directory of the codebase
            files: Optional pre-computed list of file paths

        Returns:
            List of detected language names (e.g., ["python", "javascript"])
        """
        if files is None:
            from utils.helpers import find_files

            files = find_files(root_dir)

        if not files:
            return []

        # Count files by extension
        ext_counts: Counter = Counter()
        for file_path in files:
            ext = get_file_extension(file_path)
            if ext:
                ext_counts[ext] += 1

        # Map extensions to languages
        detected: Set[str] = set()
        for lang, extensions in self.language_extensions.items():
            for ext in extensions:
                if ext and ext_counts.get(ext, 0) > 0:
                    detected.add(lang)
                    break

        # Special case: Dockerfile without extension
        for file_path in files:
            basename = Path(file_path).name.lower()
            if basename == "dockerfile" or basename.endswith(".dockerfile"):
                detected.add("dockerfile")
            if basename == "makefile":
                detected.add("makefile")
            if basename == "gemfile":
                detected.add("ruby")

        # Sort by file count (most used first)
        lang_counts: Dict[str, int] = {}
        for lang in detected:
            total = sum(
                ext_counts.get(ext, 0)
                for ext in self.language_extensions.get(lang, [])
            )
            lang_counts[lang] = total

        sorted_langs = sorted(detected, key=lambda l: lang_counts.get(l, 0), reverse=True)

        logger.info("Detected languages: %s", sorted_langs)
        return sorted_langs

    def detect_frameworks(self, root_dir: str) -> List[str]:
        """
        Detect frameworks used in the codebase.

        Args:
            root_dir: Root directory of the codebase

        Returns:
            List of detected framework names
        """
        detected: Set[str] = set()

        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if self._check_pattern(root_dir, pattern):
                    detected.add(framework)
                    break

        logger.info("Detected frameworks: %s", detected)
        return sorted(list(detected))

    def _check_pattern(self, root_dir: str, pattern: str) -> bool:
        """
        Check if a pattern exists in the codebase.

        Args:
            root_dir: Root directory
            pattern: Pattern to search for (file name or content marker)

        Returns:
            True if pattern is found
        """
        # Check if it's a file/directory path pattern
        if "/" in pattern or pattern.endswith(".json"):
            for dirpath, dirnames, filenames in os.walk(root_dir):
                # Check directories
                if any(pattern in d for d in dirnames):
                    return True
                # Check files
                if any(pattern == f or f.endswith(pattern) for f in filenames):
                    return True
                # Don't recurse too deep
                depth = dirpath.count(os.sep) - root_dir.count(os.sep)
                if depth > 3:
                    break
            return False

        # Check if it's a content marker (search in config files)
        config_files = ["package.json", "requirements.txt", "pom.xml", "Gemfile", "composer.json"]
        for dirpath, _, filenames in os.walk(root_dir):
            for config_file in config_files:
                if config_file in filenames:
                    file_path = os.path.join(dirpath, config_file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if pattern.lower() in content.lower():
                                return True
                    except Exception:
                        continue
            depth = dirpath.count(os.sep) - root_dir.count(os.sep)
            if depth > 2:
                break

        return False

    def get_primary_language(self, root_dir: str, files: Optional[List[str]] = None) -> Optional[str]:
        """
        Get the primary (most used) language.

        Args:
            root_dir: Root directory
            files: Optional file list

        Returns:
            Primary language name or None
        """
        languages = self.detect_languages(root_dir, files)
        return languages[0] if languages else None

    def get_language_stats(self, root_dir: str, files: Optional[List[str]] = None) -> Dict[str, int]:
        """
        Get file count statistics per language.

        Args:
            root_dir: Root directory
            files: Optional file list

        Returns:
            Dictionary mapping language to file count
        """
        if files is None:
            from utils.helpers import find_files

            files = find_files(root_dir)

        stats: Dict[str, int] = {}
        for file_path in files:
            ext = get_file_extension(file_path)
            for lang, extensions in self.language_extensions.items():
                if ext in extensions:
                    stats[lang] = stats.get(lang, 0) + 1
                    break

        return stats
