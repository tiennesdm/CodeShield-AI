"""
Configuration management for CodeShield AI.

Loads settings from environment variables with sensible defaults.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All settings have sensible defaults for local development.
    """

    # App
    app_name: str = "CodeShield AI"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    api_url: Optional[str] = None  # Public base URL of this API (for CI generators)

    # CORS
    cors_origins: List[str] = [
        "https://h27urx4uhwy76.kimi.page",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
    ]

    # Storage
    data_dir: Path = Field(default=Path("./data"))
    temp_dir: Path = Field(default=Path("./tmp"))
    max_upload_size_mb: int = 100

    # Scanning
    default_scan_timeout: int = 600  # seconds
    github_clone_timeout: int = 120  # seconds
    max_file_size_mb: int = 10
    max_files_per_scan: int = 5000

    # Paths to external tools (auto-detected if not set)
    semgrep_path: Optional[str] = None
    eslint_path: Optional[str] = None
    pylint_path: Optional[str] = None
    bandit_path: Optional[str] = None
    pmd_path: Optional[str] = None
    gitleaks_path: Optional[str] = None
    dependency_check_path: Optional[str] = None

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    class Config:
        """Pydantic settings configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def __init__(self, **kwargs):
        """Initialize settings and ensure directories exist."""
        super().__init__(**kwargs)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Get or create the global settings instance.

    Uses functools.lru_cache for thread-safe singleton caching.
    The settings are loaded once and cached for the lifetime of the application.
    """
    return Settings()
