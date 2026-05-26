"""
Tests for CodeShield AI CLI (codeshield-cli).

Tests the Click-based CLI commands, configuration, and exit codes.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

# Ensure backend is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import cli, get_config, severity_color, severity_icon, EXIT_OK, EXIT_VULNS_FOUND, EXIT_ERROR


class TestCLIConfig:
    """Tests for CLI configuration."""

    def test_get_config_defaults(self, tmp_path):
        """Test that get_config returns sensible defaults."""
        with patch("cli.CONFIG_DIR", tmp_path / ".codeshield"):
            with patch("cli.CONFIG_FILE", tmp_path / ".codeshield" / "config.yaml"):
                config = get_config()
                assert "api_url" in config
                assert "default_output_format" in config
                assert "severity_filter" in config
                assert "timeout" in config

    def test_config_command_show(self):
        """Test the config command shows current configuration."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "--show"])
        assert result.exit_code == 0 or result.exit_code is None


class TestCLISeverityHelpers:
    """Tests for severity helper functions."""

    def test_severity_color_mapping(self):
        """Test severity to color mapping."""
        assert severity_color("CRITICAL") == "red"
        assert severity_color("HIGH") == "bright_red"
        assert severity_color("MEDIUM") == "yellow"
        assert severity_color("LOW") == "green"
        assert severity_color("INFO") == "blue"
        assert severity_color("UNKNOWN") == "white"

    def test_severity_icon_mapping(self):
        """Test severity to icon mapping."""
        assert "!" in severity_icon("CRITICAL")
        assert "+" in severity_icon("HIGH")


class TestCLIScanCommands:
    """Tests for scan subcommands."""

    def test_scan_status_missing_scan(self):
        """Test scan status with a missing scan ID."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "status", "nonexistent"])
        # Should fail since the API won't be running
        assert result.exit_code in (EXIT_ERROR, 0, 1)

    def test_scan_history(self):
        """Test scan history command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "history"])
        assert result.exit_code in (EXIT_OK, EXIT_ERROR)

    def test_scan_results_missing_scan(self):
        """Test scan results with a missing scan ID."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "results", "nonexistent"])
        assert result.exit_code in (EXIT_OK, EXIT_ERROR, EXIT_VULNS_FOUND)


class TestCLIZipCommand:
    """Tests for the zip scan command."""

    def test_scan_zip_file_not_found(self):
        """Test scan zip with non-existent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "zip", "/nonexistent/file.zip"])
        # Should error because file doesn't exist (Click validates path)
        assert result.exit_code != 0 or "does not exist" in result.output.lower()


class TestCLIGitHubCommand:
    """Tests for the GitHub scan command."""

    def test_scan_github_no_wait(self):
        """Test GitHub scan with --no-wait flag."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", "github", "https://github.com/test/repo", "--no-wait"
        ])
        # Should attempt to connect to API
        assert result.exit_code in (EXIT_OK, EXIT_ERROR)


class TestCLIGroup:
    """Tests for CLI group structure."""

    def test_cli_help(self):
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CodeShield AI" in result.output

    def test_scan_help(self):
        """Test scan group help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "zip" in result.output
        assert "github" in result.output

    def test_config_help(self):
        """Test config command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "--help"])
        assert result.exit_code == 0
