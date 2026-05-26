"""
Generic tool runner with timeout and error handling.

Executes external security scanning tools via subprocess with configurable
timeouts, error handling, and output capture.
"""

import asyncio
import json
import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class ToolRunner:
    """
    Generic runner for external security scanning tools.

    Handles subprocess execution with timeouts, error handling,
    and output parsing.
    """

    def __init__(self) -> None:
        """Initialize the tool runner."""
        self.settings = get_settings()
        self._tool_cache: Dict[str, Optional[str]] = {}

    async def run_tool(
        self,
        tool_name: str,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        capture_json: bool = True,
    ) -> Tuple[bool, str, Optional[Any]]:
        """
        Run an external tool asynchronously.

        Args:
            tool_name: Human-readable tool name for logging
            command: Command and arguments as a list
            cwd: Working directory
            timeout: Timeout in seconds
            env: Additional environment variables
            capture_json: Whether to parse output as JSON

        Returns:
            Tuple of (success, raw_output, parsed_output)
        """
        timeout = timeout or self.settings.default_scan_timeout

        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        logger.info(
            "Running %s: %s (timeout=%ds)", tool_name, " ".join(command), timeout
        )

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=run_env,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            raw_output = stdout.decode("utf-8", errors="ignore")
            error_output = stderr.decode("utf-8", errors="ignore")

            # Many tools exit with non-zero even when they found issues
            # We consider it a success if we got output
            if raw_output:
                parsed = None
                if capture_json:
                    try:
                        parsed = json.loads(raw_output)
                    except json.JSONDecodeError:
                        logger.debug(
                            "[%s] Output is not valid JSON", tool_name
                        )

                logger.info(
                    "[%s] Completed successfully (exit code: %d)",
                    tool_name,
                    process.returncode or 0,
                )
                return True, raw_output, parsed

            if error_output:
                logger.warning("[%s] No stdout, stderr: %s", tool_name, error_output[:500])

            # Tool ran but produced no output
            return True, "", None

        except asyncio.TimeoutError:
            logger.error("[%s] Timed out after %d seconds", tool_name, timeout)
            # Kill the process on timeout to prevent zombies
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                    await asyncio.wait_for(process.wait(), timeout=5)
                except Exception:
                    pass
            return False, f"Timeout after {timeout} seconds", None
        except FileNotFoundError:
            logger.warning("[%s] Tool not found: %s", tool_name, command[0])
            return False, f"Tool not found: {command[0]}", None
        except Exception as e:
            # Kill the process on any error
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            logger.error("[%s] Error: %s", tool_name, str(e))
            return False, str(e), None

    def check_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and available.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if the tool is available
        """
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name] is not None

        path = shutil.which(tool_name)
        self._tool_cache[tool_name] = path
        return path is not None

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Get the full path to a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Full path or None if not found
        """
        if tool_name not in self._tool_cache:
            self._tool_cache[tool_name] = shutil.which(tool_name)
        return self._tool_cache[tool_name]

    async def run_with_json_output(
        self,
        tool_name: str,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Run a tool and parse JSON output.

        Args:
            tool_name: Tool name for logging
            command: Command to execute
            cwd: Working directory
            timeout: Timeout

        Returns:
            Parsed JSON output or None
        """
        success, _, parsed = await self.run_tool(
            tool_name, command, cwd, timeout, capture_json=True
        )
        if success and isinstance(parsed, dict):
            return parsed
        return None

    async def run_with_text_output(
        self,
        tool_name: str,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> str:
        """
        Run a tool and return text output.

        Args:
            tool_name: Tool name for logging
            command: Command to execute
            cwd: Working directory
            timeout: Timeout

        Returns:
            Raw text output
        """
        success, output, _ = await self.run_tool(
            tool_name, command, cwd, timeout, capture_json=False
        )
        return output if success else ""
