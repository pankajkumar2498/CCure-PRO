"""
core/web/base_wrapper.py
────────────────────────────────────────────────────────────────────────────
Abstract base class for all external security tool wrappers.

Design:
  - All tools run via subprocess.run() with hard timeouts
  - Output is always JSON (tools configured with -json/-jsonl flags)
  - Temp files used for large outputs and cleaned up in finally blocks
  - Binary availability is checked once on first use (lazy)
  - Structured logging for every subprocess invocation

Usage:
    class NucleiWrapper(ToolWrapper):
        def __init__(self):
            super().__init__(binary_path="nuclei", timeout=7200)

        def run(self, target, **kwargs):
            args = [self.binary, "-u", target, "-jsonl", "-silent"]
            result = self._run_subprocess(args)
            return self._parse_jsonl(result.stdout)
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("ccure.web.wrapper")


class ToolNotAvailableError(RuntimeError):
    """Raised when a required external tool binary is not found."""
    pass


class ToolExecutionError(RuntimeError):
    """Raised when a tool subprocess fails with a non-zero exit code."""

    def __init__(self, message: str, exit_code: int, stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class ToolWrapper(ABC):
    """
    Abstract base class for external security tool integration.

    Subclasses must implement:
      - run(target, **kwargs) -> Dict

    Provides:
      - Binary path validation (lazy, cached)
      - Subprocess execution with timeout + OOM protection
      - JSONL / JSON output parsing
      - Temp file management
    """

    def __init__(self, binary_path: str, timeout: int = 300, name: str = ""):
        self.binary = binary_path
        self.timeout = timeout
        self.name = name or binary_path.split("/")[-1]
        self._binary_verified: Optional[bool] = None
        self._binary_version: Optional[str] = None

    # ── Binary Verification ───────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check if the tool binary exists and is executable. Cached."""
        if self._binary_verified is not None:
            return self._binary_verified

        binary_path = shutil.which(self.binary)
        if binary_path:
            self._binary_verified = True
            log.info(
                "%s binary found at: %s", self.name, binary_path
            )
        else:
            self._binary_verified = False
            log.warning(
                "%s binary NOT FOUND in PATH (expected: %s). "
                "Tool will be unavailable for scanning.",
                self.name, self.binary,
            )
        return self._binary_verified

    def require_available(self) -> None:
        """Raise ToolNotAvailableError if the binary is missing."""
        if not self.is_available():
            raise ToolNotAvailableError(
                f"{self.name} binary not found at '{self.binary}'. "
                f"Install it or set the correct path via environment variable."
            )

    def get_version(self) -> Optional[str]:
        """Get tool version string. Returns None if unavailable."""
        if self._binary_version:
            return self._binary_version
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                [self.binary, "-version"],
                capture_output=True, text=True, timeout=10,
            )
            self._binary_version = result.stdout.strip() or result.stderr.strip()
            return self._binary_version
        except Exception:
            return None

    # ── Subprocess Execution ──────────────────────────────────────────────────

    def _run_subprocess(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env_override: Optional[Dict[str, str]] = None,
        input_data: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a subprocess with timeout, error capture, and structured logging.

        Args:
            args: Command and arguments
            timeout: Override default timeout (seconds)
            cwd: Working directory
            env_override: Additional environment variables
            input_data: Data to pipe to stdin

        Returns:
            subprocess.CompletedProcess

        Raises:
            ToolExecutionError: On non-zero exit code
            subprocess.TimeoutExpired: If timeout exceeded
        """
        effective_timeout = timeout or self.timeout
        tool_name = self.name

        # Build environment
        env = dict(os.environ)
        if env_override:
            env.update(env_override)

        # Sanitize args for logging (don't log auth headers/passwords)
        safe_args = self._sanitize_args_for_log(args)
        log.info(
            "[%s] Starting: %s (timeout=%ds)",
            tool_name, " ".join(safe_args), effective_timeout,
        )

        t0 = time.monotonic()
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=cwd,
                env=env,
                input=input_data,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - t0
            log.error(
                "[%s] TIMEOUT after %.1fs (limit=%ds). Command: %s",
                tool_name, duration, effective_timeout, " ".join(safe_args),
            )
            raise
        except FileNotFoundError:
            raise ToolNotAvailableError(
                f"{tool_name} binary not found: {args[0]}"
            )

        duration = time.monotonic() - t0

        if result.returncode != 0:
            stderr_preview = (result.stderr or "")[:500]
            log.warning(
                "[%s] Exited with code %d after %.1fs. stderr: %s",
                tool_name, result.returncode, duration, stderr_preview,
            )
            # Some tools use non-zero codes for "findings found" — don't
            # always raise. Let subclasses decide via _check_exit_code.
            if not self._is_acceptable_exit_code(result.returncode):
                raise ToolExecutionError(
                    f"{tool_name} failed with exit code {result.returncode}",
                    exit_code=result.returncode,
                    stderr=result.stderr or "",
                )
        else:
            log.info(
                "[%s] Completed successfully in %.1fs (%d bytes stdout)",
                tool_name, duration, len(result.stdout or ""),
            )

        return result

    def _is_acceptable_exit_code(self, code: int) -> bool:
        """
        Override in subclasses for tools that use non-zero codes
        for non-error conditions (e.g., nuclei returns 1 when findings exist).
        """
        return code == 0

    # ── Output Parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_json(text: str) -> Dict:
        """Parse JSON output from a tool. Returns empty dict on failure."""
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError) as exc:
            log.debug("JSON parse failed: %s", exc)
            return {}

    @staticmethod
    def _parse_jsonl(text: str) -> List[Dict]:
        """Parse JSONL (one JSON object per line) output. Skips bad lines."""
        results: List[Dict] = []
        for line_num, line in enumerate(text.strip().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                log.debug("JSONL parse error on line %d: %s", line_num, line[:100])
        return results

    # ── Temp File Management ──────────────────────────────────────────────────

    @staticmethod
    def _create_temp_dir(prefix: str = "ccure_web_") -> str:
        """Create a temporary directory for tool output. Caller must clean up."""
        return tempfile.mkdtemp(prefix=prefix)

    @staticmethod
    def _create_temp_file(suffix: str = ".json", prefix: str = "ccure_") -> str:
        """Create a temporary file for tool output. Caller must clean up."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)
        return path

    @staticmethod
    def _cleanup_path(path: str) -> None:
        """Safely remove a temp file or directory."""
        try:
            p = Path(path)
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.is_file():
                p.unlink(missing_ok=True)
        except Exception as exc:
            log.debug("Cleanup failed for %s: %s", path, exc)

    # ── Logging Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _sanitize_args_for_log(args: List[str]) -> List[str]:
        """
        Redact sensitive arguments (auth headers, passwords) for safe logging.
        """
        sanitized: List[str] = []
        skip_next = False
        sensitive_flags = {"-H", "--header", "--cookie", "-u", "--user", "-p", "--password"}

        for i, arg in enumerate(args):
            if skip_next:
                sanitized.append("***REDACTED***")
                skip_next = False
                continue
            if arg in sensitive_flags:
                sanitized.append(arg)
                skip_next = True
            elif any(arg.startswith(f"{flag}=") for flag in sensitive_flags):
                key = arg.split("=", 1)[0]
                sanitized.append(f"{key}=***REDACTED***")
            else:
                sanitized.append(arg)
        return sanitized

    # ── Abstract Interface ────────────────────────────────────────────────────

    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict:
        """
        Execute the tool against a target.

        Args:
            target: URL or domain to scan

        Returns:
            Parsed results as a dictionary
        """
        ...
