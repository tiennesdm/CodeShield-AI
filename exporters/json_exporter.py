"""
JSON Exporter for CodeShield AI.

Exports full scan results as structured JSON with all metadata,
vulnerabilities, and statistics.
"""

import json
from typing import Any, Dict

from models.vulnerability import ScanResult
from utils.logger import get_logger

logger = get_logger(__name__)


class JSONExporter:
    """
    Export scan results to JSON format.

    Provides a complete, structured JSON representation of scan results
    suitable for API responses, data pipelines, and third-party integrations.
    """

    def export(self, scan_result: ScanResult) -> str:
        """
        Export a ScanResult to JSON string.

        Args:
            scan_result: The scan result to export

        Returns:
            JSON string with full scan details
        """
        logger.info("Generating JSON export for scan %s", scan_result.scan_id)

        data = self._build_export_dict(scan_result)
        return json.dumps(data, indent=2, default=str)

    def _build_export_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build the export dictionary from a ScanResult."""
        vulnerabilities = []
        for vuln in scan_result.vulnerabilities:
            vuln_dict = vuln.model_dump()
            # Ensure datetime is serialized
            if hasattr(vuln, "created_at") and vuln.created_at:
                vuln_dict["created_at"] = vuln.created_at.isoformat()
            vulnerabilities.append(vuln_dict)

        return {
            "export_metadata": {
                "version": "1.0.0",
                "format": "json",
                "exported_at": datetime.now().isoformat(),
                "tool": "CodeShield AI",
                "tool_version": "1.0.0",
            },
            "scan": {
                "scan_id": scan_result.scan_id,
                "name": scan_result.name,
                "source_type": scan_result.source_type,
                "status": scan_result.status,
                "progress": scan_result.progress,
                "start_time": scan_result.start_time.isoformat() if scan_result.start_time else None,
                "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
                "scan_duration_seconds": scan_result.scan_duration,
                "languages": scan_result.languages,
                "total_files": scan_result.total_files,
                "total_lines": scan_result.total_lines,
                "tools_used": scan_result.tools_used,
                "risk_score": scan_result.risk_score,
                "stats": scan_result.stats,
                "error_message": scan_result.error_message,
            },
            "vulnerabilities": vulnerabilities,
        }

    def export_to_file(self, scan_result: ScanResult, file_path: str) -> None:
        """
        Export scan result to a JSON file.

        Args:
            scan_result: The scan result to export
            file_path: Path to write the JSON file
        """
        json_content = self.export(scan_result)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_content)
        logger.info("JSON report written to %s", file_path)

    def export_summary(self, scan_result: ScanResult) -> str:
        """
        Export a summary-only JSON with key metrics.

        Args:
            scan_result: The scan result to summarize

        Returns:
            JSON string with summary information
        """
        summary = {
            "scan_id": scan_result.scan_id,
            "name": scan_result.name,
            "status": scan_result.status,
            "risk_score": scan_result.risk_score,
            "stats": scan_result.stats,
            "vulnerability_count": len(scan_result.vulnerabilities),
            "languages": scan_result.languages,
            "tools_used": scan_result.tools_used,
            "scan_duration_seconds": scan_result.scan_duration,
        }
        return json.dumps(summary, indent=2, default=str)


# Need datetime import
from datetime import datetime
