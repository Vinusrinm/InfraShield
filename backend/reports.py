"""Security Passport and Report Generation for InfraShield.
Creates downloadable JSON security audit reports and manages configuration timelines.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from .models import ScanResponse, GateStatus


class SecurityReportGenerator:
    """Generates structured machine-readable security reports and passport timelines."""

    @staticmethod
    def generate_report(scan: ScanResponse, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Creates a comprehensive JSON audit report.
        Clearly labeled as an Infrastructure Security Evaluation Report, not an unverified certificate.
        """
        report_data = {
            "report_metadata": {
                "system": "InfraShield — The Living Security Blueprint",
                "version": "1.0.0-hackathon-release",
                "report_id": f"REP-{scan.scan_id.upper()}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "document_type": "IaC Security Policy Audit Report",
                "verification_status": "VERIFIED_EVALUATION" if scan.scanner_status == "completed" else "UNVERIFIED_INCOMPLETE",
                "session_id": session_id or "default-session",
            },
            "target_configuration": {
                "filename": scan.filename,
                "evaluated_at": scan.timestamp,
                "scanner_engine": scan.scanner_engine,
                "scanner_status": scan.scanner_status,
            },
            "validation_gate_decision": {
                "decision": scan.gate_status.value,
                "reason": scan.gate_reason,
                "deployment_blocked": scan.gate_status == GateStatus.BLOCKED,
                "deployment_approved": scan.gate_status == GateStatus.PASSED,
            },
            "summary_metrics": {
                "compliance_score_percentage": scan.compliance_percentage,
                "critical_violations": scan.critical_count,
                "high_violations": scan.high_count,
                "medium_violations": scan.medium_count,
                "low_violations": scan.low_count,
                "policies_passed": scan.passed_count,
                "policies_not_applicable": scan.not_applicable_count,
                "total_findings": len(scan.findings),
            },
            "evaluated_policies": [
                {
                    "policy_id": p.policy_id,
                    "policy_name": p.policy_name,
                    "severity": p.severity.value,
                    "status": p.status.value,
                    "resource_id": p.resource_id,
                    "details": p.details,
                    "remediation_recommendation": p.recommendation,
                }
                for p in scan.policy_evaluations
            ],
            "findings_detail": [
                {
                    "policy_id": f.policy_id,
                    "policy_name": f.policy_name,
                    "severity": f.severity.value,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "file_path": f.file_path,
                    "line_range": f"{f.start_line}-{f.end_line}" if f.start_line else "unknown",
                    "description": f.description,
                    "remediation": f.remediation,
                    "scanner_result": f.scanner_result,
                    "gate_action": f.gate_action.value,
                }
                for f in scan.findings
            ],
            "security_passport_timeline": [
                {
                    "stage": "Configuration Uploaded",
                    "timestamp": scan.timestamp,
                    "status": "COMPLETED",
                    "detail": f"File '{scan.filename}' loaded into isolated scanning environment.",
                },
                {
                    "stage": "Security Scan Executed",
                    "timestamp": scan.timestamp,
                    "status": "COMPLETED",
                    "detail": f"Evaluated using {scan.scanner_engine}.",
                },
                {
                    "stage": "Violations Identified",
                    "timestamp": scan.timestamp,
                    "status": "FLAGGED" if scan.findings else "CLEAN",
                    "detail": f"{len(scan.findings)} finding(s) discovered ({scan.critical_count} critical).",
                },
                {
                    "stage": "Gate Decision Recorded",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": scan.gate_status.value,
                    "detail": scan.gate_reason,
                },
            ],
        }
        return report_data
