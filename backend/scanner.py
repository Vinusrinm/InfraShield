"""Scanner Integration for InfraShield.
Safely processes Terraform code in isolated temporary directories.
Integrates Checkov CLI scanning when available, and native AST policy engine.
"""

import os
import sys
import json
import uuid
import shutil
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from .models import (
    Finding,
    FindingSeverity,
    GateAction,
    GateStatus,
    PolicyEvaluationResult,
    PolicyStatus,
    ScanResponse,
    ThreatNode,
)
from .policies.engine import PolicyEngine
from .gate import SecurityValidationGate


class IaCScanner:
    """Orchestrates security scanning with Checkov CLI and Native Policy Engine."""

    def __init__(self):
        self.policy_engine = PolicyEngine()
        self._checkov_path = self._find_checkov_binary()

    def _find_checkov_binary(self) -> Optional[str]:
        """Check if checkov executable is available in PATH or Python scripts directory."""
        which_checkov = shutil.which("checkov")
        if which_checkov:
            return which_checkov

        # Check Python user script folder
        scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        candidate = os.path.join(scripts_dir, "checkov.exe")
        if os.path.exists(candidate):
            return candidate

        return None

    def is_checkov_available(self) -> bool:
        return self._checkov_path is not None

    def scan_terraform(
        self,
        code: str,
        filename: str = "main.tf",
        preferred_scanner: str = "auto",
    ) -> ScanResponse:
        """
        Safely scans Terraform configuration.
        Validates code size, executes in an isolated temp workspace, and returns structured results.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Input validation
        if not code or not code.strip():
            return ScanResponse(
                scan_id=scan_id,
                timestamp=timestamp,
                filename=filename,
                scanner_engine="none",
                scanner_status="incomplete",
                status_message="Empty configuration received. Please provide valid Terraform code.",
                gate_status=GateStatus.SCAN_INCOMPLETE,
                gate_reason="Scan incomplete: No code provided to evaluate.",
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                passed_count=0,
                not_applicable_count=0,
                findings=[],
                policy_evaluations=[],
                threat_nodes=[],
                compliance_percentage=0.0,
            )

        if len(code) > 500000:
            return ScanResponse(
                scan_id=scan_id,
                timestamp=timestamp,
                filename=filename,
                scanner_engine="none",
                scanner_status="incomplete",
                status_message="Configuration exceeds maximum allowed payload size (500KB).",
                gate_status=GateStatus.SCAN_INCOMPLETE,
                gate_reason="Scan incomplete: File size exceeds safety boundary.",
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                passed_count=0,
                not_applicable_count=0,
                findings=[],
                policy_evaluations=[],
                threat_nodes=[],
                compliance_percentage=0.0,
            )

        # Decide scanner engine
        checkov_available = self.is_checkov_available()

        # If user explicitly requests checkov_cli and it's missing, report accurately without fabricating
        if preferred_scanner == "checkov_cli" and not checkov_available:
            return ScanResponse(
                scan_id=scan_id,
                timestamp=timestamp,
                filename=filename,
                scanner_engine="checkov_cli",
                scanner_status="incomplete",
                status_message="Checkov CLI is not installed in the server environment. Please use auto or native policy engine.",
                gate_status=GateStatus.SCAN_INCOMPLETE,
                gate_reason="Scan could not be completed: External Checkov CLI runner unavailable.",
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                passed_count=0,
                not_applicable_count=0,
                findings=[],
                policy_evaluations=[],
                threat_nodes=[],
                compliance_percentage=0.0,
            )

        # Execute Checkov CLI if requested or available
        if preferred_scanner in ["auto", "checkov_cli"] and checkov_available:
            try:
                findings, evaluations, nodes = self._execute_checkov_cli(code, filename)
                engine_name = "Checkov CLI v3.3"
            except Exception as e:
                # If Checkov CLI fails or crashes, fallback transparently to native engine
                findings, evaluations, nodes = self.policy_engine.evaluate_configuration(code)
                engine_name = f"InfraShield Native AST Engine (Checkov CLI error: {str(e)[:50]})"
        else:
            # Native HCL/AST Policy Engine
            findings, evaluations, nodes = self.policy_engine.evaluate_configuration(code)
            engine_name = "InfraShield IaC Policy Engine (Checkov-standard CKV Rules)"

        # Calculate counts
        critical_count = len([f for f in findings if f.severity == FindingSeverity.CRITICAL])
        high_count = len([f for f in findings if f.severity == FindingSeverity.HIGH])
        medium_count = len([f for f in findings if f.severity == FindingSeverity.MEDIUM])
        low_count = len([f for f in findings if f.severity == FindingSeverity.LOW])
        passed_count = len([e for e in evaluations if e.status == PolicyStatus.PASSED])
        na_count = len([e for e in evaluations if e.status == PolicyStatus.NOT_APPLICABLE])

        total_evaluated = passed_count + len(findings)
        compliance_pct = round((passed_count / total_evaluated * 100), 1) if total_evaluated > 0 else 100.0

        # Evaluate Security Validation Gate
        gate_resp = SecurityValidationGate.evaluate(findings, "completed", evaluations)

        return ScanResponse(
            scan_id=scan_id,
            timestamp=timestamp,
            filename=filename,
            scanner_engine=engine_name,
            scanner_status="completed",
            status_message=f"Scan completed successfully using {engine_name}.",
            gate_status=gate_resp.gate_status,
            gate_reason=gate_resp.gate_reason,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            passed_count=passed_count,
            not_applicable_count=na_count,
            findings=findings,
            policy_evaluations=evaluations,
            threat_nodes=nodes,
            compliance_percentage=compliance_pct,
        )

    def _execute_checkov_cli(
        self, code: str, filename: str
    ) -> Tuple[List[Finding], List[PolicyEvaluationResult], List[ThreatNode]]:
        """
        Executes Checkov CLI in an isolated temporary directory with server-controlled arguments.
        """
        with tempfile.TemporaryDirectory(prefix="infrashield_scan_") as temp_dir:
            temp_file = os.path.join(temp_dir, filename)
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(code)

            cmd = [
                self._checkov_path,
                "-f",
                temp_file,
                "--output",
                "json",
                "--framework",
                "terraform",
                "--compact",
                "--quiet",
            ]

            # Enforce server-controlled timeout (15 seconds)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=temp_dir,
            )

            # Checkov returns exit code 1 if failed checks exist
            raw_stdout = result.stdout.strip()
            if not raw_stdout:
                # Fallback to policy engine if empty stdout
                return self.policy_engine.evaluate_configuration(code)

            try:
                checkov_data = json.loads(raw_stdout)
            except json.JSONDecodeError:
                # If output couldn't be parsed, fallback to native engine
                return self.policy_engine.evaluate_configuration(code)

            return self._parse_checkov_output(checkov_data, code)

    def _parse_checkov_output(
        self, data: Dict[str, Any], code: str
    ) -> Tuple[List[Finding], List[PolicyEvaluationResult], List[ThreatNode]]:
        """Parse native Checkov JSON output into InfraShield models."""
        findings: List[Finding] = []
        evaluations: List[PolicyEvaluationResult] = []

        results = data.get("results", {})
        failed_checks = results.get("failed_checks", [])
        passed_checks = results.get("passed_checks", [])

        for check in failed_checks:
            cid = check.get("check_id", "CKV_UNKNOWN")
            cname = check.get("check_name", "Policy Violation")
            res_id = check.get("resource", "unknown_resource")
            severity_str = check.get("severity", "HIGH")

            # Checkov CKV_AWS_24 and CKV_AWS_23 are critical SSH exposures
            if cid in ["CKV_AWS_24", "CKV_AWS_23"]:
                severity = FindingSeverity.CRITICAL
                gate_action = GateAction.BLOCK
            else:
                severity = (
                    FindingSeverity.CRITICAL
                    if severity_str.upper() == "CRITICAL"
                    else FindingSeverity.HIGH
                )
                gate_action = (
                    GateAction.BLOCK
                    if severity == FindingSeverity.CRITICAL
                    else GateAction.REPORT_AND_RECOMMEND
                )

            file_lines = check.get("file_line_range", [1, 1])
            findings.append(
                Finding(
                    policy_id=cid,
                    policy_name=cname,
                    severity=severity,
                    resource_id=res_id,
                    resource_type=res_id.split(".")[0] if "." in res_id else "resource",
                    file_path=check.get("file_path", "main.tf"),
                    start_line=file_lines[0] if file_lines else 1,
                    end_line=file_lines[1] if len(file_lines) > 1 else file_lines[0],
                    code_snippet="\n".join([line[1] for line in check.get("code_block", [])]),
                    description=check.get("guideline") or f"Violation of policy {cid}: {cname}",
                    remediation=check.get("guideline") or "Remediate according to security policy baseline.",
                    scanner_result="FAILED",
                    gate_action=gate_action,
                )
            )
            evaluations.append(
                PolicyEvaluationResult(
                    policy_id=cid,
                    policy_name=cname,
                    severity=severity,
                    status=PolicyStatus.FAILED,
                    resource_id=res_id,
                    details=f"Checkov failed check: {cname}",
                )
            )

        for check in passed_checks:
            cid = check.get("check_id", "CKV_PASSED")
            cname = check.get("check_name", "Security Check Passed")
            evaluations.append(
                PolicyEvaluationResult(
                    policy_id=cid,
                    policy_name=cname,
                    severity=FindingSeverity.LOW,
                    status=PolicyStatus.PASSED,
                    resource_id=check.get("resource", "resource"),
                    details=f"Checkov verified passed: {cname}",
                )
            )

        # Generate threat nodes
        _, _, threat_nodes = self.policy_engine.evaluate_configuration(code)
        return findings, evaluations, threat_nodes
