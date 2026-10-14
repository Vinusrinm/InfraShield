"""Tests for Security Validation Gate Enforcement."""

import pytest
from infrashield.backend.gate import SecurityValidationGate
from infrashield.backend.models import (
    Finding,
    FindingSeverity,
    GateStatus,
    PolicyEvaluationResult,
    PolicyStatus,
)


def test_gate_blocks_on_critical_violation():
    findings = [
        Finding(
            policy_id="CKV_AWS_24",
            policy_name="Public SSH Exposure",
            severity=FindingSeverity.CRITICAL,
            resource_id="aws_security_group.web_sg",
            resource_type="aws_security_group",
            description="Port 22 open to 0.0.0.0/0",
            remediation="Restrict CIDR",
        )
    ]
    evaluations = [
        PolicyEvaluationResult(
            policy_id="CKV_AWS_24",
            policy_name="Public SSH Exposure",
            severity=FindingSeverity.CRITICAL,
            status=PolicyStatus.FAILED,
            details="Violated",
        )
    ]

    response = SecurityValidationGate.evaluate(findings, "completed", evaluations)
    assert response.gate_status == GateStatus.BLOCKED
    assert response.approval_allowed is False
    assert len(response.blocking_violations) == 1
    assert "BLOCKED" in response.gate_reason


def test_gate_passes_when_zero_critical():
    findings = [
        Finding(
            policy_id="CKV_AWS_20",
            policy_name="Public S3 Bucket",
            severity=FindingSeverity.HIGH, # High, but not critical
            resource_id="aws_s3_bucket.data_archive",
            resource_type="aws_s3_bucket",
            description="Public read ACL",
            remediation="Change to private",
        )
    ]
    evaluations = [
        PolicyEvaluationResult(
            policy_id="CKV_AWS_24",
            policy_name="Public SSH Exposure",
            severity=FindingSeverity.CRITICAL,
            status=PolicyStatus.PASSED,
            details="Passed",
        )
    ]

    response = SecurityValidationGate.evaluate(findings, "completed", evaluations)
    assert response.gate_status == GateStatus.PASSED
    assert response.approval_allowed is True
    assert response.remaining_high_count == 1


def test_gate_incomplete_on_scanner_failure():
    response = SecurityValidationGate.evaluate([], "incomplete", [])
    assert response.gate_status == GateStatus.SCAN_INCOMPLETE
    assert response.approval_allowed is False
