"""Tests for IaC Scanner integration and sample handling."""

import os
import pytest
from infrashield.backend.scanner import IaCScanner
from infrashield.backend.models import GateStatus, ThreatNodeState


def test_scanner_with_vulnerable_sample():
    scanner = IaCScanner()
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "samples", "vulnerable.tf"
    )
    with open(sample_path, "r", encoding="utf-8") as f:
        code = f.read()

    response = scanner.scan_terraform(code=code, filename="vulnerable.tf")
    assert response.scanner_status == "completed"
    assert response.gate_status == GateStatus.BLOCKED
    assert response.critical_count >= 1
    assert any(f.policy_id == "CKV_AWS_24" for f in response.findings)

    # Check that threat map nodes reflect critical vulnerability
    sg_node = next(n for n in response.threat_nodes if n.id == "security_group")
    assert sg_node.state == ThreatNodeState.RED
    assert sg_node.line_number is not None


def test_scanner_with_secure_sample():
    scanner = IaCScanner()
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "samples", "secure.tf"
    )
    with open(sample_path, "r", encoding="utf-8") as f:
        code = f.read()

    response = scanner.scan_terraform(code=code, filename="secure.tf")
    assert response.scanner_status == "completed"
    assert response.gate_status == GateStatus.PASSED
    assert response.critical_count == 0

    # Check that security group node is green
    sg_node = next(n for n in response.threat_nodes if n.id == "security_group")
    assert sg_node.state == ThreatNodeState.GREEN


def test_scanner_rejects_empty_code():
    scanner = IaCScanner()
    response = scanner.scan_terraform(code="")
    assert response.scanner_status == "incomplete"
    assert response.gate_status == GateStatus.SCAN_INCOMPLETE
