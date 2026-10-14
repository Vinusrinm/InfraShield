"""Integration tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from infrashield.backend.main import app

client = TestClient(app)


def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert "registered_policies_count" in data


def test_api_policies():
    res = client.get("/api/policies")
    assert res.status_code == 200
    data = res.json()
    assert len(data["policies"]) >= 3
    policy_ids = [p["policy_id"] for p in data["policies"]]
    assert "CKV_AWS_24" in policy_ids
    assert "CKV_AWS_20" in policy_ids
    assert "CKV_AWS_19" in policy_ids


def test_api_scan_vulnerable():
    code = """
    resource "aws_security_group" "web_sg" {
      name = "demo-sg"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    """
    res = client.post("/api/scan", json={"code": code, "filename": "test.tf"})
    assert res.status_code == 200
    data = res.json()
    assert data["gate_status"] == "BLOCKED"
    assert data["critical_count"] == 1
    assert len(data["findings"]) == 1


def test_api_scan_secure():
    code = """
    resource "aws_security_group" "web_sg" {
      name = "demo-sg"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["203.0.113.50/32"]
      }
    }
    """
    res = client.post("/api/scan", json={"code": code, "filename": "test.tf"})
    assert res.status_code == 200
    data = res.json()
    assert data["gate_status"] == "PASSED"
    assert data["critical_count"] == 0


def test_api_samples():
    res = client.get("/api/samples/vulnerable")
    assert res.status_code == 200
    assert "0.0.0.0/0" in res.json()["code"]


def test_api_repair_propose():
    payload = {
        "original_code": 'ingress { from_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
        "policy_id": "CKV_AWS_24",
        "resource_id": "aws_security_group.web_sg",
    }
    res = client.post("/api/repair/propose", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "203.0.113.50/32" in data["repaired_snippet"]
    assert len(data["diff_lines"]) > 0


def test_api_clear_history():
    res = client.delete("/api/history")
    assert res.status_code == 200
    assert res.json()["status"] == "cleared"
    assert res.json()["history"] == []
