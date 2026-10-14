"""Tests for InfraShield Security Policies."""

import pytest
from infrashield.backend.policies.ssh_exposure import PublicSSHExposurePolicy
from infrashield.backend.policies.storage_public import PublicCloudStoragePolicy
from infrashield.backend.policies.storage_encryption import MissingStorageEncryptionPolicy
from infrashield.backend.policies.engine import PolicyEngine
from infrashield.backend.models import FindingSeverity, PolicyStatus, ThreatNodeState


def test_ssh_exposure_detects_public_ingress():
    policy = PublicSSHExposurePolicy()
    body = {
        "ingress": [
            {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"],
            }
        ]
    }
    status, finding, details = policy.evaluate("aws_security_group", "web_sg", body, [], {})
    assert status == PolicyStatus.FAILED
    assert finding is not None
    assert finding.policy_id == "CKV_AWS_24"
    assert finding.severity == FindingSeverity.CRITICAL


def test_ssh_exposure_passes_restricted_cidr():
    policy = PublicSSHExposurePolicy()
    body = {
        "ingress": [
            {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["203.0.113.50/32"], # Example admin CIDR
            }
        ]
    }
    status, finding, details = policy.evaluate("aws_security_group", "web_sg", body, [], {})
    assert status == PolicyStatus.PASSED
    assert finding is None


def test_public_storage_detects_public_acl():
    policy = PublicCloudStoragePolicy()
    body = {"bucket": "demo-bucket", "acl": "public-read"}
    status, finding, details = policy.evaluate("aws_s3_bucket", "data_archive", body, [], {})
    assert status == PolicyStatus.FAILED
    assert finding is not None
    assert finding.policy_id == "CKV_AWS_20"
    assert finding.severity == FindingSeverity.HIGH


def test_public_storage_passes_private_acl():
    policy = PublicCloudStoragePolicy()
    body = {"bucket": "demo-bucket", "acl": "private"}
    status, finding, details = policy.evaluate("aws_s3_bucket", "data_archive", body, [], {})
    assert status == PolicyStatus.PASSED
    assert finding is None


def test_missing_storage_encryption_detects_unencrypted_bucket():
    policy = MissingStorageEncryptionPolicy()
    body = {"bucket": "demo-bucket"}
    status, finding, details = policy.evaluate("aws_s3_bucket", "data_archive", body, [], {})
    assert status == PolicyStatus.FAILED
    assert finding is not None
    assert finding.policy_id == "CKV_AWS_19"
    assert finding.severity == FindingSeverity.HIGH


def test_policy_engine_not_applicable_distinction():
    """Verify that absent resource types return NOT_APPLICABLE and do not falsely claim passed."""
    engine = PolicyEngine()
    # Code with ONLY an S3 bucket (no security group)
    code = """
    resource "aws_s3_bucket" "test" {
      bucket = "my-test-bucket"
      acl    = "private"
      server_side_encryption_configuration {
        rule {
          apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
          }
        }
      }
    }
    """
    findings, evaluations, nodes = engine.evaluate_configuration(code)
    ssh_eval = next(e for e in evaluations if e.policy_id == "CKV_AWS_24")
    assert ssh_eval.status == PolicyStatus.NOT_APPLICABLE
