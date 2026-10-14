"""Policy 3: Missing Storage Encryption (CKV_AWS_19).
Detects storage resources that do not enforce server-side encryption at rest.
Severity: HIGH
Gate behavior: REPORT_AND_RECOMMEND
"""

from typing import Dict, Any, List, Optional, Tuple
from .base import BaseSecurityPolicy
from ..models import Finding, FindingSeverity, GateAction, PolicyStatus


class MissingStorageEncryptionPolicy(BaseSecurityPolicy):
    """
    Enforces server-side encryption (SSE-S3 or SSE-KMS) on all S3 storage buckets.
    Unencrypted buckets violate ISO 27001, SOC2, HIPAA, and PCI-DSS compliance requirements.
    """

    @property
    def policy_id(self) -> str:
        return "CKV_AWS_19"

    @property
    def name(self) -> str:
        return "Missing Storage Server-Side Encryption (SSE)"

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    @property
    def target_resource_types(self) -> List[str]:
        return ["aws_s3_bucket"]

    @property
    def gate_action(self) -> GateAction:
        return GateAction.REPORT_AND_RECOMMEND

    @property
    def description(self) -> str:
        return (
            "Storage bucket data at rest is unencrypted. If storage media or bucket snapshots are accessed "
            "outside the authorized security boundary, data confidentiality will be compromised."
        )

    @property
    def remediation_recommendation(self) -> str:
        return (
            "Configure default server-side encryption using AES256 or AWS Key Management Service (KMS) "
            "via the 'server_side_encryption_configuration' block or standalone "
            "'aws_s3_bucket_server_side_encryption_configuration' resource."
        )

    def _find_line_numbers(self, raw_lines: List[str], resource_name: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        start_line = None
        end_line = None
        matched_lines = []
        in_resource = False
        bracket_count = 0

        for idx, line in enumerate(raw_lines, 1):
            if f'"{resource_name}"' in line or f"'{resource_name}'" in line:
                in_resource = True
                start_line = idx

            if in_resource:
                matched_lines.append(line)
                bracket_count += line.count("{") - line.count("}")
                if bracket_count == 0 and len(matched_lines) > 1:
                    end_line = idx
                    break

        if start_line and not end_line:
            end_line = min(start_line + 20, len(raw_lines))

        snippet = "".join(matched_lines) if matched_lines else None
        return start_line, end_line, snippet

    def evaluate(
        self,
        resource_type: str,
        resource_name: str,
        resource_body: Dict[str, Any],
        raw_lines: List[str],
        all_resources: Dict[str, Dict[str, Any]],
    ) -> Tuple[PolicyStatus, Optional[Finding], str]:
        if resource_type not in self.target_resource_types:
            return (
                PolicyStatus.NOT_APPLICABLE,
                None,
                f"Policy does not apply to resource type '{resource_type}'.",
            )

        resource_id = f"{resource_type}.{resource_name}"
        start_line, end_line, snippet = self._find_line_numbers(raw_lines, resource_name)

        # Check inline encryption block
        has_inline_encryption = "server_side_encryption_configuration" in resource_body

        # Check standalone encryption resource: aws_s3_bucket_server_side_encryption_configuration
        has_standalone_encryption = False
        sse_resources = all_resources.get("aws_s3_bucket_server_side_encryption_configuration", {})
        for sse_name, sse_body in sse_resources.items():
            bucket_ref = sse_body.get("bucket", "")
            # check if bucket_ref matches resource name or aws_s3_bucket.name.id
            if (
                resource_name in str(bucket_ref)
                or resource_body.get("bucket", "") in str(bucket_ref)
            ):
                has_standalone_encryption = True
                break

        if not has_inline_encryption and not has_standalone_encryption:
            remediation_code = (
                f'resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_encryption" {{\n'
                f'  bucket = aws_s3_bucket.{resource_name}.id\n\n'
                f'  rule {{\n'
                f'    apply_server_side_encryption_by_default {{\n'
                f'      sse_algorithm = "AES256"\n'
                f'    }}\n'
                f'  }}\n'
                f'}}'
            )

            finding = Finding(
                policy_id=self.policy_id,
                policy_name=self.name,
                severity=self.severity,
                resource_id=resource_id,
                resource_type=resource_type,
                file_path="main.tf",
                start_line=start_line,
                end_line=end_line,
                code_snippet=snippet,
                description=self.description,
                remediation=self.remediation_recommendation,
                scanner_result="FAILED",
                gate_action=self.gate_action,
                remediation_code=remediation_code,
            )
            return (
                PolicyStatus.FAILED,
                finding,
                f"Storage bucket '{resource_id}' does not have server-side encryption enabled.",
            )

        return (
            PolicyStatus.PASSED,
            None,
            f"Storage bucket '{resource_id}' enforces server-side encryption.",
        )
