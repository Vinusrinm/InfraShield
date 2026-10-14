"""Policy 2: Public Cloud Storage (CKV_AWS_20 / CKV_AWS_53 / CKV_AWS_54).
Detects publicly accessible cloud storage resources.
Severity: HIGH
Gate behavior: REPORT_AND_RECOMMEND
"""

from typing import Dict, Any, List, Optional, Tuple
from .base import BaseSecurityPolicy
from ..models import Finding, FindingSeverity, GateAction, PolicyStatus


class PublicCloudStoragePolicy(BaseSecurityPolicy):
    """
    Enforces that Amazon S3 storage buckets do not expose public read/write permissions
    and maintain explicit public access block configurations.
    """

    @property
    def policy_id(self) -> str:
        return "CKV_AWS_20"

    @property
    def name(self) -> str:
        return "Public Cloud Storage Access (S3 Public Read/Write ACL)"

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    @property
    def target_resource_types(self) -> List[str]:
        return ["aws_s3_bucket", "aws_s3_bucket_acl"]

    @property
    def gate_action(self) -> GateAction:
        return GateAction.REPORT_AND_RECOMMEND

    @property
    def description(self) -> str:
        return (
            "Cloud storage bucket is configured with public access permissions ('public-read' or 'public-read-write'). "
            "Public buckets expose confidential files, logs, and database snapshots to unauthorized internet users, "
            "leading to severe data leaks and regulatory non-compliance."
        )

    @property
    def remediation_recommendation(self) -> str:
        return (
            "Set the S3 bucket 'acl' attribute to 'private', and declare an 'aws_s3_bucket_public_access_block' "
            "with 'block_public_acls = true' and 'block_public_policy = true' to enforce strict zero-public-access."
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

        acl = resource_body.get("acl", "private")
        public_acls = ["public-read", "public-read-write", "website"]

        if acl in public_acls:
            remediation_code = (
                f'resource "{resource_type}" "{resource_name}" {{\n'
                f'  bucket = "{resource_body.get("bucket", resource_name)}"\n'
                f'  acl    = "private" # Hardened: zero public access\n'
                f'}}\n\n'
                f'resource "aws_s3_bucket_public_access_block" "{resource_name}_block" {{\n'
                f'  bucket                  = aws_s3_bucket.{resource_name}.id\n'
                f'  block_public_acls       = true\n'
                f'  block_public_policy     = true\n'
                f'  ignore_public_acls      = true\n'
                f'  restrict_public_buckets = true\n'
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
                f"Bucket '{resource_id}' is configured with public ACL '{acl}'.",
            )

        return (
            PolicyStatus.PASSED,
            None,
            f"Storage resource '{resource_id}' is not publicly accessible.",
        )
