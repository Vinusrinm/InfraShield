"""Policy 1: Public SSH Exposure (CKV_AWS_24 / CKV_AWS_23).
Detects SSH port 22 open to 0.0.0.0/0 or ::/0.
Severity: CRITICAL
Gate behavior: BLOCK
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from .base import BaseSecurityPolicy
from ..models import Finding, FindingSeverity, GateAction, PolicyStatus


class PublicSSHExposurePolicy(BaseSecurityPolicy):
    """
    Enforces that port 22 (SSH) is never open to unrestricted CIDRs (0.0.0.0/0 or ::/0).
    Exposing SSH to the entire internet allows automated bots and attackers to launch
    credential stuffing, brute-force attacks, and leverage unpatched SSH vulnerabilities.
    """

    @property
    def policy_id(self) -> str:
        return "CKV_AWS_24"

    @property
    def name(self) -> str:
        return "Public SSH Exposure (Port 22 Open to 0.0.0.0/0)"

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.CRITICAL

    @property
    def target_resource_types(self) -> List[str]:
        return ["aws_security_group", "aws_security_group_rule"]

    @property
    def gate_action(self) -> GateAction:
        return GateAction.BLOCK

    @property
    def description(self) -> str:
        return (
            "Security group allows ingress traffic on port 22 (SSH) from all IPv4 addresses (0.0.0.0/0) "
            "or IPv6 (::/0). This exposes administrative management interfaces directly to the public internet, "
            "inviting automated brute-force attacks and potential host compromise."
        )

    @property
    def remediation_recommendation(self) -> str:
        return (
            "Restrict SSH access to trusted administrative CIDR ranges (e.g. your corporate VPN, "
            "bastion host IP such as '203.0.113.50/32' [example RFC 5737 admin IP]), or eliminate "
            "inbound SSH entirely by utilizing AWS Systems Manager (SSM) Session Manager."
        )

    def _find_line_numbers(self, raw_lines: List[str], resource_name: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """Extract line numbers and code snippet from raw lines for precise UI highlighting."""
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
            end_line = min(start_line + 25, len(raw_lines))

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

        # Inspect aws_security_group ingress blocks
        if resource_type == "aws_security_group":
            ingress_list = resource_body.get("ingress", [])
            if isinstance(ingress_list, dict):
                ingress_list = [ingress_list]

            is_vulnerable = False
            violating_rule = None

            for rule in ingress_list:
                if not isinstance(rule, dict):
                    continue

                from_port = rule.get("from_port")
                to_port = rule.get("to_port")
                cidr_blocks = rule.get("cidr_blocks", [])
                ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks", [])

                if isinstance(cidr_blocks, str):
                    cidr_blocks = [cidr_blocks]
                if isinstance(ipv6_cidr_blocks, str):
                    ipv6_cidr_blocks = [ipv6_cidr_blocks]

                # Check if port 22 is included
                covers_ssh = False
                try:
                    f_port = int(from_port) if from_port is not None else -1
                    t_port = int(to_port) if to_port is not None else -1
                    if (f_port <= 22 <= t_port) or (f_port == 0 and t_port == 0):
                        covers_ssh = True
                except (ValueError, TypeError):
                    pass

                # Check if CIDR is open to the world
                open_cidr = "0.0.0.0/0" in cidr_blocks or "::/0" in ipv6_cidr_blocks

                if covers_ssh and open_cidr:
                    is_vulnerable = True
                    violating_rule = rule
                    break

            if is_vulnerable:
                remediation_code = (
                    f'resource "{resource_type}" "{resource_name}" {{\n'
                    f'  # Compliant: SSH restricted to administrative CIDR\n'
                    f'  ingress {{\n'
                    f'    description = "Restricted SSH access from admin VPN"\n'
                    f'    from_port   = 22\n'
                    f'    to_port     = 22\n'
                    f'    protocol    = "tcp"\n'
                    f'    cidr_blocks = ["203.0.113.50/32"] # Example admin CIDR\n'
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
                    f"Resource '{resource_id}' exposes SSH port 22 to 0.0.0.0/0. Critical security violation.",
                )

            # If ingress rules exist and passed check
            return (
                PolicyStatus.PASSED,
                None,
                f"Resource '{resource_id}' does not expose SSH port 22 to unrestricted CIDRs.",
            )

        # Inspect standalone aws_security_group_rule
        elif resource_type == "aws_security_group_rule":
            rule_type = resource_body.get("type", "")
            if rule_type == "ingress":
                from_port = resource_body.get("from_port")
                to_port = resource_body.get("to_port")
                cidr_blocks = resource_body.get("cidr_blocks", [])

                covers_ssh = False
                try:
                    f_port = int(from_port) if from_port is not None else -1
                    t_port = int(to_port) if to_port is not None else -1
                    if f_port <= 22 <= t_port or (f_port == 0 and t_port == 0):
                        covers_ssh = True
                except (ValueError, TypeError):
                    pass

                if covers_ssh and "0.0.0.0/0" in cidr_blocks:
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
                    )
                    return (
                        PolicyStatus.FAILED,
                        finding,
                        f"Rule '{resource_id}' grants public SSH access to 0.0.0.0/0.",
                    )

            return (
                PolicyStatus.PASSED,
                None,
                f"Rule '{resource_id}' verified non-vulnerable.",
            )

        return (PolicyStatus.NOT_APPLICABLE, None, "Resource not evaluated.")
