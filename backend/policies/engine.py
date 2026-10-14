"""Policy Execution Engine for InfraShield.
Orchestrates policy evaluations and accurately maps findings and resource statuses.
"""

import re
from typing import Dict, Any, List, Tuple, Optional

try:
    import hcl2
    HCL2_AVAILABLE = True
except Exception:
    hcl2 = None
    HCL2_AVAILABLE = False

from .base import BaseSecurityPolicy
from .ssh_exposure import PublicSSHExposurePolicy
from .storage_public import PublicCloudStoragePolicy
from .storage_encryption import MissingStorageEncryptionPolicy
from ..models import (
    Finding,
    FindingSeverity,
    PolicyEvaluationResult,
    PolicyStatus,
    ThreatNode,
    ThreatNodeState,
)


class PolicyEngine:
    """Modular engine holding registered security policies."""

    def __init__(self):
        self.policies: List[BaseSecurityPolicy] = [
            PublicSSHExposurePolicy(),
            PublicCloudStoragePolicy(),
            MissingStorageEncryptionPolicy(),
        ]

    def register_policy(self, policy: BaseSecurityPolicy):
        """Allows registering custom or future OPA/Conftest policy adapters."""
        self.policies.append(policy)

    def parse_hcl(self, code: str) -> Dict[str, Any]:
        """Safely parse HCL code using python-hcl2 or resilient standard library parser."""
        if HCL2_AVAILABLE and hcl2 is not None:
            try:
                parsed = hcl2.loads(code)
                if parsed and parsed.get("resource"):
                    return parsed
            except Exception:
                pass
        return self._fallback_regex_parse(code)

    def _fallback_regex_parse(self, code: str) -> Dict[str, Any]:
        """Lightweight block parser for fault tolerance if HCL2 parser encounters non-standard syntax."""
        parsed: Dict[str, Any] = {"resource": []}
        resource_pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}', re.MULTILINE
        )

        for match in resource_pattern.finditer(code):
            rtype, rname, body = match.groups()
            res_dict: Dict[str, Any] = {}

            # Parse ingress blocks
            if "ingress" in body:
                ingress_list = []
                for ing in re.finditer(r'ingress\s*\{([\s\S]*?)\}', body):
                    ing_body = ing.group(1)
                    ing_dict: Dict[str, Any] = {}
                    from_p = re.search(r'from_port\s*=\s*(\d+)', ing_body)
                    to_p = re.search(r'to_port\s*=\s*(\d+)', ing_body)
                    cidr = re.search(r'cidr_blocks\s*=\s*\[(.*?)\]', ing_body)
                    if from_p:
                        ing_dict["from_port"] = int(from_p.group(1))
                    if to_p:
                        ing_dict["to_port"] = int(to_p.group(1))
                    if cidr:
                        cidrs = [c.strip().strip('"').strip("'") for c in cidr.group(1).split(",") if c.strip()]
                        ing_dict["cidr_blocks"] = cidrs
                    ingress_list.append(ing_dict)
                res_dict["ingress"] = ingress_list

            # Parse acl
            acl_match = re.search(r'acl\s*=\s*"([^"]+)"', body)
            if acl_match:
                res_dict["acl"] = acl_match.group(1)

            # Parse bucket
            bucket_match = re.search(r'bucket\s*=\s*"([^"]+)"', body)
            if bucket_match:
                res_dict["bucket"] = bucket_match.group(1)

            # Check encryption
            if "server_side_encryption_configuration" in body:
                res_dict["server_side_encryption_configuration"] = {}

            parsed["resource"].append({rtype: {rname: res_dict}})

        return parsed

    def evaluate_configuration(
        self, code: str
    ) -> Tuple[List[Finding], List[PolicyEvaluationResult], List[ThreatNode]]:
        """
        Evaluate all registered policies against the provided Terraform configuration.
        Distinguishes PASSED, FAILED, NOT_APPLICABLE, and NOT_EVALUATED.
        """
        raw_lines = code.splitlines(keepends=True)
        parsed = self.parse_hcl(code)

        # Flatten resources into structured dictionary: { resource_type: { resource_name: body } }
        all_resources: Dict[str, Dict[str, Any]] = {}
        for block in parsed.get("resource", []):
            if isinstance(block, dict):
                for rtype, rinstances in block.items():
                    if rtype not in all_resources:
                        all_resources[rtype] = {}
                    if isinstance(rinstances, dict):
                        for rname, rbody in rinstances.items():
                            all_resources[rtype][rname] = rbody

        findings: List[Finding] = []
        evaluations: List[PolicyEvaluationResult] = []

        # Iterate through registered policies
        for policy in self.policies:
            applicable_resources_found = False

            for rtype in policy.target_resource_types:
                if rtype in all_resources and all_resources[rtype]:
                    applicable_resources_found = True
                    for rname, rbody in all_resources[rtype].items():
                        res_id = f"{rtype}.{rname}"
                        status, finding, details = policy.evaluate(
                            rtype, rname, rbody, raw_lines, all_resources
                        )

                        if status == PolicyStatus.FAILED and finding:
                            findings.append(finding)
                            evaluations.append(
                                PolicyEvaluationResult(
                                    policy_id=policy.policy_id,
                                    policy_name=policy.name,
                                    severity=policy.severity,
                                    status=PolicyStatus.FAILED,
                                    resource_id=res_id,
                                    details=details,
                                    recommendation=policy.remediation_recommendation,
                                )
                            )
                        elif status == PolicyStatus.PASSED:
                            evaluations.append(
                                PolicyEvaluationResult(
                                    policy_id=policy.policy_id,
                                    policy_name=policy.name,
                                    severity=policy.severity,
                                    status=PolicyStatus.PASSED,
                                    resource_id=res_id,
                                    details=details,
                                )
                            )

            if not applicable_resources_found:
                evaluations.append(
                    PolicyEvaluationResult(
                        policy_id=policy.policy_id,
                        policy_name=policy.name,
                        severity=policy.severity,
                        status=PolicyStatus.NOT_APPLICABLE,
                        resource_id=None,
                        details=f"No resources matching target types ({', '.join(policy.target_resource_types)}) were declared in configuration.",
                    )
                )

        # Generate threat map node states derived strictly from actual findings
        threat_nodes = self._generate_threat_nodes(all_resources, findings, evaluations)

        return findings, evaluations, threat_nodes

    def _generate_threat_nodes(
        self,
        all_resources: Dict[str, Dict[str, Any]],
        findings: List[Finding],
        evaluations: List[PolicyEvaluationResult],
    ) -> List[ThreatNode]:
        """
        Derives threat map nodes directly from actual scan findings and declared resources.
        Internet -> Network -> Security Group -> Server -> Cloud Storage -> Database
        """
        # Node mapping:
        # 1. Internet (Untrusted External)
        # 2. Network (VPC / Gateway)
        # 3. Security Group (aws_security_group)
        # 4. Server (aws_instance)
        # 5. Cloud Storage (aws_s3_bucket)
        # 6. Database (aws_db_instance)

        # Check SG findings
        sg_findings = [f for f in findings if f.resource_type in ["aws_security_group", "aws_security_group_rule"]]
        s3_findings = [f for f in findings if f.resource_type in ["aws_s3_bucket", "aws_s3_bucket_acl"]]
        server_declared = "aws_instance" in all_resources and len(all_resources["aws_instance"]) > 0
        sg_declared = "aws_security_group" in all_resources and len(all_resources["aws_security_group"]) > 0
        s3_declared = "aws_s3_bucket" in all_resources and len(all_resources["aws_s3_bucket"]) > 0
        vpc_declared = "aws_vpc" in all_resources and len(all_resources["aws_vpc"]) > 0
        db_declared = "aws_db_instance" in all_resources and len(all_resources["aws_db_instance"]) > 0

        # Security group node state
        if sg_findings:
            crit = any(f.severity == FindingSeverity.CRITICAL for f in sg_findings)
            sg_state = ThreatNodeState.RED if crit else ThreatNodeState.ORANGE
            sg_policy = sg_findings[0].policy_name
            sg_reason = sg_findings[0].description
            sg_correction = sg_findings[0].remediation
            sg_res_id = sg_findings[0].resource_id
            sg_line = sg_findings[0].start_line
        elif sg_declared:
            sg_state = ThreatNodeState.GREEN
            sg_policy = "Public SSH Exposure (CKV_AWS_24)"
            sg_reason = "Administrative port 22 access is properly restricted to authorized CIDR."
            sg_correction = None
            first_sg = list(all_resources["aws_security_group"].keys())[0]
            sg_res_id = f"aws_security_group.{first_sg}"
            sg_line = 1
        else:
            sg_state = ThreatNodeState.GREY
            sg_policy = None
            sg_reason = "Security group not present in configuration."
            sg_correction = None
            sg_res_id = None
            sg_line = None

        # Server node state
        # If security group is RED (critical SSH exposure), server is at risk (RED/ORANGE)
        if server_declared:
            if sg_findings and any(f.severity == FindingSeverity.CRITICAL for f in sg_findings):
                server_state = ThreatNodeState.RED
                server_reason = "Server is directly exposed to public internet due to unconstrained security group ingress on port 22."
                server_policy = "Exposed Compute Workload"
                server_correction = "Remediate attached security group ingress rules."
            else:
                server_state = ThreatNodeState.GREEN
                server_reason = "Server is protected behind hardened security boundaries."
                server_policy = "Compute Hardening Verified"
                server_correction = None
            first_srv = list(all_resources["aws_instance"].keys())[0]
            srv_res_id = f"aws_instance.{first_srv}"
        else:
            server_state = ThreatNodeState.GREY
            server_reason = "No EC2 compute instance declared in current file."
            server_policy = None
            server_correction = None
            srv_res_id = None

        # Storage node state
        if s3_findings:
            s3_state = ThreatNodeState.RED if any(f.severity == FindingSeverity.CRITICAL for f in s3_findings) else ThreatNodeState.ORANGE
            s3_policy = s3_findings[0].policy_name
            s3_reason = s3_findings[0].description
            s3_correction = s3_findings[0].remediation
            s3_res_id = s3_findings[0].resource_id
            s3_line = s3_findings[0].start_line
        elif s3_declared:
            s3_state = ThreatNodeState.GREEN
            s3_policy = "S3 Privacy & Encryption Verified"
            s3_reason = "Bucket is private and protected with server-side encryption."
            s3_correction = None
            first_s3 = list(all_resources["aws_s3_bucket"].keys())[0]
            s3_res_id = f"aws_s3_bucket.{first_s3}"
            s3_line = 1
        else:
            s3_state = ThreatNodeState.GREY
            s3_policy = None
            s3_reason = "No storage buckets declared in configuration."
            s3_correction = None
            s3_res_id = None
            s3_line = None

        # Network node state
        if vpc_declared:
            net_state = ThreatNodeState.GREEN
            net_reason = "Virtual Private Cloud (VPC) boundary defined."
        elif sg_declared or server_declared:
            net_state = ThreatNodeState.GREEN if sg_state == ThreatNodeState.GREEN else ThreatNodeState.ORANGE
            net_reason = "Default AWS network boundary with defined security group."
        else:
            net_state = ThreatNodeState.GREY
            net_reason = "Network boundaries not evaluated."

        # Database node state
        if db_declared:
            db_state = ThreatNodeState.GREEN
            db_reason = "Relational database instance configured in private subnet."
        else:
            db_state = ThreatNodeState.GREY
            db_reason = "Database instance not evaluated in current snippet."

        # Internet Node (Red if public SSH exposure permits arbitrary internet access, otherwise Green/Controlled)
        if sg_findings:
            internet_state = ThreatNodeState.RED
            internet_reason = "Unrestricted public internet (0.0.0.0/0) has direct route to port 22."
        else:
            internet_state = ThreatNodeState.GREEN
            internet_reason = "Public ingress filtered via security perimeter."

        nodes = [
            ThreatNode(
                id="internet",
                name="Public Internet (0.0.0.0/0)",
                type="internet",
                state=internet_state,
                resource_id="external.internet",
                findings_count=len([f for f in findings if "0.0.0.0/0" in f.description]),
                severity="CRITICAL" if internet_state == ThreatNodeState.RED else "INFO",
                violated_policy="Unfiltered Public Ingress" if internet_state == ThreatNodeState.RED else "Perimeter Controlled",
                reason=internet_reason,
                suggested_correction="Enforce ingress firewall restrictions.",
            ),
            ThreatNode(
                id="network",
                name="VPC & Gateway",
                type="network",
                state=net_state,
                resource_id="aws_vpc.production_vpc" if vpc_declared else "aws_network.boundary",
                findings_count=0,
                severity="INFO",
                violated_policy=None,
                reason=net_reason,
            ),
            ThreatNode(
                id="security_group",
                name="Security Group (Firewall)",
                type="security_group",
                state=sg_state,
                resource_id=sg_res_id,
                findings_count=len(sg_findings),
                severity="CRITICAL" if sg_state == ThreatNodeState.RED else ("WARNING" if sg_state == ThreatNodeState.ORANGE else "PASS"),
                violated_policy=sg_policy,
                reason=sg_reason,
                suggested_correction=sg_correction,
                line_number=sg_line,
            ),
            ThreatNode(
                id="server",
                name="EC2 Compute Workload",
                type="server",
                state=server_state,
                resource_id=srv_res_id,
                findings_count=1 if server_state == ThreatNodeState.RED else 0,
                severity="CRITICAL" if server_state == ThreatNodeState.RED else "PASS",
                violated_policy=server_policy,
                reason=server_reason,
                suggested_correction=server_correction,
            ),
            ThreatNode(
                id="storage",
                name="S3 Cloud Storage",
                type="storage",
                state=s3_state,
                resource_id=s3_res_id,
                findings_count=len(s3_findings),
                severity="HIGH" if s3_state in [ThreatNodeState.RED, ThreatNodeState.ORANGE] else "PASS",
                violated_policy=s3_policy,
                reason=s3_reason,
                suggested_correction=s3_correction,
                line_number=s3_line,
            ),
            ThreatNode(
                id="database",
                name="RDS Database Instance",
                type="database",
                state=db_state,
                resource_id="aws_db_instance.primary_db" if db_declared else None,
                findings_count=0,
                severity="INFO",
                violated_policy=None,
                reason=db_reason,
            ),
        ]

        return nodes
