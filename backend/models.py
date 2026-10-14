"""Data models for InfraShield - The Living Security Blueprint."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class GateStatus(str, Enum):
    BLOCKED = "BLOCKED"
    PASSED = "PASSED"
    SCAN_INCOMPLETE = "SCAN_INCOMPLETE"


class GateAction(str, Enum):
    BLOCK = "BLOCK"
    REPORT_AND_RECOMMEND = "REPORT_AND_RECOMMEND"


class Finding(BaseModel):
    policy_id: str
    policy_name: str
    severity: FindingSeverity
    resource_id: str
    resource_type: str
    file_path: str = "main.tf"
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    description: str
    remediation: str
    scanner_result: str = "FAILED"
    gate_action: GateAction = GateAction.REPORT_AND_RECOMMEND
    remediation_code: Optional[str] = None


class PolicyEvaluationResult(BaseModel):
    policy_id: str
    policy_name: str
    severity: FindingSeverity
    status: PolicyStatus
    resource_id: Optional[str] = None
    details: str
    recommendation: Optional[str] = None


class ThreatNodeState(str, Enum):
    RED = "RED"       # Verified policy violation
    GREEN = "GREEN"   # Applicable security checks passed
    ORANGE = "ORANGE" # Noncritical warning
    GREY = "GREY"     # Not evaluated / not present in config


class ThreatNode(BaseModel):
    id: str
    name: str
    type: str # internet, network, security_group, server, storage, database
    state: ThreatNodeState
    resource_id: Optional[str] = None
    findings_count: int = 0
    severity: Optional[str] = None
    violated_policy: Optional[str] = None
    reason: Optional[str] = None
    suggested_correction: Optional[str] = None
    line_number: Optional[int] = None


class ScanRequest(BaseModel):
    code: str = Field(..., max_length=500000, description="Terraform HCL code string")
    filename: Optional[str] = "main.tf"
    preferred_scanner: Optional[str] = "auto" # "auto", "checkov_cli", "native_engine"


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    filename: str
    scanner_engine: str
    scanner_status: str # "completed", "incomplete", "failed"
    status_message: str
    gate_status: GateStatus
    gate_reason: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    passed_count: int = 0
    not_applicable_count: int = 0
    findings: List[Finding] = []
    policy_evaluations: List[PolicyEvaluationResult] = []
    threat_nodes: List[ThreatNode] = []
    compliance_percentage: float = 100.0


class RepairRequest(BaseModel):
    original_code: Optional[str] = None
    current_code: Optional[str] = None
    code: Optional[str] = None
    policy_id: str
    resource_id: str


class RepairDiffLine(BaseModel):
    type: str # "add", "del", "same"
    line_number_old: Optional[int] = None
    line_number_new: Optional[int] = None
    content: str


class RepairResponse(BaseModel):
    policy_id: str
    resource_id: str
    original_snippet: str
    repaired_snippet: str
    full_repaired_code: str
    explanation: str
    why_it_helps: str
    diff_lines: List[RepairDiffLine] = []


class GateEvaluationRequest(BaseModel):
    findings: List[Finding]
    scanner_status: str = "completed"
    evaluations: List[PolicyEvaluationResult] = []


class GateEvaluationResponse(BaseModel):
    gate_status: GateStatus
    gate_reason: str
    blocking_violations: List[Finding] = []
    approval_allowed: bool = False
    checks_passed_count: int = 0
    remaining_high_count: int = 0
