"""Security Validation Gate Enforcement for InfraShield.
Enforces the mandatory deployment gate decisions strictly on the backend.
"""

from typing import List, Tuple
from .models import (
    Finding,
    FindingSeverity,
    GateStatus,
    GateEvaluationResponse,
    PolicyEvaluationResult,
    PolicyStatus,
)


class SecurityValidationGate:
    """
    Enforces security compliance gates:
    - BLOCKED: When one or more CRITICAL violations exist. Approval is strictly disabled.
    - PASSED: Completed scan with zero critical violations. Approval is enabled.
    - SCAN_INCOMPLETE: When scanner failed or could not evaluate required checks.
    """

    @staticmethod
    def evaluate(
        findings: List[Finding],
        scanner_status: str,
        evaluations: List[PolicyEvaluationResult],
    ) -> GateEvaluationResponse:
        # Check scanner status first
        if scanner_status in ["incomplete", "failed", "error"]:
            return GateEvaluationResponse(
                gate_status=GateStatus.SCAN_INCOMPLETE,
                gate_reason="Security scan could not be completed or verified. The deployment gate is held in a guarded state until a valid scan completes.",
                blocking_violations=[],
                approval_allowed=False,
                checks_passed_count=0,
                remaining_high_count=0,
            )

        # Check critical violations
        critical_violations = [
            f for f in findings if f.severity == FindingSeverity.CRITICAL
        ]

        if critical_violations:
            blocking_policy_names = list(
                {f.policy_name for f in critical_violations}
            )
            policies_str = ", ".join(blocking_policy_names)
            return GateEvaluationResponse(
                gate_status=GateStatus.BLOCKED,
                gate_reason=(
                    f"Configuration deployment is BLOCKED due to {len(critical_violations)} verified CRITICAL violation(s): "
                    f"{policies_str}. Infrastructure containing critical security exposures cannot proceed to deployment."
                ),
                blocking_violations=critical_violations,
                approval_allowed=False,
                checks_passed_count=len(
                    [e for e in evaluations if e.status == PolicyStatus.PASSED]
                ),
                remaining_high_count=len(
                    [f for f in findings if f.severity == FindingSeverity.HIGH]
                ),
            )

        # Count passing and remaining high severity items
        passed_count = len([e for e in evaluations if e.status == PolicyStatus.PASSED])
        remaining_high = [f for f in findings if f.severity == FindingSeverity.HIGH]

        # Passed state
        summary_msg = (
            f"Validation PASSED. All {passed_count} evaluated security policies satisfied. "
            f"Zero critical exposures detected. Configuration is verified compliant for deployment pipeline."
        )
        if remaining_high:
            summary_msg += f" Note: {len(remaining_high)} advisory high-severity finding(s) reported for recommended hardening."

        return GateEvaluationResponse(
            gate_status=GateStatus.PASSED,
            gate_reason=summary_msg,
            blocking_violations=[],
            approval_allowed=True,
            checks_passed_count=passed_count,
            remaining_high_count=len(remaining_high),
        )
