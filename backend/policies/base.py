"""Base Policy interface for InfraShield.
Provides modular extensibility for Checkov, OPA/Conftest, and native IaC policy engines.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from ..models import (
    Finding,
    FindingSeverity,
    GateAction,
    PolicyEvaluationResult,
    PolicyStatus,
)


class BaseSecurityPolicy(ABC):
    """Abstract base class for security policies."""

    @property
    @abstractmethod
    def policy_id(self) -> str:
        """Standard Policy identifier (e.g., CKV_AWS_24)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable policy name."""
        pass

    @property
    @abstractmethod
    def severity(self) -> FindingSeverity:
        """Violation severity: CRITICAL, HIGH, MEDIUM, LOW, INFO."""
        pass

    @property
    @abstractmethod
    def target_resource_types(self) -> List[str]:
        """List of Terraform resource types this policy applies to."""
        pass

    @property
    @abstractmethod
    def gate_action(self) -> GateAction:
        """Action when policy fails: BLOCK or REPORT_AND_RECOMMEND."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Clear description of what this policy enforces and the risk."""
        pass

    @property
    @abstractmethod
    def remediation_recommendation(self) -> str:
        """Actionable guidance on how to remediate the vulnerability."""
        pass

    @abstractmethod
    def evaluate(
        self,
        resource_type: str,
        resource_name: str,
        resource_body: Dict[str, Any],
        raw_lines: List[str],
        all_resources: Dict[str, Dict[str, Any]],
    ) -> Tuple[PolicyStatus, Optional[Finding], str]:
        """
        Evaluate this policy against a specific Terraform resource.

        Returns:
            Tuple of:
            - PolicyStatus (PASSED, FAILED, NOT_APPLICABLE, NOT_EVALUATED)
            - Optional[Finding] if FAILED
            - str details/reason
        """
        pass
