"""
report_modules/models.py
Defines the Finding model used by CIS CAT - Cisco CIS Auditor
This version is backward-compatible with all audit modules.
"""

from typing import Optional, Dict


class Finding:
    """
    Represents a single CIS control finding from the Cisco configuration audit.

    Compatible with:
      - legacy instantiations like Finding(status="Fail", risk="High", issue="..."),
      - strict instantiations requiring (level, description, remediation).
    """

    def __init__(
        self,
        level: Optional[str] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None,
        **kwargs
    ):
        # Core expected CIS attributes
        self.level = level or kwargs.get("risk", "High")
        self.description = description or kwargs.get("issue", "No description provided.")
        self.remediation = remediation or kwargs.get(
            "remediation", "Review this setting manually and apply CIS guidance."
        )

        # Optional or legacy fields (for compatibility)
        self.status = kwargs.get("status", "Manual")
        self.risk = kwargs.get("risk", self.level)
        self.cis_id = kwargs.get("cis_id", "N/A")
        self.issue = kwargs.get("issue", self.description)
        self.category = kwargs.get("category", "General")
        self.control = kwargs.get("control", "N/A")

    def to_dict(self) -> Dict[str, str]:
        """
        Converts this finding to a dictionary for report rendering and scoring.
        """
        return {
            "level": self.level,
            "status": self.status,
            "risk": self.risk,
            "cis_id": self.cis_id,
            "issue": self.issue,
            "description": self.description,
            "remediation": self.remediation,
            "category": self.category,
            "control": self.control,
        }

    def __repr__(self):
        return f"<Finding level={self.level}, status={self.status}, issue='{self.issue[:40]}...'>"
