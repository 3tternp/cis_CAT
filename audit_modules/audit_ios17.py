# audit_modules/audit_ios17.py

import re
from report_modules.models import Finding
from typing import List

CHECK_FUNCTIONS = []

def register_check(cis_id: str, level: int, issue: str, risk: str, remediation: str):
    def decorator(func):
        func.cis_id = cis_id
        func.level = level
        func.issue = issue
        func.risk = risk
        func.remediation = remediation
        CHECK_FUNCTIONS.append(func)
        return func
    return decorator

def _create_finding(func, status: str, description: str = ""):
    """Creates a Finding object based on the function's attributes."""
    return Finding(
        cis_id=func.cis_id,
        level=func.level,
        status=status,
        risk=func.risk,
        issue=func.issue,
        description=description or func.issue,
        remediation=func.remediation
    )

# --- SAMPLE CIS IOS XE 17 CHECKS ---

@register_check(
    cis_id="1.1.1", level=1, issue="Enable 'aaa new-model'", 
    risk="Critical", remediation="Set 'aaa new-model' globally."
)
def check_aaa_new_model(config: str) -> Finding:
    if re.search(r"^\s*aaa\s+new-model\s*$", config, re.MULTILINE):
        return _create_finding(check_aaa_new_model, "Pass")
    return _create_finding(check_aaa_new_model, "Fail", 
                           description="AAA New Model is not enabled, compromising authentication framework.")

@register_check(
    cis_id="1.3.1", level=1, issue="Set 'username <user> privilege 15 secret'", 
    risk="High", remediation="Use 'username ... secret' and privilege levels instead of local-user database."
)
def check_admin_user_secret(config: str) -> Finding:
    if re.search(r"^\s*username\s+\S+\s+privilege\s+15\s+secret\s+5|9\s+", config, re.MULTILINE):
        return _create_finding(check_admin_user_secret, "Pass")
    return _create_finding(check_admin_user_secret, "Manual", 
                           description="Check for secure local user definition with privilege 15 and strong secret.")
                           
def run_cis_cisco_ios_17_assessment(config_content: str) -> List[Finding]:
    """Runs all registered IOS XE 17 checks."""
    findings = []
    normalized_config = config_content.lower().replace('\r\n', '\n').replace('\r', '\n')
    
    for check_func in CHECK_FUNCTIONS:
        try:
            findings.append(check_func(normalized_config))
        except Exception as e:
            findings.append(
                _create_finding(check_func, "Manual", description=f"Check failed due to execution error: {e}")
            )
            
    return findings