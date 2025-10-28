# audit_modules/audit_ios15.py

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

# --- SAMPLE CIS IOS 15 CHECKS ---

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
    cis_id="1.2.2", level=1, issue="Set 'enable secret' (Type 5/9 preferred)", 
    risk="Critical", remediation="Set 'enable secret <password>' globally. Avoid 'enable password'."
)
def check_enable_secret(config: str) -> Finding:
    if re.search(r"^\s*enable\s+secret\s+5|9\s+", config, re.MULTILINE):
        return _create_finding(check_enable_secret, "Pass")
    
    if re.search(r"^\s*enable\s+password\s+", config, re.MULTILINE):
        return _create_finding(check_enable_secret, "Fail", 
                               description="Legacy 'enable password' found (clear text or weak hash).")
    
    return _create_finding(check_enable_secret, "Fail",
                           description="'enable secret' is not configured.")

def run_cis_cisco_ios_15_assessment(config_content: str) -> List[Finding]:
    """Runs all registered IOS 15 checks."""
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
