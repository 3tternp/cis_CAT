import os
import re
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader

# --- Placeholder Imports for Core Modules ---
# These allow GUI startup even if some files are missing.
try:
    from audit_modules.audit_ios15 import run_cis_cisco_ios_15_assessment
    from audit_modules.audit_ios17 import run_cis_cisco_ios_17_assessment
    from report_modules.models import Finding

    def score_compute(findings: List[Any]) -> int:
        fail_count = sum(1 for f in findings if f.status in ("Fail", "Manual"))
        total_checks = len(findings)
        score = int(100 * (1 - (fail_count / total_checks))) if total_checks > 0 else 100
        return max(0, min(100, score))

except ImportError as e:
    print(f"Warning: Core audit dependencies missing ({e}). Functionality limited to basic file handling.")

    def run_cis_cisco_ios_15_assessment(config_content: str) -> List[Any]:
        return []

    def run_cis_cisco_ios_17_assessment(config_content: str) -> List[Any]:
        return []

    def score_compute(findings: List[Any]) -> int:
        return 0

    class Finding:
        def __init__(self, **kwargs):
            self.status = kwargs.get("status", "Manual")
            self.risk = kwargs.get("risk", "High")
            self.cis_id = kwargs.get("cis_id", "N/A")
            self.issue = kwargs.get("issue", "Missing Dependency")
            self.level = kwargs.get("level", "Medium")
            self.remediation = kwargs.get("remediation", "Check dependencies.")

        def to_dict(self):
            return {
                "status": self.status,
                "risk": self.risk,
                "cis_id": self.cis_id,
                "issue": self.issue,
                "level": self.level,
                "remediation": self.remediation,
            }


# --- Helper to determine IOS / SG300 version ---
def _determine_device_type(config_content: str) -> str:
    """
    Determines if the configuration belongs to Cisco IOS 15, IOS XE 17, or SG300/SG500.
    """
    if re.search(r"ios\s+xe\s+software,\s+version\s+17\.", config_content, re.IGNORECASE):
        return "ios17"
    if re.search(r"ios\s+software,\s+version\s+15\.", config_content, re.IGNORECASE):
        return "ios15"
    if re.search(r"R800_NIK_1_4_|SG300|SG500|system mode switch", config_content, re.IGNORECASE):
        return "sg300"
    return "unknown"


# --- Main Offline Assessment Logic ---
def run_assessment_offline(config_path: str) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
        config_content = f.read()

    device_type = _determine_device_type(config_content)

    # --- Cisco IOS XE 17.x ---
    if device_type == "ios17":
        findings = run_cis_cisco_ios_17_assessment(config_content)
        version_label = "Cisco IOS XE 17.x Audit"

    # --- Cisco IOS 15.x ---
    elif device_type == "ios15":
        findings = run_cis_cisco_ios_15_assessment(config_content)
        version_label = "Cisco IOS 15.x Audit"

    # --- Cisco Small Business SG300/SG500 ---
    elif device_type == "sg300":
        try:
            from audit_modules.audit_sg300 import run_cis_sg300_audit
            findings = run_cis_sg300_audit(config_content)
        except ImportError:
            findings = [Finding(
                status="Manual",
                risk="High",
                cis_id="N/A",
                issue="Missing audit_sg300.py module.",
                level="High",
                remediation="Ensure audit_modules/audit_sg300.py exists."
            )]
        version_label = "Cisco Small Business SG300/SG500 Audit"

    # --- Unknown Device Type ---
    else:
        findings = [Finding(
            status="Manual",
            risk="High",
            cis_id="N/A",
            issue="Could not determine device OS version or model.",
            level="High",
            remediation="Check configuration content for IOS version header."
        )]
        version_label = "Cisco Device (Unknown Version) Audit"

    # --- Compute Compliance Score ---
    score = score_compute(findings)

    # --- Generate Report Path ---
    report_filename = (
        os.path.splitext(os.path.basename(config_path))[0]
        + f"_CiscoAudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    report_path = os.path.join(os.path.dirname(config_path) or ".", report_filename)

    # --- Generate HTML Report ---
    _generate_offline_html_report(
        findings,
        config_path,
        score,
        report_path,
        version_label=version_label
    )

    findings_dicts = [f.to_dict() for f in findings]

    return {
        "findings": findings_dicts,
        "score": score,
        "report_file": report_path,
        "mode": "offline",
        "version_label": version_label
    }


# --- HTML Report Generation ---
def _generate_offline_html_report(
    findings: List[Finding],
    source: str,
    score: int,
    output_path: str,
    version_label: str = "Cisco Audit"
):
    """
    Uses Jinja2 and the cisco_report_template.html to render the report with charts.
    """
    env = Environment(loader=FileSystemLoader('.'))
    try:
        template = env.get_template('cisco_report_template.html')
    except Exception:
        raise FileNotFoundError("Missing 'cisco_report_template.html'. Ensure it is in the same directory.")

    # Count statuses and risks
    status_counts = {"Fail": 0, "Manual": 0, "Pass": 0}
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for f in findings:
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        risk_counts[f.risk] = risk_counts.get(f.risk, 0) + 1

    html_output = template.render(
        findings=findings,
        filename=os.path.basename(source),
        review_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        score=score,
        status_counts=status_counts,
        risk_counts=risk_counts,
        audit_version=version_label
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)


# --- Live Assessment Logic (Future Implementation) ---
def run_assessment_live(host, port, username, password) -> Dict[str, Any]:
    raise NotImplementedError("Live assessment via SSH is not implemented for this version.")
