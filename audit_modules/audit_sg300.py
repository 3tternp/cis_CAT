"""
Enhanced Audit Module for Cisco Small Business SG300 / SG500 Series Switches
Author: Onyx CAAAT (Vairav Technology Security Pvt. Ltd.)
"""

import re
from typing import List
from report_modules.models import Finding


def run_cis_sg300_audit(config_content: str) -> List[Finding]:
    """
    Runs an extended CIS-style audit on SG300/SG500 switch configurations.
    Returns a list of Finding objects.
    """

    findings = []

    def add_finding(cis_id, level, status, risk, issue, remediation):
        findings.append(Finding(
            cis_id=cis_id,
            level=level,
            status=status,
            risk=risk,
            issue=issue,
            remediation=remediation
        ))

    # Normalize config text
    content = config_content.lower()

    # ================================================================
    # 1. SYSTEM IDENTIFICATION
    # ================================================================
    if re.search(r"^hostname\s+\S+", content, re.MULTILINE):
        add_finding("SYS-01", "Low", "Pass", "Low",
                    "Hostname is configured.", "No action required.")
    else:
        add_finding("SYS-01", "Low", "Fail", "Medium",
                    "No hostname configured.", "Use `hostname <name>`.")

    if re.search(r"banner\s+motd", content):
        add_finding("SYS-02", "Low", "Pass", "Low",
                    "Banner MOTD is configured.", "No action required.")
    else:
        add_finding("SYS-02", "Low", "Fail", "Medium",
                    "No login banner found.", "Set with `banner motd #Authorized Access Only#`.")

    # ================================================================
    # 2. MANAGEMENT ACCESS SECURITY
    # ================================================================
    if re.search(r"ip\s+ssh\s+server\s+enable", content):
        add_finding("MGMT-01", "High", "Pass", "Low",
                    "SSH server is enabled.", "No action required.")
    else:
        add_finding("MGMT-01", "High", "Fail", "High",
                    "SSH server not enabled.", "Enable SSH: `ip ssh server enable`.")

    if re.search(r"ip\s+telnet\s+server\s+enable", content):
        add_finding("MGMT-02", "High", "Fail", "High",
                    "Telnet access is enabled.", "Disable with `no ip telnet server enable`.")
    else:
        add_finding("MGMT-02", "High", "Pass", "Low",
                    "Telnet is disabled.", "No action required.")

    if re.search(r"ip\s+http\s+server\s+enable", content):
        add_finding("MGMT-03", "Medium", "Fail", "Medium",
                    "HTTP server is enabled (insecure).", "Disable and use HTTPS only: `no ip http server enable`.")
    else:
        add_finding("MGMT-03", "Medium", "Pass", "Low",
                    "HTTP server disabled.", "No action required.")

    if re.search(r"ip\s+https\s+server\s+enable", content):
        add_finding("MGMT-04", "Medium", "Pass", "Low",
                    "HTTPS management is enabled.", "No action required.")
    else:
        add_finding("MGMT-04", "Medium", "Fail", "Medium",
                    "HTTPS not enabled.", "Use `ip https server enable` for secure GUI access.")

    # ================================================================
    # 3. AUTHENTICATION & PASSWORD SECURITY
    # ================================================================
    if re.search(r"username\s+\S+\s+password\s+\d+\s+\S+", content):
        add_finding("AUTH-01", "High", "Pass", "Low",
                    "Encrypted local user passwords found.", "No action required.")
    else:
        add_finding("AUTH-01", "High", "Fail", "High",
                    "No encrypted passwords found.", "Use `service password-encryption`.")

    if not re.search(r"password strength-check", content):
        add_finding("AUTH-02", "Medium", "Manual", "Medium",
                    "No password strength policy found.", "Manually verify strong password policy enabled.")
    else:
        add_finding("AUTH-02", "Medium", "Pass", "Low",
                    "Password strength policy enforced.", "No action required.")

    if not re.search(r"login block-for", content):
        add_finding("AUTH-03", "Medium", "Manual", "Medium",
                    "No login block policy configured.", "Consider using login attempt limits.")
    else:
        add_finding("AUTH-03", "Medium", "Pass", "Low",
                    "Login block policy configured.", "No action required.")

    # ================================================================
    # 4. SNMP CONFIGURATION
    # ================================================================
    if re.search(r"snmp-server\s+community\s+(public|private)", content):
        add_finding("SNMP-01", "High", "Fail", "High",
                    "Insecure SNMP community string found.", "Replace with strong unique string or SNMPv3.")
    else:
        add_finding("SNMP-01", "High", "Pass", "Low",
                    "No insecure SNMP community found.", "No action required.")

    if not re.search(r"snmp-server\s+community\s+\S+\s+ro\s+\S+", content):
        add_finding("SNMP-02", "Medium", "Manual", "Medium",
                    "SNMP access restrictions not found.", "Restrict SNMP community to specific IPs.")
    else:
        add_finding("SNMP-02", "Medium", "Pass", "Low",
                    "SNMP restricted to specific IPs.", "No action required.")

    # ================================================================
    # 5. VLAN / INTERFACE SECURITY
    # ================================================================
    if not re.search(r"interface\s+vlan\s+(?!1\b)\d+", content):
        add_finding("VLAN-01", "Medium", "Fail", "Medium",
                    "Management VLAN appears to be VLAN 1.", "Move management to a separate VLAN.")
    else:
        add_finding("VLAN-01", "Medium", "Pass", "Low",
                    "Dedicated management VLAN detected.", "No action required.")

    if not re.search(r"spanning-tree\s+portfast\s+disable", content):
        add_finding("VLAN-02", "Low", "Manual", "Low",
                    "PortFast default unknown.", "Verify PortFast disabled on trunk ports.")
    else:
        add_finding("VLAN-02", "Low", "Pass", "Low",
                    "PortFast properly managed.", "No action required.")

    # ================================================================
    # 6. PORT SECURITY
    # ================================================================
    if re.search(r"port-security", content):
        add_finding("PORT-01", "High", "Pass", "Low",
                    "Port security enabled.", "No action required.")
    else:
        add_finding("PORT-01", "High", "Manual", "High",
                    "No port security configured.", "Use `switchport port-security` to limit MACs.")

    # ================================================================
    # 7. LOGGING / NTP / TIME SYNC
    # ================================================================
    if re.search(r"logging\s+\d+\.\d+\.\d+\.\d+", content):
        add_finding("LOG-01", "Medium", "Pass", "Low",
                    "Syslog server configured.", "No action required.")
    else:
        add_finding("LOG-01", "Medium", "Fail", "Medium",
                    "No syslog server configured.", "Use `logging <IP>` to enable remote logs.")

    if re.search(r"ntp\s+server\s+\d+\.\d+\.\d+\.\d+", content):
        add_finding("LOG-02", "Low", "Pass", "Low",
                    "NTP server configured.", "No action required.")
    else:
        add_finding("LOG-02", "Low", "Manual", "Low",
                    "NTP not configured.", "Add with `ntp server <IP>`.")

    # ================================================================
    # 8. CERTIFICATES & ENCRYPTION
    # ================================================================
    if re.search(r"crypto\s+key\s+generate\s+rsa", content):
        add_finding("CRYPTO-01", "High", "Pass", "Low",
                    "RSA keypair exists for SSH/HTTPS.", "No action required.")
    else:
        add_finding("CRYPTO-01", "High", "Fail", "High",
                    "No RSA keypair found.", "Generate key: `crypto key generate rsa`.")

    if re.search(r"certificate\s+chain", content):
        add_finding("CRYPTO-02", "Medium", "Pass", "Low",
                    "Certificate chain configured.", "No action required.")
    else:
        add_finding("CRYPTO-02", "Medium", "Manual", "Medium",
                    "Certificate chain not found.", "Manually verify HTTPS certificate installed.")

    # ================================================================
    # 9. GENERAL BEST PRACTICES
    # ================================================================
    if re.search(r"service\s+password-encryption", content):
        add_finding("GEN-01", "Low", "Pass", "Low",
                    "Password encryption service enabled.", "No action required.")
    else:
        add_finding("GEN-01", "Low", "Fail", "Medium",
                    "Password encryption service not enabled.", "Use `service password-encryption`.")

    if re.search(r"no\s+service\s+pad", content):
        add_finding("GEN-02", "Low", "Pass", "Low",
                    "PAD service disabled.", "No action required.")
    else:
        add_finding("GEN-02", "Low", "Manual", "Low",
                    "PAD service configuration not found.", "Disable it: `no service pad`.")

    if re.search(r"service\s+timestamps\s+debug", content) and re.search(r"service\s+timestamps\s+log", content):
        add_finding("GEN-03", "Low", "Pass", "Low",
                    "Timestamps enabled for logs and debugging.", "No action required.")
    else:
        add_finding("GEN-03", "Low", "Manual", "Low",
                    "Timestamp settings missing.", "Enable with `service timestamps log datetime`.")

    return findings
