import ast
import re
import logging
from typing import Dict, Any, List
import os
import sys

# Dynamically import the advanced signature engine
from .signature_loader import signature_engine # type: ignore

# Optional Data Science for high-performance log ingestion
try:
    import pandas as pd # pyre-ignore[21]
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None # type: ignore
    PANDAS_AVAILABLE = False


# ==============================================================================
# CLOUDSCAPE 9.0 - UNIFIED VULNERABILITY & EXPLOITATION ORCHESTRATOR
# ==============================================================================
# Simulates full enterprise Security Scanning: SAST, DAST, SCA, CSPM
# Utilizes dynamic JSON signature rules and AST parsing.
# ==============================================================================

class UnifiedVulnOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Intelligence.VulnOrchestrator")
        self.signatures = signature_engine.load_signature("vuln_signatures.json")

    # --------------------------------------------------------------------------
    # 1. SAST (Static Application Security Testing)
    # --------------------------------------------------------------------------
    
    class SastSecurityVisitor(ast.NodeVisitor):
        """Python AST Walker executing dynamic JSON heuristic signatures against parsed code."""
        def __init__(self, rules: List[Dict[str, Any]]):
            self.findings = []
            self.rules = rules
            
        def visit_Call(self, node):
            for rule in self.rules:
                if rule.get("type") == "MethodCall":
                    try:
                        if isinstance(node.func, ast.Attribute):
                            if node.func.value.id == rule.get("module") and node.func.attr == rule.get("method"): # type: ignore
                                self.findings.append({
                                    "rule": rule.get("id"),
                                    "severity": rule.get("severity"),
                                    "cvss_score": rule.get("cvss_score"),
                                    "description": rule.get("description"),
                                    "remediation": rule.get("remediation", "No remediation specified."),
                                    "line": node.lineno
                                })
                    except (AttributeError, TypeError):
                        pass
                elif rule.get("type") == "AttributeAccess":
                    try:
                        if isinstance(node.func, ast.Attribute) and node.func.value.id == rule.get("module"): # type: ignore
                            self.findings.append({
                                "rule": rule.get("id"),
                                "severity": rule.get("severity"),
                                "cvss_score": rule.get("cvss_score"),
                                "description": rule.get("description"),
                                "remediation": rule.get("remediation", "No remediation specified."),
                                "line": node.lineno
                            })
                    except (AttributeError, TypeError):
                        pass
            self.generic_visit(node)

        def visit_Assign(self, node):
            for rule in self.rules:
                if rule.get("type") == "VariableAssignment":
                    try:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if any(kw in target.id.upper() for kw in rule.get("keywords", [])):
                                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                        val = node.value.value
                                        if len(val) == dict(rule).get("regex_len", 0) and re.match(dict(rule).get("regex", ""), val):
                                            self.findings.append({
                                                "rule": rule.get("id"),
                                                "severity": rule.get("severity"),
                                                "cvss_score": rule.get("cvss_score"),
                                                "description": rule.get("description"),
                                                "remediation": rule.get("remediation", "No remediation specified."),
                                                "line": node.lineno
                                            })
                    except (AttributeError, TypeError):
                        pass
            self.generic_visit(node)


    def perform_sast_scan(self, raw_python_code: str) -> Dict[str, Any]:
        """
        Ingests a raw string of Python script (e.g., Lambda execution code)
        and physically compiles it into an Abstract Syntax Tree to identify zero-days based on dynamic JSON banks.
        """
        sast_rules = self.signatures.get("sast_rules", [])
        rules_evaluated = [r.get("id") for r in sast_rules]
        
        try:
            tree = ast.parse(raw_python_code)
            visitor = self.SastSecurityVisitor(sast_rules)
            visitor.visit(tree)
            
            return {
                "scan_type": "SAST",
                "rules_evaluated": rules_evaluated,
                "vulnerabilities": visitor.findings
            }
        except SyntaxError as e:
            return {"scan_type": "SAST", "error": f"Invalid Python Syntax: {e}"}

    # --------------------------------------------------------------------------
    # 2. SCA (Software Composition Analysis)
    # --------------------------------------------------------------------------

    def perform_sca_scan(self, requirements_content: str) -> Dict[str, Any]:
        """
        Parses `requirements.txt` or Node manifests from discovered compute nodes,
        dynamically flagging dependency trees against a mock runtime JSON corpus.
        Enriched with Supreme-Tier technical depth.
        """
        findings = []
        lines = requirements_content.split("\n")
        sca_rules = self.signatures.get("sca_rules", [])
        
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            for rule in sca_rules:
                kw = rule.get("keyword", "")
                if kw in line.lower():
                    # Handle exclusive version match
                    exclude_versions = rule.get("exclude_versions", [])
                    if exclude_versions:
                        if not any(v in line for v in exclude_versions):
                            findings.append({
                                "package": line, 
                                "id": rule.get("vulnerability"), 
                                "severity": rule.get("severity", "HIGH"),
                                "description": f"{rule.get('vulnerability')}: {rule.get('description')} [MITRE T1195.002] Supply Chain Compromise: Vulnerable dependency {line} detected.", 
                                "remediation": rule.get("remediation", "Update package to a secured version."), 
                                "line": idx+1
                            })
                    
                    # Handle trigger version match
                    trigger_versions = rule.get("trigger_versions", [])
                    if trigger_versions:
                        if any(v in line for v in trigger_versions):
                            findings.append({
                                "package": line, 
                                "id": rule.get("vulnerability"), 
                                "severity": rule.get("severity", "HIGH"),
                                "description": f"{rule.get('vulnerability')}: {rule.get('description')} [MITRE T1195.002] Supply Chain Compromise: Vulnerable dependency {line} detected.", 
                                "remediation": rule.get("remediation", "Update package to a secured version."), 
                                "line": idx+1
                            })
                
        return {
            "scan_type": "SCA",
            "dependencies_analyzed": len(lines),
            "vulnerabilities": findings
        }

    # --------------------------------------------------------------------------
    # 3. DAST (Dynamic Application Security Testing)
    # --------------------------------------------------------------------------

    def perform_dast_scan(self, w3c_alb_logs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Ingests rapid API Gateway or Load Balancer logs. If Pandas is available,
        uses an optimized DataFrame pipeline with custom RegEx rules to flag
        OWASP Top 10 attacks (SQLi, XSS, Path Traversal) dynamically.
        """
        dast_rules = self.signatures.get("dast_rules", {})
        sqli_pattern = dast_rules.get("sql_injection", r"(?i)(UNION\s+ALL\s+SELECT|1=1|DROP\s+TABLE|OR\s+1=1)")
        xss_pattern = dast_rules.get("cross_site_scripting", r"(?i)(<script>|<img\s+src=x\s+onerror=)")
        path_traversal = dast_rules.get("path_traversal", r"(?i)(\.\./\.\./|/etc/passwd)")

        findings = []

        if PANDAS_AVAILABLE and pd is not None:
            # Accelerated Data Pipeline
            df = pd.DataFrame(w3c_alb_logs)
            if 'request_uri' in df.columns:
                df['is_sqli'] = df['request_uri'].str.contains(sqli_pattern, regex=True, na=False)
                df['is_xss'] = df['request_uri'].str.contains(xss_pattern, regex=True, na=False)
                df['is_pt'] = df['request_uri'].str.contains(path_traversal, regex=True, na=False)
                
                for _, row in df[df['is_sqli'] | df['is_xss'] | df['is_pt']].iterrows():
                    attack_type = "SQL Injection" if row['is_sqli'] else ("Cross-Site Scripting" if row['is_xss'] else "Path Traversal")
                    findings.append({
                        "timestamp": row.get('timestamp', 'unknown'),
                        "source_ip": row.get('client_ip', 'unknown'),
                        "target_uri": row.get('request_uri'),
                        "owasp_attack_vector": attack_type
                    })
        else:
            # Native Python Fallback
            for log in w3c_alb_logs:
                uri = str(log.get('request_uri', ''))
                if re.search(sqli_pattern, uri):
                    findings.append({"source_ip": log.get('client_ip'), "target_uri": uri, "owasp_attack_vector": "SQL Injection"})
                elif re.search(xss_pattern, uri):
                    findings.append({"source_ip": log.get('client_ip'), "target_uri": uri, "owasp_attack_vector": "Cross-Site Scripting"})
                elif re.search(path_traversal, uri):
                    findings.append({"source_ip": log.get('client_ip'), "target_uri": uri, "owasp_attack_vector": "Path Traversal"})

        return {
            "scan_type": "DAST",
            "traffic_events_analyzed": len(w3c_alb_logs),
            "attacks_intercepted": len(findings),
            "threats": findings
        }

    # --------------------------------------------------------------------------
    # 4. CSPM (Cloud Security Posture Management)
    # --------------------------------------------------------------------------

    def evaluate_cspm_controls(self, cloud_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dynamically analyzes Infrastructure-as-Code (or Live State) against
        compliance benchmarks (CIS, NIST). Maps violations dynamically and 
        enriches with Supreme-Tier metadata.
        """
        import importlib
        vuln_reg_mod = importlib.import_module("intelligence.vulnerability_registry")
        vulnerability_registry = vuln_reg_mod.vulnerability_registry
        
        findings = []
        
        # 1. Block Public Access (S3)
        for bucket in cloud_state.get('Storage', {}).get('S3Buckets', []):
            policy = str(bucket.get('Policy', ''))
            if '"Principal": "*"' in policy and "Allow" in policy:
                # Lookup advanced metadata
                reg_entry = vulnerability_registry.lookup("AWS_S3_PUBLIC_EXPOSURE")
                if reg_entry:
                    findings.append({
                        "id": "CSPM-IAM-001",
                        "title": reg_entry.get("title"),
                        "severity": "CRITICAL",
                        "description": reg_entry.get("technical_explanation"),
                        "remediation": reg_entry.get("remediation_blueprint")[0] if isinstance(reg_entry.get("remediation_blueprint"), list) else "Rotate IAM keys.",
                        "mitre": reg_entry.get("mitre_details"),
                        "resource_arn": bucket.get("Arn"),
                        "blast_radius": 5.4
                    })

        # 3. IMDSv1 Detection (EC2)
        # Assuming node context is passed or derived
        # (Placeholder for logic integration)
                
        # 2. In-Transit Encryption (RDS/EC2)
        for sg in cloud_state.get('Network', {}).get('SecurityGroups', []):
            for rule in sg.get('IpPermissions', []):
                if rule.get('ToPort') == 22 and "0.0.0.0/0" in [r.get('CidrIp') for r in rule.get('IpRanges', [])]:
                    findings.append({
                        "resource": f"sg-{sg.get('GroupId')}",
                        "framework": "CIS 4.1",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "description": "[MITRE T1190] Security Group allows inbound SSH (Port 22) from the entire internet. This facilitates brute-force attacks and lateral movement vectors.",
                        "remediation": "Restrict Port 22 access to specific bastion host IPs or VPN gateways."
                    })

        # 3. IAM Least Privilege
        for role in cloud_state.get('IAM', {}).get('Roles', []):
            if "AdministratorAccess" in str(role.get('AttachedPolicies', [])):
                findings.append({
                    "resource": role.get('Arn'),
                    "framework": "NIST 800-53 AC-6",
                    "severity": "HIGH",
                    "cvss_score": 8.0,
                    "description": "[MITRE T1078] IAM Role possesses highly privileged AdministratorAccess. This violates the principle of least privilege and increases the blast radius of a credential compromise.",
                    "remediation": "Replace AdministratorAccess with fine-grained IAM policies targeting only required services."
                 })
        
        return {
            "scan_type": "CSPM",
            "compliance_failures": len(findings),
            "findings": findings
        }

    def orchestrate_node_security(self, node: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs the appropriate scanning suite based on the node's resource type.
        """
        findings = []
        resource_type = node.get("type", "").lower()
        
        # 1. SAST (Lambda / Compute)
        if resource_type in ("function", "instance", "lambda"):
            # If code is present in metadata, scan it
            code = node.get("metadata", {}).get("ScriptCode") or node.get("metadata", {}).get("HandlerCode")
            if code:
                sast = self.perform_sast_scan(code)
                findings.extend(sast.get("vulnerabilities", []))
                
        # 2. SCA (Software Inventory)
        reqs = node.get("metadata", {}).get("RequirementsTxt")
        if reqs:
            sca = self.perform_sca_scan(reqs)
            findings.extend(sca.get("vulnerabilities", []))
            
        # 3. CSPM (Generic Configurations)
        # Wrap the node in a 'Storage' or 'Network' structure if needed for evaluate_cspm_controls
        pseudo_state = {"Storage": {"S3Buckets": [node]} if resource_type == "bucket" else {},
                        "Network": {"SecurityGroups": [node]} if resource_type == "securitygroup" else {},
                        "IAM": {"Roles": [node]} if resource_type == "role" else {}}
        cspm = self.evaluate_cspm_controls(pseudo_state)
        findings.extend(cspm.get("findings", []))
        
        return findings

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
unified_orchestrator = UnifiedVulnOrchestrator()
