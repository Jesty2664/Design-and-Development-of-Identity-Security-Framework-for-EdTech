import re
from flask import request, abort, current_app
from datetime import datetime, timedelta
from models import db, IPBlacklist, AuditLog
from utils import lattice_crypto

# Regex signatures for major attack vectors
SQLI_PATTERN = re.compile(r"(union\s+select|--|;\s*--|'\s+or\s+'1'='1|'\s*or\s*1\s*=\s*1|xp_cmdshell)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script>|javascript:|onerror=|onload=|eval\()", re.IGNORECASE)
CMD_INJECT_PATTERN = re.compile(r"(\/bin\/bash|\/bin\/sh|;\s*ls|\|\s*cat|\|\s*whoami)", re.IGNORECASE)
PATH_TRAV_PATTERN = re.compile(r"(\.\.\/|\.\.\\|\/etc\/passwd)", re.IGNORECASE)

def scan_payload(payload_str):
    """Scans a given string against all IPS signatures."""
    if not isinstance(payload_str, str):
        return None
        
    if SQLI_PATTERN.search(payload_str):
        return "SQL Injection"
    if XSS_PATTERN.search(payload_str):
        return "Cross-Site Scripting (XSS)"
    if CMD_INJECT_PATTERN.search(payload_str):
        return "Command Injection"
    if PATH_TRAV_PATTERN.search(payload_str):
        return "Path Traversal"
        
    return None

def trigger_ips_lockdown(ip, threat_type, payload):
    """Executes immediate quarantine and logging."""
    # 1. Quarantine IP for 24 hours
    record = IPBlacklist.query.filter_by(ip_address=ip).first()
    if not record:
        record = IPBlacklist(ip_address=ip)
        db.session.add(record)
    
    record.failed_attempts = 99  # Flag as high-severity
    record.blocked_until = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()
    
    # 2. Log High-Priority Critical Event to Admin Dashboard
    # Safe trimming of payload so massive data drops don't crush the view
    safe_payload = (payload[:100] + '...') if len(payload) > 100 else payload
    log_entry = f"IPS_TRIGGER [{threat_type}]: Src IP {ip} -> Payload: {safe_payload}"
    
    # Sign it with lattice crypto to ensure audit integrity
    keys = lattice_crypto.generate_keypair()
    pqc_sig = lattice_crypto.sign_audit_entry(log_entry, keys['private'])
    
    db.session.add(AuditLog(
        action="SECURITY_INCIDENT", 
        user_id=None, # System level
        details=log_entry, 
        pqc_signature=pqc_sig
    ))
    db.session.commit()

def global_ips_hook():
    """To be attached to app.before_request to scan all inbound data."""
    # Whitelist static assets and clearance requests to prevent overhead and allow unblock submissions
    if request.path.startswith('/static') or request.path == '/request-clearance':
        return
        
    ip = request.remote_addr
    
    # First, check if they are already in the IPS quarantine
    record = IPBlacklist.query.filter_by(ip_address=ip).first()
    if record and record.blocked_until and record.blocked_until > datetime.utcnow():
        if record.failed_attempts >= 99:
             abort(403, "ERR_CYBER_QUARANTINE: Active threat detected from this node. Connection severed.")
    
    threat_detected = None
    malicious_payload = None

    # Scan form data (POST/PUT)
    if request.form:
        for key, val in request.form.items():
            threat_detected = scan_payload(val)
            if threat_detected:
                malicious_payload = f"{key}={val}"
                break
                
    # Scan query params (GET)
    if not threat_detected and request.args:
        for key, val in request.args.items():
            threat_detected = scan_payload(val)
            if threat_detected:
                malicious_payload = f"{key}={val}"
                break

    # Scan JSON body
    if not threat_detected and request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if isinstance(json_data, dict):
                for key, val in json_data.items():
                    if isinstance(val, str):
                        threat_detected = scan_payload(val)
                        if threat_detected:
                            malicious_payload = f"{key}={val}"
                            break
        except:
            pass

    if threat_detected:
        trigger_ips_lockdown(ip, threat_detected, malicious_payload)
        abort(403, "ERR_CYBER_QUARANTINE: Malicious payload intercepted.")
