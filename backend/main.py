"""InfraShield FastAPI Backend Server.
Provides RESTful APIs for IaC scanning, gate evaluation, repair studio, and reports.
"""

import os
import sys
import difflib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

from .models import (
    Finding,
    FindingSeverity,
    GateEvaluationRequest,
    GateEvaluationResponse,
    GateStatus,
    PolicyEvaluationResult,
    RepairDiffLine,
    RepairRequest,
    RepairResponse,
    ScanRequest,
    ScanResponse,
)
from .scanner import IaCScanner
from .gate import SecurityValidationGate
from .reports import SecurityReportGenerator

app = FastAPI(
    title="InfraShield — The Living Security Blueprint API",
    description="Cybersecurity Policy Engine and Automated Validation Gate for Infrastructure as Code",
    version="1.0.0",
)

# Enable CORS for local dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = IaCScanner()

# Memory scan history storage
SCAN_HISTORY: List[Dict[str, Any]] = []

# Base directory for samples
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")


@app.get("/api/health")
def health_check():
    """Health check endpoint indicating API and scanner operational readiness."""
    return {
        "status": "operational",
        "service": "InfraShield IaC Security Blueprint",
        "version": "1.0.0",
        "checkov_available": scanner.is_checkov_available(),
        "registered_policies_count": len(scanner.policy_engine.policies),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/policies")
def list_policies():
    """Returns the catalog of registered security policies and gate behaviors."""
    policies = []
    for p in scanner.policy_engine.policies:
        policies.append(
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "severity": p.severity.value,
                "target_resources": p.target_resource_types,
                "gate_action": p.gate_action.value,
                "description": p.description,
                "remediation": p.remediation_recommendation,
            }
        )
    return {"policies": policies}


@app.post("/api/scan", response_model=ScanResponse)
def run_scan(payload: ScanRequest):
    """
    Primary endpoint: Scans Terraform configuration, detects policy violations,
    and returns verified findings, threat map nodes, and gate status.
    """
    response = scanner.scan_terraform(
        code=payload.code,
        filename=payload.filename or "main.tf",
        preferred_scanner=payload.preferred_scanner or "auto",
    )

    # Record scan history
    SCAN_HISTORY.insert(0, {
        "scan_id": response.scan_id,
        "timestamp": response.timestamp,
        "filename": response.filename,
        "gate_status": response.gate_status.value,
        "critical_count": response.critical_count,
        "findings_count": len(response.findings),
        "compliance_percentage": response.compliance_percentage,
        "scanner_engine": response.scanner_engine,
    })
    # Keep last 50 scans
    if len(SCAN_HISTORY) > 50:
        SCAN_HISTORY.pop()

    return response


@app.post("/api/scan/upload", response_model=ScanResponse)
async def upload_and_scan(file: UploadFile = File(...)):
    """Upload a .tf file and immediately scan it."""
    if not file.filename.endswith(".tf"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Only Terraform configuration files (.tf) are accepted.",
        )

    content = await file.read()
    if len(content) > 500000:
        raise HTTPException(
            status_code=400,
            detail="File size exceeds the 500KB limit.",
        )

    try:
        code_str = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Invalid text encoding. File must be UTF-8 encoded text.",
        )

    return scanner.scan_terraform(code=code_str, filename=file.filename)


@app.post("/api/gate/evaluate", response_model=GateEvaluationResponse)
def evaluate_gate(payload: GateEvaluationRequest):
    """Enforce the security validation gate decision based on current findings."""
    return SecurityValidationGate.evaluate(
        findings=payload.findings,
        scanner_status=payload.scanner_status,
        evaluations=payload.evaluations,
    )


@app.post("/api/repair/propose", response_model=RepairResponse)
def propose_repair(req: RepairRequest):
    """
    Repair Studio API: Generates targeted code remediation, explanation,
    beginner-friendly rationale, and unified diff comparison.
    """
    code = req.original_code or req.current_code or req.code or ""
    policy_id = req.policy_id

    # Handle SSH exposure repair
    if policy_id in ["CKV_AWS_24", "CKV_AWS_23"]:
        original_snippet = """    ingress {
      description = "Unrestricted administrative SSH access"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }"""
        
        repaired_snippet = """    ingress {
      description = "Restricted SSH access from corporate VPN / Admin Bastion (Example CIDR)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["203.0.113.50/32"] # Example administrative CIDR (RFC 5737 TEST-NET-3)
    }"""

        # Replace in code
        full_repaired = code
        if 'cidr_blocks = ["0.0.0.0/0"]' in full_repaired:
            # specifically replace within port 22 block or first instance
            full_repaired = full_repaired.replace(
                'cidr_blocks = ["0.0.0.0/0"]',
                'cidr_blocks = ["203.0.113.50/32"] # Example admin CIDR',
                1
            )

        explanation = (
            "The original configuration specifies '0.0.0.0/0' as the ingress CIDR block for port 22 (SSH). "
            "In IPv4 networking, '0.0.0.0/0' represents every routable address on the public internet. "
            "This leaves your server's secure shell interface open to brute-force dictionaries and zero-day scanner bots."
        )
        why_it_helps = (
            "By constraining the CIDR block to a dedicated administrative IP range (e.g. '203.0.113.50/32' as an example admin bastion), "
            "only authorized internal workstations or secure VPN endpoints can initiate an SSH handshake. "
            "All untrusted traffic from the wider internet is dropped at the AWS cloud network boundary before reaching the virtual machine."
        )

    # Handle Public S3 Bucket repair
    elif policy_id in ["CKV_AWS_20", "CKV_AWS_53"]:
        original_snippet = '  acl    = "public-read"'
        repaired_snippet = (
            '  acl    = "private"\n'
            '}\n\n'
            'resource "aws_s3_bucket_public_access_block" "archive_block" {\n'
            '  bucket                  = aws_s3_bucket.data_archive.id\n'
            '  block_public_acls       = true\n'
            '  block_public_policy     = true\n'
            '  ignore_public_acls      = true\n'
            '  restrict_public_buckets = true'
        )
        full_repaired = code.replace('acl    = "public-read"', 'acl    = "private"')
        if "aws_s3_bucket_public_access_block" not in full_repaired:
            full_repaired += "\n\n" + """resource "aws_s3_bucket_public_access_block" "archive_block" {
  bucket                  = aws_s3_bucket.data_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
        explanation = "The bucket is declared with 'public-read' ACL, allowing anonymous read access to any internet client."
        why_it_helps = "Restricting ACL to 'private' and enforcing a Public Access Block guarantees zero anonymous access to sensitive storage objects."

    # Handle Missing Storage Encryption
    elif policy_id == "CKV_AWS_19":
        original_snippet = "# Missing server_side_encryption_configuration"
        repaired_snippet = """resource "aws_s3_bucket_server_side_encryption_configuration" "archive_encryption" {
  bucket = aws_s3_bucket.data_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}"""
        full_repaired = code + "\n\n" + repaired_snippet
        explanation = "Objects stored in this bucket are not automatically encrypted at rest."
        why_it_helps = "Enforcing AES-256 server-side encryption ensures storage media snapshots are encrypted against physical or unauthorized snapshot exfiltration."

    else:
        original_snippet = "# Insecure configuration"
        repaired_snippet = "# Hardened configuration"
        full_repaired = code
        explanation = "Generic remediation suggested."
        why_it_helps = "Improves posture against defined security policies."

    # Generate unified diff lines
    diff_lines: List[RepairDiffLine] = []
    old_lines = original_snippet.splitlines()
    new_lines = repaired_snippet.splitlines()
    matcher = difflib.ndiff(old_lines, new_lines)

    for item in matcher:
        tag = item[0]
        text = item[2:]
        if tag == "-":
            diff_lines.append(RepairDiffLine(type="del", content=text))
        elif tag == "+":
            diff_lines.append(RepairDiffLine(type="add", content=text))
        elif tag == " ":
            diff_lines.append(RepairDiffLine(type="same", content=text))

    return RepairResponse(
        policy_id=policy_id,
        resource_id=req.resource_id,
        original_snippet=original_snippet,
        repaired_snippet=repaired_snippet,
        full_repaired_code=full_repaired,
        explanation=explanation,
        why_it_helps=why_it_helps,
        diff_lines=diff_lines,
    )


@app.get("/api/samples/{sample_name}")
def get_sample_configuration(sample_name: str):
    """Retrieve sample Terraform configurations."""
    clean_name = sample_name.replace(".tf", "")
    mapping = {
        "vulnerable": "vulnerable.tf",
        "secure": "secure.tf",
        "s3_vulnerable": "s3_public_unencrypted.tf",
        "s3_public_unencrypted": "s3_public_unencrypted.tf",
        "s3_secure": "s3_secure.tf",
        "multi_tier": "multi_tier_complex.tf",
        "multi_tier_complex": "multi_tier_complex.tf",
    }
    filename = mapping.get(clean_name) or mapping.get(sample_name)
    if not filename and os.path.exists(os.path.join(SAMPLES_DIR, sample_name)):
        filename = sample_name
    elif not filename and os.path.exists(os.path.join(SAMPLES_DIR, f"{sample_name}.tf")):
        filename = f"{sample_name}.tf"

    if not filename:
        raise HTTPException(status_code=404, detail="Requested sample not found.")

    file_path = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Sample file {filename} does not exist.")

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    return {
        "sample_name": sample_name,
        "filename": filename,
        "code": content,
    }


@app.get("/api/history")
def get_scan_history():
    """Retrieve recent scan activity for the dashboard."""
    return {"history": SCAN_HISTORY}


@app.delete("/api/history")
def clear_scan_history():
    """Clear all scan history entries."""
    global SCAN_HISTORY
    SCAN_HISTORY.clear()
    return {"status": "cleared", "history": []}


@app.post("/api/reports/generate")
def generate_report(scan: ScanResponse):
    """Generate and return structured JSON security report for download."""
    return SecurityReportGenerator.generate_report(scan)


SRC_DIR = os.path.join(FRONTEND_DIR, "src")

# Mount static files and frontend src
if os.path.exists(SRC_DIR):
    app.mount("/src", StaticFiles(directory=SRC_DIR), name="src")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_index():
    """Serves the main application page."""
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "InfraShield API online. Frontend index not found."}

