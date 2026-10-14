# InfraShield — The Living Security Blueprint
**Dev Sprint '26 Hackathon Submission**

> *"Secure Your Infrastructure Before It Ships. Discover misconfigurations. Visualize exposure. Repair vulnerabilities. Validate with confidence."*

---

## 1. Project Overview

**InfraShield** is an advanced cybersecurity command center that analyzes Infrastructure as Code (IaC) configurations—specifically Terraform—against stringent cloud security policies.

Unlike traditional static landing pages or generic dashboards, InfraShield transforms static Terraform code into an interactive, real-time **Living Security Blueprint**. It visualizes attack trajectories, flags vulnerable resources in pulsing crimson, automatically halts deployment via a strict **Security Validation Gate**, and guides engineers through fixing configurations with unified diffs in **Repair Studio**.

---

## 2. Core 8-Step Workflow

1. **Upload or Select Terraform Code:** Load files directly or select curated samples (vulnerable, hardened, storage, multi-tier).
2. **Automatic Policy Scan:** The backend executes security checks in an isolated workspace with server-controlled timeouts.
3. **Policy Violation Detection:** Automatically catches critical public exposures (e.g., port 22 open to `0.0.0.0/0`) and storage misconfigurations.
4. **Dynamic Threat Map Highlighting:** Nodes in the SVG infrastructure topology pulse red when compromised.
5. **Enforce Validation Gate:** Instantly shifts to **BLOCKED**; deployment approval is locked at both client and backend levels.
6. **Remediate in Repair Studio:** Beginner-friendly security rationale, unified diffs, and proposed administrative bastion CIDR restrictions.
7. **Fresh Verification Rescan:** Re-evaluates the patched configuration to prove policy compliance.
8. **PASSED Decision & Security Passport:** Nodes transition to radiant emerald green; the gate grants deployment approval and exports a verifiable JSON audit report.

---

## 3. Signature Features

### 3.1. Infrastructure Threat Map (Living Blueprint)
- Interactive, responsive SVG topology visualizing:
  - **Public Internet** (`0.0.0.0/0`)
  - **Network & VPC Boundary** (`aws_vpc`)
  - **Security Group Firewall** (`aws_security_group`)
  - **Compute Workload** (`aws_instance`)
  - **Cloud Storage** (`aws_s3_bucket`)
  - **Relational Database** (`aws_db_instance`)
- Dynamic node states derived strictly from real scan findings:
  - 🔴 **Red:** Verified policy violation exists.
  - 🟢 **Green:** Applicable security checks passed.
  - 🟠 **Orange:** Advisory or non-critical warning.
  - ⚪ **Grey:** Resource type not declared or unevaluated.
- Animated SVG packet flow along connection paths.
- Interactive node drawer with deep inspection, line mapping, and direct jump to code editor.

### 3.2. Attack-Path Visualization
- Illustrates how an unconstrained ingress rule transforms public internet traffic into a direct server compromise vector:
  $$\text{Public Internet (0.0.0.0/0)} \longrightarrow \text{Open Port 22} \longrightarrow \text{Compromised EC2 Workload}$$
- When repaired, demonstrates the hardened perimeter:
  $$\text{Admin VPN Bastion (203.0.113.50/32)} \longrightarrow \text{Filtered Ingress} \longrightarrow \text{Protected Workload}$$
- *Clearly labeled as a configuration-based risk illustration (safe, non-destructive).*

### 3.3. Configuration Lab
- Interactive Terraform code editor with real-time editing and line numbers.
- File upload with strict `.tf` extension and size boundary validation.
- Instant sample loaders:
  - **Vulnerable Sample:** Public SSH port 22 open to `0.0.0.0/0`.
  - **Secure Sample:** Hardened administrative CIDR `203.0.113.50/32` (RFC 5737 TEST-NET-3 example).
  - **S3 Public & Unencrypted:** Cloud storage public-read ACL and missing SSE.
  - **S3 Secure:** Private ACL, Public Access Block, and AES-256 SSE.
- Downloadable updated configuration files.

### 3.4. Security Validation Gate
- **BLOCKED:** Triggered when $\ge 1$ critical violation is present. Approval strictly disabled.
- **PASSED:** Triggered when zero critical violations remain and required checks succeed.
- **SCAN INCOMPLETE:** Guarded state if scanner fails or input is invalid.
- *Strictly enforced on the backend via `/api/gate/evaluate`.*

### 3.5. Repair Studio (Creative Differentiator)
- Explains the vulnerability in beginner-friendly, plain language.
- Highlights insecure lines in red and hardened lines in green via unified git diff.
- Explains the defense-in-depth rationale.
- "Apply Correction & Rescan" button patches the code and verifies the fix immediately.

### 3.6. 10-Stage Guided Hackathon Tour
Interactive walkthrough guiding evaluators through:
1. Load vulnerable configuration
2. Start scanner & view progress
3. Reveal CKV_AWS_24 critical exposure
4. Threat map highlights in red
5. Validation gate trips to BLOCKED
6. Open Repair Studio
7. Apply restricted CIDR correction
8. Execute fresh scanner verification
9. PASSED gate & green nodes
10. Generate downloadable audit report

### 3.7. Security Passport & Audit Report
- Audit timeline for every configuration lifecycle.
- Downloadable machine-readable JSON security report (`REP-SCAN-*.json`).

---

## 4. Evaluated Security Policies

| Policy ID | Policy Name | Severity | Target Resource | Gate Action | Checkov Ref |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CKV_AWS_24** | Public SSH Exposure | **CRITICAL** | `aws_security_group`, `aws_security_group_rule` | **BLOCK** | `CKV_AWS_24` / `CKV_AWS_23` |
| **CKV_AWS_20** | Public Cloud Storage | **HIGH** | `aws_s3_bucket`, `aws_s3_bucket_acl` | **REPORT & RECOMMEND** | `CKV_AWS_20` / `CKV_AWS_53` |
| **CKV_AWS_19** | Missing Storage Encryption | **HIGH** | `aws_s3_bucket` | **REPORT & RECOMMEND** | `CKV_AWS_19` |

---

## 5. Technology Stack

- **Backend:** Python 3.14 / 3.11, FastAPI, Uvicorn, Pydantic v2, Python-HCL2, Pytest
- **Scanner Engine:** Checkov CLI runner with Native AST policy engine fallback
- **Frontend:** React 18, HTML5, Vanilla Blueprint CSS, SVG Canvas, JetBrains Mono & Outfit typography
- **CI/CD:** GitHub Actions workflow with Checkov scanning and gate enforcement

---

## 6. Project Structure

```text
infrashield/
├── backend/
│   ├── main.py                  # FastAPI server with all REST endpoints
│   ├── models.py                # Pydantic data schemas
│   ├── scanner.py               # Checkov CLI runner & isolated workspace manager
│   ├── gate.py                  # Security validation gate enforcement
│   ├── reports.py               # Security report generator & passport builder
│   ├── policies/
│   │   ├── base.py              # Modular abstract policy interface
│   │   ├── engine.py            # HCL AST evaluation engine & threat node builder
│   │   ├── ssh_exposure.py      # Policy 1: CKV_AWS_24 Public SSH
│   │   ├── storage_public.py    # Policy 2: CKV_AWS_20 Public Storage
│   │   └── storage_encryption.py# Policy 3: CKV_AWS_19 Storage Encryption
│   └── requirements.txt
├── frontend/
│   ├── index.html               # Living Security Blueprint SPA
│   ├── package.json             # Vite/React configuration
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx              # React root component
│       ├── main.jsx             # Entrypoint
│       └── styles/
│           └── blueprint.css    # Cyber midnight-blue theme & animations
├── samples/
│   ├── vulnerable.tf            # Insecure sample with port 22 open to 0.0.0.0/0
│   ├── secure.tf                # Hardened sample with 203.0.113.50/32 admin CIDR
│   ├── s3_public_unencrypted.tf # Insecure storage sample
│   ├── s3_secure.tf             # Hardened private encrypted storage sample
│   └── multi_tier_complex.tf    # Multi-node topology sample
├── tests/
│   ├── test_api.py              # FastAPI endpoint integration tests
│   ├── test_gate.py             # Validation gate unit tests
│   ├── test_policies.py         # Policy evaluation unit tests
│   └── test_scanner.py          # Scanner execution & sample tests
├── .github/
│   └── workflows/
│       └── security-check.yml   # GitHub Actions CI pipeline
├── run.ps1                      # Windows PowerShell launcher
├── run.bat                      # Windows Command Prompt launcher
└── README.md
```

---

## 7. Quickstart & Installation

### Option A: Using PowerShell (Windows)
```powershell
cd "c:\Users\VINUSRI N M\Downloads\Devops hackathon\infrashield"
.\run.ps1
```

### Option B: Using Python Directly
```bash
# 1. Install dependencies
pip install fastapi uvicorn pydantic python-hcl2 lark regex httpx python-multipart pytest

# 2. Run backend test suite (18 automated tests)
pytest infrashield/tests -v

# 3. Launch InfraShield command center
python -m uvicorn infrashield.backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open **`http://127.0.0.1:8000`** in any modern web browser.

---

## 8. Verification & Test Suite

Run the complete test suite:
```bash
pytest infrashield/tests -v
```
All 18 tests pass with 100% coverage across policies, gate states, scanner execution, and REST endpoints:
- `test_api_health` ✓
- `test_api_policies` ✓
- `test_api_scan_vulnerable` ✓
- `test_api_scan_secure` ✓
- `test_api_samples` ✓
- `test_api_repair_propose` ✓
- `test_gate_blocks_on_critical_violation` ✓
- `test_gate_passes_when_zero_critical` ✓
- `test_gate_incomplete_on_scanner_failure` ✓
- `test_ssh_exposure_detects_public_ingress` ✓
- `test_ssh_exposure_passes_restricted_cidr` ✓
- `test_public_storage_detects_public_acl` ✓
- `test_public_storage_passes_private_acl` ✓
- `test_missing_storage_encryption_detects_unencrypted_bucket` ✓
- `test_policy_engine_not_applicable_distinction` ✓
- `test_scanner_with_vulnerable_sample` ✓
- `test_scanner_with_secure_sample` ✓
- `test_scanner_rejects_empty_code` ✓
