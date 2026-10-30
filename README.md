# SourceMark – Digital Content Provenance & Authenticity Platform

SourceMark is an enterprise-grade digital content provenance and tamper-detection platform engineered for digital forensics, media integrity verification, and evidentiary audit compliance.

![SourceMark Banner](https://img.shields.io/badge/Security-Ed25519%20%2B%20SHA--256-00F0FF?style=for-the-badge)
![Status](https://img.shields.io/badge/Platform-Operational-10B981?style=for-the-badge)

---

## 1. Core Workflow
```
UPLOAD FILE ➔ SHA-256 HASH ➔ ED25519 SIGNATURE ➔ REGISTER PROVENANCE ➔ VERIFY ➔ FORENSIC VERDICT
```

- **Zero-Knowledge Fingerprinting:** Hashing is executed client-side via the browser's native **Web Crypto API**. Raw binary files are never transmitted unhashed across the network.
- **Asymmetric Cryptography:** Detached signatures are calculated using **Ed25519 (Curve25519)**.
- **Tamper-Evident Ledger:** Every event is chained into an immutable, hash-linked block ledger (`hash(prevHash + eventData)`).

---

## 2. Key Modules & Pages

1. **Overview / Executive Dashboard (`/`):**
   - High-level intelligence metrics (Total Registered Files, Verifications, Alterations caught, Unknown files).
   - Interactive verification distribution doughnut chart (Recharts).
   - Real-time cryptographic service and ledger integrity telemetry.
   - Quick workflow action shortcuts.

2. **Register Digital Source (`/register`):**
   - Large drag-and-drop file upload with format & size validation (JPG, PNG, PDF, TXT).
   - 6-stage interactive cryptographic pipeline:
     1. In-memory buffer read
     2. SHA-256 Web Crypto digest generation
     3. Ed25519 digital signature creation
     4. Mathematical signature validation
     5. Contextual provenance attribution
     6. Commit event to audit ledger
   - Downloadable cryptographic registration receipt (`.json`) with verified digital seal.

3. **Verify Content Authenticity (`/verify`):**
   - 7-stage zero-trust verification pipeline.
   - Three distinct forensic result states:
     - 🟢 **Original – Cryptographically Verified:** 100% hash match + valid Ed25519 signature.
     - 🔴 **Edited – Content Difference Detected:** Bitstream divergence identified; direct link to launch pixel comparison.
     - 🟡 **Unknown – No Trusted Source Found:** Unmatched asset without prior declared provenance.
   - One-click demo test scenarios for judges.

4. **Digital Tamper Analysis (`/compare`):**
   - Dual upload interface for baseline vs. suspected assets.
   - **Image Diff:** Pixel-level canvas difference visualization with fluorescent red highlighting of modified regions, percentage variance, and synchronized zoom controls.
   - **Text Diff:** Line-by-line colored diff inspection.
   - Explicit forensic disclaimer regarding malicious intent vs bitstream modification.

5. **Content Provenance Trail (`/history`):**
   - Filterable, searchable, and sortable registry table.
   - Chronological timeline inspection modal showing the complete lifecycle of every asset.

6. **Tamper-Evident Audit Ledger (`/ledger`):**
   - Visual block-by-block hash chain linking genesis block to the latest events.
   - **Validate Ledger Button:** Recalculates all Merkle links and validates chain continuity.
   - **Simulate Tamper Test:** Demo feature allowing testers to corrupt a block and watch the chain flag `INVALID`.

7. **Forensic Verification Reports (`/reports`):**
   - ISO/IEC 27037 compliant evidentiary dossier.
   - Export report as `.json`, or use "Print / Save PDF" with custom forensic print stylesheets.

8. **Platform Settings (`/settings`):**
   - Active Ed25519 public key viewer & export tool.
   - Security principles (Private keys isolated in client memory).
   - Backend endpoint configuration & live health ping.

---

## 3. Quickstart & Running the Application

### Frontend (Vite + React)
```bash
# 1. Install dependencies
npm install

# 2. Run the development server
npm run dev
```
The application will launch at `http://localhost:3000`.

### Optional Python FastAPI Backend
The frontend works out of the box in **Simulation / Demo Mode** with full in-browser WebCrypto SHA-256 and Ed25519 cryptography. If you want to run the connected REST API:
```bash
# 1. Install FastAPI & Uvicorn
pip install fastapi uvicorn pydantic

# 2. Start the API service
uvicorn backend.main:app --reload --port 8000
```
When running, the top navigation pill will immediately flip to **`API Connected`**.

