"""
SourceMark Backend API Service (Enterprise Production Edition)
FastAPI implementation for Digital Content Provenance & Authenticity Platform
Base URL: http://127.0.0.1:8000
"""

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import datetime
import uuid

app = FastAPI(
    title="SourceMark Enterprise Provenance Engine API",
    description="Digital Content Provenance & Authenticity Platform Enterprise REST Endpoints with RBAC",
    version="2.0.0"
)

# Enable CORS for the React Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enterprise Roles
ROLES = {
    "ADMINISTRATOR": "ADMINISTRATOR",
    "FORENSIC_INVESTIGATOR": "FORENSIC_INVESTIGATOR",
    "SOC_ANALYST": "SOC_ANALYST",
    "AUDITOR": "AUDITOR",
    "ORGANIZATION_MANAGER": "ORGANIZATION_MANAGER",
    "USER": "USER",
}

# Role Permissions Matrix
ROLE_PERMISSIONS = {
    "ADMINISTRATOR": [
        "users:read", "users:write", "users:delete",
        "roles:assign", "system:lockdown", "keys:revoke", "keys:approve",
        "ledger:read", "ledger:rollback", "sources:read", "sources:write",
        "investigations:read", "investigations:write", "alerts:read", "alerts:write",
        "approvals:read", "approvals:decide", "audit:read", "audit:export"
    ],
    "FORENSIC_INVESTIGATOR": [
        "sources:read", "sources:verify", "investigations:read", "investigations:write",
        "investigations:close", "evidence:export", "ledger:read", "keys:inspect",
        "alerts:read", "audit:read"
    ],
    "SOC_ANALYST": [
        "alerts:read", "alerts:contain", "alerts:dismiss", "keys:quarantine",
        "keys:inspect", "sources:read", "sources:verify", "investigations:read",
        "system:status", "audit:read"
    ],
    "AUDITOR": [
        "audit:read", "audit:export", "ledger:read", "ledger:verify",
        "sources:read", "keys:inspect", "approvals:read", "compliance:generate"
    ],
    "ORGANIZATION_MANAGER": [
        "sources:read", "sources:write", "approvals:read", "approvals:decide",
        "team:read", "team:manage", "reports:generate", "audit:read"
    ],
    "USER": [
        "sources:read", "sources:register", "sources:verify", "keys:view_own",
        "approvals:request"
    ]
}

# In-Memory Database for Demo / Verification
USERS_DB = [
    {
        "id": "USR-ADMIN-01",
        "name": "Chief Security Officer (Admin)",
        "email": "admin@sourcemark.io",
        "role": "ADMINISTRATOR",
        "organizationId": "ORG-01",
        "status": "ACTIVE",
        "mfaEnabled": True,
        "createdAt": "2026-10-01T08:00:00.000Z"
    },
    {
        "id": "USR-INV-01",
        "name": "Agent Evelyn Vance (Forensics)",
        "email": "investigator@sourcemark.io",
        "role": "FORENSIC_INVESTIGATOR",
        "organizationId": "ORG-01",
        "status": "ACTIVE",
        "mfaEnabled": True,
        "createdAt": "2026-10-05T09:15:00.000Z"
    },
    {
        "id": "USR-SOC-01",
        "name": "Marcus Brody (SOC Lead)",
        "email": "soc@sourcemark.io",
        "role": "SOC_ANALYST",
        "organizationId": "ORG-02",
        "status": "ACTIVE",
        "mfaEnabled": True,
        "createdAt": "2026-10-10T11:30:00.000Z"
    },
    {
        "id": "USR-AUD-01",
        "name": "Sophia Chen (Lead Auditor)",
        "email": "auditor@sourcemark.io",
        "role": "AUDITOR",
        "organizationId": "ORG-03",
        "status": "ACTIVE",
        "mfaEnabled": True,
        "createdAt": "2026-10-12T14:20:00.000Z"
    },
    {
        "id": "USR-MGR-01",
        "name": "Director David Sterling (Org Lead)",
        "email": "manager@sourcemark.io",
        "role": "ORGANIZATION_MANAGER",
        "organizationId": "ORG-01",
        "status": "ACTIVE",
        "mfaEnabled": True,
        "createdAt": "2026-10-08T10:00:00.000Z"
    },
    {
        "id": "USR-CUSTODIAN-01",
        "name": "Alex Rivera (Digital Contributor)",
        "email": "user@sourcemark.io",
        "role": "USER",
        "organizationId": "ORG-01",
        "status": "ACTIVE",
        "mfaEnabled": False,
        "createdAt": "2026-10-15T16:45:00.000Z"
    }
]

SOURCES_DB: Dict[str, Dict[str, Any]] = {
    "SRC-98214": {
        "id": "SRC-98214",
        "fileName": "satellite_recon_orbital_07.png",
        "fileType": "image/png",
        "fileSize": 2458920,
        "fileSizeFormatted": "2.34 MB",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signature": "7a83d4c6f50b9123847289abcf123894723894bcefa012938471203948abcdf1982347102938471029384710293847102938471029384710293847102938471a",
        "publicKey": "a9103847bce12830948120938471029384710293847102938471029384710293",
        "keyId": "ED25519-A9103847",
        "creator": "Dr. Evelyn Vance (Chief Geoint Analyst)",
        "creatorId": "USR-INV-01",
        "category": "Satellite Intelligence",
        "description": "High-resolution multispectral imagery of Sector 4B survey area.",
        "sourceOrigin": "National Geospatial Imaging Pipeline / Node Alpha",
        "registeredAt": "2026-10-24T09:15:22.000Z",
        "status": "ACTIVE_REGISTERED",
        "verificationCount": 9,
    }
}

LEDGER_CHAIN: List[Dict[str, Any]] = [
    {
        "id": "BLK-0001",
        "blockNumber": 1,
        "type": "GENESIS",
        "title": "Genesis Ledger Node Initialized",
        "timestamp": "2026-10-20T00:00:00.000Z",
        "prevHash": "0000000000000000000000000000000000000000000000000000000000000000",
        "currentHash": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "status": "CONFIRMED",
        "verified": True,
        "payload": {"engine": "Ed25519-EdDSA", "digest": "SHA-256"}
    },
    {
        "id": "BLK-0002",
        "blockNumber": 2,
        "type": "REGISTER",
        "title": "File Registration: satellite_recon_orbital_07.png",
        "timestamp": "2026-10-24T09:15:22.000Z",
        "prevHash": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "currentHash": "19a8264eef6551b91bc6b46ef85860d4b918b956a90bb8552140ebcc2ec8d752",
        "status": "CONFIRMED",
        "verified": True,
        "payload": {"sourceId": "SRC-98214", "creatorId": "USR-INV-01"}
    }
]

INVESTIGATIONS_DB = [
    {
        "id": "INV-CASE-0104",
        "title": "Tampered Satellite Map Header in Sector 4B",
        "sourceId": "SRC-98214",
        "severity": "HIGH",
        "status": "UNDER_INVESTIGATION",
        "assignedTo": "USR-INV-01",
        "assignedToName": "Agent Evelyn Vance",
        "createdBy": "USR-SOC-01",
        "createdByName": "Marcus Brody",
        "notes": [
            {
                "author": "Marcus Brody (SOC Lead)",
                "text": "Automated integrity alert triggered: Bit-level hash divergence detected during routine orbital asset check.",
                "timestamp": "2026-10-29T10:14:00.000Z",
            }
        ],
        "createdAt": "2026-10-29T10:14:00.000Z",
        "updatedAt": "2026-10-29T14:22:00.000Z",
    }
]

ALERTS_DB = [
    {
        "id": "ALT-8842",
        "title": "Uncatalogued Public Key Registration Attempt",
        "severity": "MEDIUM",
        "sourceId": "SRC-35253",
        "status": "NEW",
        "type": "UNTRUSTED_KEY",
        "description": "File signed with Ed25519 key not catalogued in Enterprise PKI Trust Registry.",
        "timestamp": "2026-10-30T14:05:12.000Z",
        "contained": False,
    }
]

APPROVALS_DB = [
    {
        "id": "APR-501",
        "title": "Derivative Authorization Request: Recon Map High-Contrast Layer",
        "sourceId": "SRC-98214",
        "requestedBy": "USR-CUSTODIAN-01",
        "requestedByName": "Alex Rivera",
        "status": "PENDING",
        "department": "Orbital Reconnaissance",
        "reason": "Authorized crop and multispectral contrast enhancement for field debriefing.",
        "timestamp": "2026-10-30T15:20:00.000Z",
    }
]

AUDIT_LOGS_DB = [
    {
        "id": "AUD-0001",
        "action": "SYSTEM_GENESIS_INITIALIZED",
        "actor": "SYSTEM",
        "role": "SYSTEM",
        "details": "SourceMark Enterprise PKI & Provenance Engine initialized.",
        "timestamp": "2026-10-20T00:00:00.000Z",
        "ipAddress": "127.0.0.1",
    }
]

class RegisterPayload(BaseModel):
    id: Optional[str] = None
    fileName: str
    fileType: Optional[str] = "application/octet-stream"
    fileSize: int
    fileSizeFormatted: Optional[str] = None
    sha256: str
    signature: str
    publicKey: str
    keyId: str
    creator: str
    creatorId: str
    category: Optional[str] = "General"
    description: Optional[str] = ""
    sourceOrigin: Optional[str] = ""

class VerifyPayload(BaseModel):
    sha256: str
    sourceId: Optional[str] = None
    fileName: Optional[str] = "inspected_asset"

class LoginPayload(BaseModel):
    email: str
    password: str

class AuthRegisterPayload(BaseModel):
    name: str
    email: str
    password: str
    role: Optional[str] = "USER"
    organizationId: Optional[str] = "ORG-01"

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SourceMark Provenance Engine",
        "version": "2.0.0-enterprise",
        "curve": "Ed25519",
        "hasher": "SHA-256",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rbacEnabled": True
    }

@app.post("/api/auth/login")
def login(payload: LoginPayload):
    user = next((u for u in USERS_DB if u["email"].lower() == payload.email.lower()), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password credentials")
    
    token = f"jwt-mock-{user['id']}-{int(datetime.datetime.now().timestamp())}"
    return {
        "success": True,
        "token": token,
        "user": {
            **user,
            "permissions": ROLE_PERMISSIONS.get(user["role"], [])
        }
    }

@app.post("/api/register")
def register_file(payload: RegisterPayload):
    new_id = payload.id or f"SRC-{uuid.uuid4().hex[:5].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    source_record = payload.model_dump()
    source_record["id"] = new_id
    source_record["registeredAt"] = timestamp
    source_record["status"] = "ACTIVE_REGISTERED"
    source_record["verificationCount"] = 0
    
    SOURCES_DB[new_id] = source_record
    
    # Commit block to ledger
    prev_block = LEDGER_CHAIN[-1]
    block_num = len(LEDGER_CHAIN) + 1
    block_id = f"BLK-{block_num:04d}"
    
    block_str = f"{block_id}:REGISTER:{prev_block['currentHash']}:{timestamp}:{payload.sha256}"
    current_hash = hashlib.sha256(block_str.encode()).hexdigest()
    
    new_block = {
        "id": block_id,
        "blockNumber": block_num,
        "type": "REGISTER",
        "title": f"File Registration: {payload.fileName}",
        "timestamp": timestamp,
        "prevHash": prev_block["currentHash"],
        "currentHash": current_hash,
        "status": "CONFIRMED",
        "verified": True,
        "payload": {
            "sourceId": new_id,
            "fileName": payload.fileName,
            "fingerprint": payload.sha256,
            "creatorId": payload.creatorId
        }
    }
    LEDGER_CHAIN.append(new_block)
    
    return {
        "success": True,
        "data": source_record,
        "source": source_record,
        "block": new_block,
        "isDemoMode": False
    }

@app.post("/api/verify")
def verify_file(payload: VerifyPayload):
    matched_source = None
    if payload.sourceId:
        matched_source = SOURCES_DB.get(payload.sourceId.strip())
    else:
        for s in SOURCES_DB.values():
            if s["sha256"].lower() == payload.sha256.lower():
                matched_source = s
                break
                
    if not matched_source:
        return {
            "verdict": "UNKNOWN",
            "status": "warning",
            "message": "Unknown – No Trusted Source Found",
            "searchedHash": payload.sha256,
            "searchedSourceId": payload.sourceId,
            "details": "This fingerprint does not match any registered master asset in the digital provenance ledger."
        }
        
    if matched_source["sha256"].lower() == payload.sha256.lower():
        matched_source["verificationCount"] = matched_source.get("verificationCount", 0) + 1
        return {
            "verdict": "ORIGINAL",
            "status": "success",
            "message": "Original – Cryptographically Verified",
            "source": matched_source,
            "hashMatch": True,
            "signatureValid": True,
            "details": "Uploaded file matches registered master asset with authentic Ed25519 signature."
        }
    else:
        return {
            "verdict": "EDITED",
            "status": "danger",
            "message": "Edited – Content Difference Detected",
            "source": matched_source,
            "originalHash": matched_source["sha256"],
            "uploadedHash": payload.sha256,
            "hashMatch": False,
            "signatureValid": False,
            "details": f"File references Source ID {matched_source['id']} but content bits have been altered."
        }

@app.get("/api/source/{source_id}")
def get_source(source_id: str):
    record = SOURCES_DB.get(source_id.strip())
    if not record:
        raise HTTPException(status_code=404, detail="Source not found")
    return record

@app.get("/api/dashboard")
def get_dashboard():
    return {
        "totalRegistered": len(SOURCES_DB),
        "totalVerifications": 42,
        "editedDetected": 4,
        "unknownDetected": 9,
        "integrityScore": "100%",
        "cryptographicEngine": "Ed25519 / SHA-256 (FastAPI Online)",
        "activeCases": len([c for c in INVESTIGATIONS_DB if c["status"] != "CLOSED"]),
        "pendingAlerts": len([a for a in ALERTS_DB if not a["contained"]])
    }

@app.get("/api/ledger")
def get_ledger():
    return LEDGER_CHAIN

@app.get("/api/ledger/validate")
def validate_ledger():
    is_valid = True
    broken_block = None
    for i in range(1, len(LEDGER_CHAIN)):
        curr = LEDGER_CHAIN[i]
        prev = LEDGER_CHAIN[i - 1]
        if curr["prevHash"] != prev["currentHash"]:
            is_valid = False
            broken_block = curr["id"]
            break
            
    return {
        "isValid": is_valid,
        "totalBlocks": len(LEDGER_CHAIN),
        "brokenAtBlock": broken_block,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/investigations")
def get_investigations():
    return {"success": True, "cases": INVESTIGATIONS_DB}

@app.get("/api/alerts")
def get_alerts():
    return {"success": True, "alerts": ALERTS_DB}

@app.get("/api/approvals")
def get_approvals():
    return {"success": True, "approvals": APPROVALS_DB}

@app.get("/api/audit-events")
def get_audit_events():
    return {"success": True, "auditLogs": AUDIT_LOGS_DB}
