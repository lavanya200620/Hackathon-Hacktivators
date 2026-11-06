/**
 * SourceMark Enterprise Collaborative Workflow Service
 * Coordinates investigation cases, SOC threat alerts, approval requests, and audit ledger.
 */

import axios from 'axios';
import { authService } from './authService.js';

const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) || 'http://127.0.0.1:8000';

const memStore = {};
const safeStorage = {
  getItem: (k) => (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(k) : memStore[k] || null),
  setItem: (k, v) => {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(k, v);
    } else {
      memStore[k] = v;
    }
  },
  removeItem: (k) => {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(k);
    } else {
      delete memStore[k];
    }
  },
};

const STORAGE_KEYS = {
  CASES: 'sourcemark_investigation_cases',
  ALERTS: 'sourcemark_soc_alerts',
  APPROVALS: 'sourcemark_org_approvals',
};

function getAuthHeaders() {
  const token = authService.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// Initial Seed Data
const INITIAL_CASES = [
  {
    id: 'INV-CASE-0104',
    title: 'Tampered Satellite Map Header in Sector 4B',
    sourceId: 'SRC-98214',
    fileName: 'satellite_recon_orbital_07.png',
    severity: 'HIGH',
    status: 'UNDER_INVESTIGATION',
    assignedTo: 'USR-INV-01',
    assignedToName: 'Agent Evelyn Vance',
    createdBy: 'USR-SOC-01',
    createdByName: 'Marcus Brody (SOC Lead)',
    evidenceHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    alteredHash: 'fa49182bb1928374a81928374bce819238471928374192837419283741928374',
    notes: [
      {
        author: 'Marcus Brody (SOC Lead)',
        text: 'Automated integrity alert triggered: Bit-level hash divergence detected during routine orbital asset check.',
        timestamp: '2026-10-29T10:14:00.000Z',
      },
      {
        author: 'Agent Evelyn Vance (Forensics)',
        text: 'Forensic inspection confirms bytes 4096-4128 altered. Original Ed25519 signature fails verification against altered buffer.',
        timestamp: '2026-10-29T14:22:00.000Z',
      },
    ],
    createdAt: '2026-10-29T10:14:00.000Z',
    updatedAt: '2026-10-29T14:22:00.000Z',
  },
  {
    id: 'INV-CASE-0105',
    title: 'Uncatalogued Key Registration Investigation',
    sourceId: 'SRC-35253',
    fileName: 'tactical_telemetry_grid.dat',
    severity: 'MEDIUM',
    status: 'RESOLVED',
    assignedTo: 'USR-INV-01',
    assignedToName: 'Agent Evelyn Vance',
    createdBy: 'SYSTEM_MONITOR',
    createdByName: 'Automated PKI Guard',
    evidenceHash: '8b7291a9283bce19283741928374192837419283741928374192837419283741',
    alteredHash: '8b7291a9283bce19283741928374192837419283741928374192837419283741',
    notes: [
      {
        author: 'Agent Evelyn Vance (Forensics)',
        text: 'Signing key confirmed generated outside Enterprise PKI Trust Registry. Custodian instructed to catalog key through Key Security Centre.',
        timestamp: '2026-10-30T15:10:00.000Z',
      },
    ],
    createdAt: '2026-10-30T14:05:12.000Z',
    updatedAt: '2026-10-30T15:10:00.000Z',
  },
];

const INITIAL_ALERTS = [
  {
    id: 'ALT-8842',
    title: 'Uncatalogued Public Key Registration Attempt',
    severity: 'MEDIUM',
    sourceId: 'SRC-35253',
    status: 'ACTIVE',
    type: 'UNTRUSTED_KEY',
    description: 'File signed with Ed25519 key not catalogued in Enterprise PKI Trust Registry.',
    timestamp: '2026-10-30T14:05:12.000Z',
    contained: false,
    recommendedAction: 'Quarantine signing key and verify identity with Security Admin.',
  },
  {
    id: 'ALT-8843',
    title: 'Revoked Key Signature Creation Attempt',
    severity: 'CRITICAL',
    sourceId: 'SRC-99011',
    status: 'CONTAINED',
    type: 'REVOKED_KEY_BLOCK',
    description: 'Prohibited signing attempt blocked for revoked key ED25519-STOLEN-01.',
    timestamp: '2026-10-30T16:11:45.000Z',
    contained: true,
    recommendedAction: 'Credential revoked. Containment lock enabled.',
  },
  {
    id: 'ALT-8844',
    title: 'Potential Rollback or Divergent Block Detected',
    severity: 'CRITICAL',
    sourceId: 'BLK-0042',
    status: 'ACTIVE',
    type: 'INTEGRITY_ANOMALY',
    description: 'Cryptographic hash sequence divergence detected between local node and trusted authority checkpoint.',
    timestamp: '2026-10-30T18:40:00.000Z',
    contained: false,
    recommendedAction: 'Enforce immutable WORM checkpoint synchronization.',
  },
];

const INITIAL_APPROVALS = [
  {
    id: 'APR-501',
    title: 'Derivative Authorization Request: Recon Map High-Contrast Layer',
    sourceId: 'SRC-98214',
    fileName: 'satellite_recon_orbital_07.png',
    requestedBy: 'Alex Rivera (Digital Contributor)',
    requestedById: 'USR-CUSTODIAN-01',
    status: 'PENDING',
    department: 'Orbital Reconnaissance',
    reason: 'Authorized crop and multispectral contrast enhancement for field debriefing.',
    timestamp: '2026-10-30T15:20:00.000Z',
  },
  {
    id: 'APR-502',
    title: 'Key Rotation Request: Sub-orbital Drone Sensor Array Key',
    sourceId: 'ED25519-DRONE-88',
    fileName: 'Sensor Signing Key Rotation',
    requestedBy: 'Alex Rivera',
    requestedById: 'USR-CUSTODIAN-01',
    status: 'APPROVED',
    department: 'Field Intelligence Capture',
    reason: 'Scheduled 90-day cryptographic key rotation per NIST SP 800-57 guidelines.',
    decidedBy: 'Director David Sterling (Org Lead)',
    decidedAt: '2026-10-30T16:00:00.000Z',
    timestamp: '2026-10-30T14:10:00.000Z',
  },
];

class EnterpriseWorkflowService {
  constructor() {
    this.initStorage();
  }

  initStorage() {
    try {
      if (!safeStorage.getItem(STORAGE_KEYS.CASES)) {
        safeStorage.setItem(STORAGE_KEYS.CASES, JSON.stringify(INITIAL_CASES));
      }
      if (!safeStorage.getItem(STORAGE_KEYS.ALERTS)) {
        safeStorage.setItem(STORAGE_KEYS.ALERTS, JSON.stringify(INITIAL_ALERTS));
      }
      if (!safeStorage.getItem(STORAGE_KEYS.APPROVALS)) {
        safeStorage.setItem(STORAGE_KEYS.APPROVALS, JSON.stringify(INITIAL_APPROVALS));
      }
    } catch {
      // ignore
    }
  }

  // --- Investigation Cases ---
  async getCases() {
    try {
      const res = await axios.get(`${BASE_URL}/api/investigations`, { headers: getAuthHeaders(), timeout: 1500 });
      if (res.data && res.data.cases) return res.data.cases;
    } catch {}
    const raw = safeStorage.getItem(STORAGE_KEYS.CASES);
    return raw ? JSON.parse(raw) : INITIAL_CASES;
  }

  async createCase(caseData) {
    const user = authService.getCurrentUser() || { id: 'USR-INV-01', name: 'Agent Evelyn Vance', email: 'investigator@sourcemark.io' };
    const newCase = {
      id: `INV-CASE-${Math.floor(1000 + Math.random() * 9000)}`,
      title: caseData.title || 'Forensic Discrepancy Case',
      sourceId: caseData.sourceId || 'SRC-MANUAL',
      fileName: caseData.fileName || 'inspected_asset',
      severity: caseData.severity || 'HIGH',
      status: 'UNDER_INVESTIGATION',
      assignedTo: user.id,
      assignedToName: user.name,
      createdBy: user.id,
      createdByName: user.name,
      evidenceHash: caseData.evidenceHash || '',
      alteredHash: caseData.alteredHash || '',
      notes: caseData.initialNote ? [
        {
          author: `${user.name} (${user.role})`,
          text: caseData.initialNote,
          timestamp: new Date().toISOString(),
        }
      ] : [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    try {
      await axios.post(`${BASE_URL}/api/investigations`, newCase, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    const cases = await this.getCases();
    cases.unshift(newCase);
    safeStorage.setItem(STORAGE_KEYS.CASES, JSON.stringify(cases));
    return newCase;
  }

  async addCaseNote(caseId, noteText) {
    const user = authService.getCurrentUser() || { name: 'Investigator', role: 'FORENSIC_INVESTIGATOR' };
    const cases = await this.getCases();
    const target = cases.find(c => c.id === caseId);
    if (!target) throw new Error('Investigation case not found');

    const note = {
      author: `${user.name} (${user.role})`,
      text: noteText,
      timestamp: new Date().toISOString(),
    };

    target.notes.push(note);
    target.updatedAt = new Date().toISOString();

    try {
      await axios.patch(`${BASE_URL}/api/investigations/${caseId}`, { note: noteText }, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    safeStorage.setItem(STORAGE_KEYS.CASES, JSON.stringify(cases));
    return target;
  }

  async updateCaseStatus(caseId, status) {
    const cases = await this.getCases();
    const target = cases.find(c => c.id === caseId);
    if (!target) throw new Error('Investigation case not found');

    target.status = status;
    target.updatedAt = new Date().toISOString();

    try {
      await axios.patch(`${BASE_URL}/api/investigations/${caseId}`, { status }, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    safeStorage.setItem(STORAGE_KEYS.CASES, JSON.stringify(cases));
    return target;
  }

  // --- SOC Security Alerts ---
  async getAlerts() {
    try {
      const res = await axios.get(`${BASE_URL}/api/alerts`, { headers: getAuthHeaders(), timeout: 1500 });
      if (res.data && res.data.alerts) return res.data.alerts;
    } catch {}
    const raw = safeStorage.getItem(STORAGE_KEYS.ALERTS);
    return raw ? JSON.parse(raw) : INITIAL_ALERTS;
  }

  async containAlert(alertId, action = 'QUARANTINE_CREDENTIAL') {
    const user = authService.getCurrentUser() || { name: 'SOC Operator', email: 'soc@sourcemark.io' };
    const alerts = await this.getAlerts();
    const target = alerts.find(a => a.id === alertId);
    if (target) {
      target.contained = true;
      target.status = 'CONTAINED';
      target.containedAt = new Date().toISOString();
      target.containedBy = user.name;
    }

    try {
      await axios.post(`${BASE_URL}/api/alerts/contain`, { alertId, action }, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    safeStorage.setItem(STORAGE_KEYS.ALERTS, JSON.stringify(alerts));
    return target;
  }

  // --- Approvals ---
  async getApprovals() {
    try {
      const res = await axios.get(`${BASE_URL}/api/approvals`, { headers: getAuthHeaders(), timeout: 1500 });
      if (res.data && res.data.approvals) return res.data.approvals;
    } catch {}
    const raw = safeStorage.getItem(STORAGE_KEYS.APPROVALS);
    return raw ? JSON.parse(raw) : INITIAL_APPROVALS;
  }

  async submitApprovalRequest({ title, sourceId, fileName, reason, department }) {
    const user = authService.getCurrentUser() || { name: 'Alex Rivera', id: 'USR-CUSTODIAN-01' };
    const newReq = {
      id: `APR-${Math.floor(500 + Math.random() * 500)}`,
      title,
      sourceId,
      fileName,
      requestedBy: user.name,
      requestedById: user.id,
      status: 'PENDING',
      department: department || 'Field Intelligence',
      reason,
      timestamp: new Date().toISOString(),
    };

    const list = await this.getApprovals();
    list.unshift(newReq);
    safeStorage.setItem(STORAGE_KEYS.APPROVALS, JSON.stringify(list));

    try {
      await axios.post(`${BASE_URL}/api/approvals`, newReq, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    return newReq;
  }

  async decideApproval(approvalId, decision, reason = '') {
    const user = authService.getCurrentUser() || { name: 'Director David Sterling' };
    const list = await this.getApprovals();
    const target = list.find(a => a.id === approvalId);
    if (!target) throw new Error('Approval request not found');

    target.status = decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    target.decidedBy = user.name;
    target.decidedAt = new Date().toISOString();
    target.decisionReason = reason;

    try {
      await axios.post(`${BASE_URL}/api/approvals/${approvalId}/decide`, { decision, reason }, { headers: getAuthHeaders(), timeout: 1500 });
    } catch {}

    safeStorage.setItem(STORAGE_KEYS.APPROVALS, JSON.stringify(list));
    return target;
  }
}

export const workflowService = new EnterpriseWorkflowService();
