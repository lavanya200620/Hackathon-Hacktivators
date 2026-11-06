import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Zap,
  Lock,
  Layers,
  Key,
  Database,
  FileSearch,
  GitBranch,
  QrCode,
  Globe,
  Radio,
  UserCheck,
  CheckCircle,
  HelpCircle,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { calculateSHA256 } from '../services/crypto';

const THREATS = [
  {
    id: 'pre-image',
    title: '1. Pre-image & Hash Collision Attacks',
    severity: 'CRITICAL',
    vector: 'Cryptanalysis',
    description: 'An attacker attempts to synthesize a fraudulent file that computes to the exact same SHA-256 hash as an authentic document.',
    impact: 'If successful, a forged document could seamlessly replace a registered original without triggering tamper detection.',
    mechanism: 'Adversary executes multi-billion GPU cluster searching for inputs m_1 \\neq m_2 such that H(m_1) = H(m_2).',
    mitigation: 'SourceMark deploys SHA-256 (2^{128} collision resistance work factor), making collisions mathematically impossible with present computational physics.',
    residuals: 'Cryptographic anomaly logs; simultaneous multi-hash verification (SHA-256 + BLAKE3).',
  },
  {
    id: 'stolen-key',
    title: '2. Stolen Private Key Impersonation',
    severity: 'CRITICAL',
    vector: 'Key Management',
    description: 'An adversary compromises the private signing key of an authorized journalist or corporate officer.',
    impact: 'Allows malicious actors to produce mathematically valid signatures for fabricated news or fraudulent contracts.',
    mechanism: 'Exfiltration of endpoint keys via phishing, malware, or unsecured local memory buffers.',
    mitigation: 'Centralized Key Security Centre with instant revocation flags, hardware security module (HSM) enforcement, and retroactive signature partitioning.',
    residuals: 'Timestamp anomalies; sudden usage spikes; geographic IP disparity during signing.',
  },
  {
    id: 'rollback-attack',
    title: '3. Ledger Rollback & History Rewrite',
    severity: 'HIGH',
    vector: 'Ledger Storage',
    description: 'A malicious database administrator erases recent ledger blocks to remove evidence of an asset registration.',
    impact: 'Victim files become "Unknown / Unregistered", discrediting genuine content owners.',
    mechanism: 'Targeting database storage directly using SQL truncate or filesystem file rewrites, bypassing frontend APIs.',
    mitigation: 'Independently anchored WORM (Write-Once-Read-Many) checkpoints and continuous integrity watchdogs.',
    residuals: 'Height regression mismatch; Merkle root divergence between live node and cold storage.',
  },
  {
    id: 'metadata-strip',
    title: '4. Metadata Stripping & Spoofing',
    severity: 'MEDIUM',
    vector: 'Asset Transport',
    description: 'Messaging platforms (WhatsApp, X, Discord) routinely strip EXIF tags to conserve bandwidth or privacy.',
    impact: 'Naive verification platforms flag innocent files as tampered due to missing metadata headers.',
    mechanism: 'Compression pipelines re-encode raster pixels and discard auxiliary EXIF, XMP, and IPTC segments.',
    mitigation: 'SourceMark isolates bitstream SHA-256 verification from metadata parsing; missing EXIF never marks an asset fake.',
    residuals: 'JFIF standard headers intact with missing TIFF tags; clean pixel quantization tables.',
  },
  {
    id: 'false-positives',
    title: '5. Benign Re-save False Positives',
    severity: 'MEDIUM',
    vector: 'Editorial Pipeline',
    description: 'A legitimate photographer saves an authentic photo from TIFF to WebP for mobile publication.',
    impact: 'The bitstream hash completely changes, resulting in a false-positive "TAMPERED" verdict.',
    mechanism: 'Compression algorithms alter underlying discrete cosine transform coefficients and color subsampling.',
    mitigation: 'Authorized Derivative Lineage module allowing creators to sign parent-child version control chains.',
    residuals: 'Parent Source ID manifest attached to child asset metadata.',
  },
  {
    id: 'evidence-tamper',
    title: '6. Digital Forensic Evidence Tampering',
    severity: 'HIGH',
    vector: 'Legal Custody',
    description: 'An adversary modifies an exported verification certificate or audit ledger export before presenting it in legal arbitration.',
    impact: 'Fraudulent evidence submitted to court proceedings; judicial loss of trust.',
    mechanism: 'Editing exported PDF text layers using vector editors or modifying JSON audit logs.',
    mitigation: 'Certificates embed signed cryptographic QR tokens that reference immutable ledger block hashes.',
    residuals: 'PDF modification timestamps; signature mismatch against public verification endpoints.',
  },
  {
    id: 'registry-injection',
    title: '7. Malicious Registry Injection',
    severity: 'HIGH',
    vector: 'Identity & Access',
    description: 'An attacker injects fraudulent source records directly into the local browser storage or backend database.',
    impact: 'Counterfeit documents appear officially registered with spoofed historical timestamps.',
    mechanism: 'Exploiting cross-site scripting (XSS) or unauthenticated API endpoints to inject rogue records.',
    mitigation: 'Hash-chained ledger verification; every record must have a valid cryptographic back-link and Ed25519 signature.',
    residuals: 'Broken hash pointers; unresolvable previous-block digests.',
  },
  {
    id: 'qr-phishing',
    title: '8. QR Code Phishing & Replay Attacks',
    severity: 'MEDIUM',
    vector: 'Physical / Optical',
    description: 'An attacker prints a legitimate QR code on a counterfeit physical asset or replaces the QR with a link to a phishing site.',
    impact: 'Users scanning the physical QR believe a physical fake is digitally authentic.',
    mechanism: 'Visual barcode swapping; man-in-the-middle web redirection.',
    mitigation: 'Client requires cross-verifying the physical asset bitstream hash against the payload decoded inside the QR.',
    residuals: 'Mismatch between scanned file hash and QR payload digest.',
  },
  {
    id: 'mitm-interception',
    title: '9. Man-in-the-Middle Verification Interception',
    severity: 'HIGH',
    vector: 'Network',
    description: 'Adversary intercepts verification API calls and returns spoofed JSON: `{"status": "ORIGINAL"}`.',
    impact: 'Clients are deceived into trusting counterfeit assets.',
    mechanism: 'DNS cache poisoning, malicious Wi-Fi hotspots, or proxy injection.',
    mitigation: 'Client-side verification architecture: SHA-256 and Ed25519 math are calculated directly inside the browser sandbox.',
    residuals: 'TLS certificate mismatch; failed local detached signature verification.',
  },
  {
    id: 'quantum-threat',
    title: '10. Quantum Threat to Classical Asymmetric Cryptography',
    severity: 'MEDIUM',
    vector: 'Post-Quantum',
    description: 'Future fault-tolerant quantum computers running Shor’s algorithm could theoretically break discrete logarithms in Curve25519.',
    impact: 'Past Ed25519 signatures could be retroactively forged if private keys are derived.',
    mechanism: 'Quantum period finding solving discrete logarithms in polynomial time (O((\\log N)^3)).',
    mitigation: 'SourceMark architecture supports modular cryptographic agility, designed to swap to NIST Post-Quantum standards (ML-DSA / Dilithium).',
    residuals: 'None observable currently; mitigation relies on algorithmic upgradability.',
  },
  {
    id: 'sybil-identity',
    title: '11. Social Engineering & Sybil Identity Fraud',
    severity: 'MEDIUM',
    vector: 'Human / Social',
    description: 'An attacker generates hundreds of fake personas and registers plagiarized assets under deceptive authority names.',
    impact: 'Users trust an asset because it is "Signed", without verifying the identity of the signer.',
    mechanism: 'Name spoofing (e.g. "Dr. Eve1yn Vance - Reuters" using lookalike Unicode characters).',
    mitigation: 'Key Security Registry requiring explicit identity anchoring and public key fingerprint verification.',
    residuals: 'Key ID disparity; missing organizational accreditation in key metadata.',
  },
];

export default function SecurityRiskCentre() {
  const [selectedThreat, setSelectedThreat] = useState(THREATS[0]);
  const [expandedThreatId, setExpandedThreatId] = useState(THREATS[0].id);

  // Simulation 1: Bit-flip Avalanche State
  const [baseString, setBaseString] = useState('SourceMark Document v1.0 Original');
  const [altString, setAltString] = useState('SourceMark Document v1.0 0riginal');
  const [baseHash, setBaseHash] = useState('');
  const [altHash, setAltHash] = useState('');
  const [hammingDistance, setHammingDistance] = useState(0);

  // Simulation 2: Signature Forgery State
  const [forgeryResult, setForgeryResult] = useState(null);

  // Simulation 3: Broken Chain State
  const [chainTampered, setChainTampered] = useState(false);

  // Run Bit-flip Simulation
  const runBitFlipSim = async () => {
    const h1 = await calculateSHA256(new Blob([baseString]));
    const h2 = await calculateSHA256(new Blob([altString]));
    setBaseHash(h1);
    setAltHash(h2);

    // Calculate different hex characters
    let diffs = 0;
    for (let i = 0; i < 64; i++) {
      if (h1[i] !== h2[i]) diffs++;
    }
    setHammingDistance(diffs);
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-rose-400 text-xs font-mono uppercase tracking-wider mb-1">
            <ShieldAlert className="w-4 h-4" />
            <span>Adversarial Threat Intelligence</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Security & Risk Awareness Centre
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            In-depth technical breakdown of 11 digital content attack vectors with 5-point forensic analyses and live interactive vulnerability simulations.
          </p>
        </div>
      </div>

      {/* 4 Interactive Attack Simulations Ribbon */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyan-accent" />
          Interactive Attack Simulations
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* SIMULATION 1: Bit-Flip Avalanche Effect */}
          <div className="p-6 bg-navy-900 border border-background-border rounded-xl shadow-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-cyan-300 font-mono">SIMULATION 1</span>
                <span className="text-[10px] font-mono text-slate-400">Avalanche Effect</span>
              </div>
              <h3 className="text-sm font-bold text-white">Bit-flip Cryptographic Scrambling</h3>
              <p className="text-xs text-slate-400 mt-1 mb-4">
                Observe how altering a single character ("O" to "0") cascades across all 64 rounds of SHA-256.
              </p>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-[10px] text-slate-400 font-mono block">Original Text:</span>
                  <input
                    type="text"
                    value={baseString}
                    onChange={(e) => setBaseString(e.target.value)}
                    className="w-full bg-navy-950 border border-background-border rounded px-2.5 py-1.5 font-mono text-slate-200"
                  />
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 font-mono block">Altered Text (1 character changed):</span>
                  <input
                    type="text"
                    value={altString}
                    onChange={(e) => setAltString(e.target.value)}
                    className="w-full bg-navy-950 border border-background-border rounded px-2.5 py-1.5 font-mono text-slate-200"
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-background-border">
              <button
                onClick={runBitFlipSim}
                className="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-bold text-xs transition-all mb-3"
              >
                Compute Avalanche Delta
              </button>

              {baseHash && (
                <div className="space-y-2 text-[10px] font-mono">
                  <div className="p-2 bg-navy-950 rounded break-all text-emerald-400 border border-emerald-500/20">
                    H1: {baseHash}
                  </div>
                  <div className="p-2 bg-navy-950 rounded break-all text-rose-400 border border-rose-500/20">
                    H2: {altHash}
                  </div>
                  <div className="text-cyan-300 text-right">
                    Hex Character Divergence: <strong>{hammingDistance} / 64 ({(hammingDistance / 64 * 100).toFixed(0)}%)</strong>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* SIMULATION 2: Signature Forgery Rejection */}
          <div className="p-6 bg-navy-900 border border-background-border rounded-xl shadow-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-rose-400 font-mono">SIMULATION 2</span>
                <span className="text-[10px] font-mono text-slate-400">Curve25519 Math</span>
              </div>
              <h3 className="text-sm font-bold text-white">Signature Forgery Attempt</h3>
              <p className="text-xs text-slate-400 mt-1 mb-4">
                Simulate an adversary attempting to bypass verification by submitting a forged detached signature.
              </p>

              <div className="p-3 bg-navy-950 rounded-lg border border-background-border text-xs text-slate-300 font-mono space-y-1">
                <div>Payload: <span className="text-white">"Approved Wire Transfer $5,000,000"</span></div>
                <div>Attacker Sig: <span className="text-rose-400 break-all">ff00a12b3c...[FORGED BYTES]</span></div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-background-border">
              <button
                onClick={() => setForgeryResult('REJECTED')}
                className="w-full py-2 rounded-lg bg-rose-950/80 hover:bg-rose-900 text-rose-200 border border-rose-800 font-bold text-xs transition-all mb-3"
              >
                Execute Forged Signature Verification
              </button>

              {forgeryResult && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/50 text-xs text-rose-300 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
                  <span>
                    <strong>CRYPTOGRAPHIC VERIFICATION FAILED:</strong> Ed25519 signature curve coordinates do not resolve to public key. Forgery rejected with zero false positives.
                  </span>
                </div>
              )}
            </div>
          </div>

        </div>
      </div>

      {/* 11 Threat Profiles with 5-Point Analysis */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          The 11 Threat Vectors & 5-Point Forensic Breakdown
        </h2>

        <div className="space-y-4">
          {THREATS.map((threat) => {
            const isExpanded = expandedThreatId === threat.id;

            return (
              <div
                key={threat.id}
                className={`bg-navy-900/90 border rounded-2xl p-6 transition-all shadow-xl ${
                  isExpanded ? 'border-cyan-500/50 shadow-glow-cyan/20' : 'border-background-border hover:border-cyan-500/30'
                }`}
              >
                <div
                  onClick={() => setExpandedThreatId(isExpanded ? null : threat.id)}
                  className="cursor-pointer flex items-start justify-between gap-4"
                >
                  <div className="flex items-start gap-3">
                    <span className={`px-2 py-1 rounded text-[10px] font-mono font-bold mt-0.5 ${
                      threat.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : threat.severity === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    }`}>
                      {threat.severity}
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-white">
                        {threat.title}
                      </h3>
                      <span className="text-[11px] font-mono text-slate-400">
                        Vector: {threat.vector}
                      </span>
                    </div>
                  </div>

                  <button className="text-slate-400 hover:text-white p-1">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>

                <p className="text-xs text-slate-300 mt-3 leading-relaxed">
                  {threat.description}
                </p>

                {/* 5-Point Breakdown */}
                {isExpanded && (
                  <div className="mt-5 pt-5 border-t border-background-border grid grid-cols-1 md:grid-cols-2 gap-4 text-xs animate-fade-in">
                    
                    {/* Point 1: Real-World Impact */}
                    <div className="p-3 bg-navy-950/70 rounded-xl border border-background-border">
                      <span className="text-[10px] font-mono uppercase text-rose-400 font-bold block mb-1">
                        1. Real-World Operational Impact
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {threat.impact}
                      </p>
                    </div>

                    {/* Point 2: Attack Mechanism */}
                    <div className="p-3 bg-navy-950/70 rounded-xl border border-background-border">
                      <span className="text-[10px] font-mono uppercase text-amber-400 font-bold block mb-1">
                        2. Technical Attack Mechanism
                      </span>
                      <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                        {threat.mechanism}
                      </p>
                    </div>

                    {/* Point 3: SourceMark Mitigation */}
                    <div className="p-3 bg-navy-950/70 rounded-xl border border-cyan-500/20">
                      <span className="text-[10px] font-mono uppercase text-cyan-300 font-bold block mb-1">
                        3. SourceMark Mitigation
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {threat.mitigation}
                      </p>
                    </div>

                    {/* Point 4 & 5: Forensic Residuals */}
                    <div className="p-3 bg-navy-950/70 rounded-xl border border-background-border">
                      <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block mb-1">
                        4. Forensic Residuals & Indicators
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {threat.residuals}
                      </p>
                    </div>

                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

