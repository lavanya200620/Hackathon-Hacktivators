import React, { useState } from 'react';
import {
  BookOpen,
  Cpu,
  Key,
  Boxes,
  Lock,
  RotateCcw,
  FileSearch,
  GitBranch,
  ShieldCheck,
  QrCode,
  Award,
  Database,
  ArrowRight,
  CheckCircle,
  AlertTriangle,
  Play,
  Search,
  Sparkles,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { calculateSHA256, getOrCreateKeyPair, signHash, verifySignature, bufferToHex } from '../services/crypto';

const CONCEPTS = [
  {
    id: 'sha256',
    title: '1. Cryptographic Hash Functions (SHA-256)',
    icon: Cpu,
    category: 'Foundations',
    summary: 'A one-way cryptographic hash function transforms arbitrary-sized input bytes into a fixed 256-bit hexadecimal digest.',
    keyPoints: [
      'Deterministic: The same byte sequence will always produce the exact same 64-character hex hash.',
      'Pre-image Resistance: Computationally infeasible to reverse or deduce the original file from the hash.',
      'Avalanche Effect: Modifying a single bit in a 10 GB file flips roughly 50% of the resulting digest bits.',
      'Collision Resistance: No two distinct files have ever been found with identical SHA-256 digests in human history.',
    ],
    mathNote: 'SHA-256 operates on 512-bit message blocks with 64 rounds of bitwise logic (Ch, Maj, \\Sigma, \\sigma).',
  },
  {
    id: 'ed25519',
    title: '2. Asymmetric Digital Signatures (Ed25519)',
    icon: Key,
    category: 'Foundations',
    summary: 'Curve25519-based Edwards-curve digital signature algorithm providing tamper-proofing and non-repudiation.',
    keyPoints: [
      'Public/Private Key Pair: The private key signs the SHA-256 digest; anyone can verify using the public key.',
      'Non-Repudiation: Proves mathematically that the registered creator signed the exact bitstream.',
      'High Security & Speed: 128-bit security level resisting timing attacks with minimal CPU overhead.',
      'Collision Immunity: Signature generation is deterministic and does not rely on weak random number generators.',
    ],
    mathNote: 'Operates over Twisted Edwards Curve -x^2 + y^2 = 1 - (121665/121666)x^2 y^2 modulo 2^{255}-19.',
  },
  {
    id: 'ledger',
    title: '3. Append-Only Audit Ledgers & Hash Chaining',
    icon: Boxes,
    category: 'Architecture',
    summary: 'Each ledger event references the cryptographic hash of the previous event, forming an immutable hash chain.',
    keyPoints: [
      'Temporal Ordering: Events are permanently sequenced; time cannot be rearranged without breaking hashes.',
      'Tamper Evident: Altering any past block invalidates every downstream block hash in the entire chain.',
      'Cryptographic Continuity: Verification software walks backwards from tip to genesis to guarantee chain integrity.',
      'WORM Principle: Write-Once-Read-Many architecture prevents silent in-place database row updates.',
    ],
    mathNote: 'Block_n = SHA-256(Block_{n-1} Hash || Timestamp || Action || Payload Hash).',
  },
  {
    id: 'rollback',
    title: '4. Rollback & Truncation Protection',
    icon: RotateCcw,
    category: 'Security',
    summary: 'Techniques to prevent malicious operators from silently truncating recent ledger events or resetting state.',
    keyPoints: [
      'Truncation Threat: An adversary with root database privileges drops recent blocks to erase proof of registration.',
      'WORM Anchoring: State snapshots are independently mirrored to immutable cold storage (e.g. AWS S3 Object Lock).',
      'Watchdog Detection: Verifiers query external checkpoints; if active height is less than checkpoint, alarm fires.',
      'Automated Incident Logging: Generates structured digital forensics reports with exact missing transaction counts.',
    ],
    mathNote: 'Integrity Rule: Live Ledger Height >= Sealed Checkpoint Height AND Cumulative Root == Checkpoint Root.',
  },
  {
    id: 'key-security',
    title: '5. Key Compromise & Revocation Lifecycle',
    icon: Lock,
    category: 'Security',
    summary: 'Governance protocols for handling stolen signing keys and evaluating retroactive signature validity.',
    keyPoints: [
      'Public Key Registry: Authoritative directory mapping public keys to verified human identities and HSMs.',
      'Compromise Flagging: Stolen keys are immediately marked COMPROMISED; signature math alone is not enough.',
      'Retroactive Partitioning: Signatures before the breach remain valid; signatures after are invalidated.',
      'Emergency Rotation: Smooth migration to fresh Ed25519 keys with explicit parent-key lineage.',
    ],
    mathNote: 'Verification Predicate: Valid(Sig) AND Status(Key) == ACTIVE AND Time(Tx) < CompromisedDate.',
  },
  {
    id: 'metadata',
    title: '6. Metadata Forensics vs Bitstream Verification',
    icon: FileSearch,
    category: 'Forensics',
    summary: 'Why metadata is advisory context and must never be treated as the sole proof of file authenticity.',
    keyPoints: [
      'Metadata Volatility: EXIF tags can be stripped by chat apps (WhatsApp, Slack) or forged in seconds.',
      'Bitstream Rigor: SHA-256 measures literal file bytes, unaffected by operating system file rename or copying.',
      'Anomaly Detection: Software stamps (Photoshop/GIMP) and timestamp inversions offer investigative leads.',
      'Balanced Triage: Missing EXIF reduces confidence score slightly, but never yields a false "Malicious" verdict.',
    ],
    mathNote: 'Authenticity Guarantee: Bitstream Hash = Immutable Truth; EXIF Headers = Auxiliary Clues.',
  },
  {
    id: 'derivatives',
    title: '7. Legitimate Re-saves vs Malicious Forgeries',
    icon: GitBranch,
    category: 'Forensics',
    summary: 'Differentiating innocent creative re-compression and redactions from deceptive adversarial alterations.',
    keyPoints: [
      'The Bit-Flip Dilemma: Compressing an image to WebP changes 100% of the SHA-256 hash.',
      'Author Attribution: Authorized creators register derivative versions with signed justification tokens.',
      'Lineage Trees: The system maps parent master files (v1.0) to approved distribution derivatives (v1.1, v1.2).',
      'Contextual Verdicts: Displays AUTHORIZED DERIVATIVE instead of alarming users with false TAMPERED alerts.',
    ],
    mathNote: 'Derivative Proof: Master Sig + Child Sig + Signed Transformation Manifest.',
  },
  {
    id: 'forensic-score',
    title: '8. Forensic Intelligence Scoring Methodology',
    icon: ShieldCheck,
    category: 'Intelligence',
    summary: 'Rule-based, explainable 0–100 forensic triage score across eight orthogonal security vectors.',
    keyPoints: [
      'Explainable AI/Rules: Transparent point deductions rather than an unexplainable "black-box" neural network.',
      'Eight Vectors: Hash Match (35pts), Signature (30pts), Registry (10pts), Key (10pts), Ledger (5pts), etc.',
      'Actionable Recommendations: Offers clear next operational steps (e.g. "Re-sign with rotated HSM key").',
      'Risk Classification: Categorizes into Low (90-100), Medium (70-89), High (40-69), and Critical (0-39).',
    ],
    mathNote: 'Score = 100 - \\sum (Vector Deductions). Not a subjective fake probability.',
  },
  {
    id: 'qr-codes',
    title: '9. QR Code Verification Architecture',
    icon: QrCode,
    category: 'Architecture',
    summary: 'Tamper-evident verification tokens designed for mobile field scanners and physical media printouts.',
    keyPoints: [
      'Privacy Preservation: Barcodes never contain private keys, proprietary algorithms, or raw confidential files.',
      'Structured Payload: Encodes Source ID, SHA-256 digest, creator, timestamp, and verification server endpoint.',
      'Cross-Validation: The scanner recalculates the file hash on the target device to ensure payload matches.',
      'Offline Capability: Digital signatures inside the QR can be verified offline against cached public keys.',
    ],
    mathNote: 'Payload Envelope: JSON { protocol: "SOURCEMARK-V1", sourceId, sha256, signature, ts }.',
  },
  {
    id: 'iso27037',
    title: '10. Digital Evidence Admissibility (ISO/IEC 27037)',
    icon: Award,
    category: 'Legal & Standards',
    summary: 'Guidelines for identification, collection, acquisition, and preservation of digital evidence.',
    keyPoints: [
      'Chain of Custody: Unbroken, auditable log tracking every party who handled or verified the evidence item.',
      'Repeatability: Any independent forensic lab running SHA-256 on the evidence must obtain the exact same hash.',
      'Evidentiary Certificates: Structured PDF jurats combining hashes, cryptographic timestamps, and author identities.',
      'Demonstration Disclaimer: Clear labeling preventing mock academic tools from masquerading as sworn affidavits.',
    ],
    mathNote: 'Standards Alignment: ISO/IEC 27037, NIST SP 800-86, RFC 3161 Timestamp Protocol.',
  },
  {
    id: 'merkle',
    title: '11. Merkle Trees & Cryptographic Accumulators',
    icon: Database,
    category: 'Foundations',
    summary: 'Hierarchical tree of hashes enabling efficient and secure verification of massive ledger states.',
    keyPoints: [
      'Logarithmic Proofs: Verify an entry in a 1,000,000 block ledger using only ~20 cryptographic hashes (O(log n)).',
      'Root Sealing: A single 32-byte Merkle Root mathematically encapsulates every transaction in the entire database.',
      'Inclusion Proof: Third-party auditors can verify a specific file is registered without downloading the full ledger.',
      'Consensus Ready: Provides foundational primitives for multi-organization digital provenance consortia.',
    ],
    mathNote: 'Merkle Parent = SHA-256(Left Child Hash || Right Child Hash).',
  },
  {
    id: 'mitm',
    title: '12. Man-in-the-Middle & Registry Spoofing',
    icon: AlertTriangle,
    category: 'Security',
    summary: 'Protecting clients against DNS poisoning, proxy injection, and rogue provenance registries.',
    keyPoints: [
      'Adversary Objective: Intercept verification queries and return false "Verified" signals for malicious forgeries.',
      'End-to-End Cryptography: Client recalculates SHA-256 locally and verifies Ed25519 signatures in WebAssembly/JS.',
      'Certificate Pinning: Production applications pin TLS certificates and use decentralized hash anchors.',
      'Zero-Trust Client: The browser never relies on blind server promises; mathematical proof is computed locally.',
    ],
    mathNote: 'Defense Formula: Client-side Hashing + Local Ed25519 Math = Zero Server Trust Requirement.',
  },
];

export default function LearnExplore() {
  const [selectedConcept, setSelectedConcept] = useState(CONCEPTS[0]);
  const [expandedId, setExpandedId] = useState(CONCEPTS[0].id);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('ALL');

  // Interactive Pipeline Simulator State
  const [simText, setSimText] = useState('Confidential SourceMark Digital Asset Briefing 2026');
  const [simHash, setSimHash] = useState('');
  const [simSignature, setSimSignature] = useState('');
  const [simVerified, setSimVerified] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const categories = ['ALL', 'Foundations', 'Architecture', 'Security', 'Forensics', 'Intelligence', 'Legal & Standards'];

  const filteredConcepts = CONCEPTS.filter((c) => {
    const matchesCat = activeCategory === 'ALL' || c.category === activeCategory;
    const matchesQuery = searchQuery === '' ||
      c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.summary.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesQuery;
  });

  // Run Pipeline Simulator
  const handleRunSimulator = async () => {
    setIsSimulating(true);
    setSimHash('');
    setSimSignature('');
    setSimVerified(null);

    // Step 1: Calculate SHA-256
    const blob = new Blob([simText], { type: 'text/plain' });
    const hash = await calculateSHA256(blob);
    setSimHash(hash);

    // Step 2: Sign with local Ed25519 key
    const sig = signHash(hash);
    setSimSignature(sig);

    // Step 3: Verify with public key
    const keyPair = getOrCreateKeyPair();
    const ok = verifySignature(hash, sig, keyPair.publicKey);
    setSimVerified(ok);

    setIsSimulating(false);
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <BookOpen className="w-4 h-4" />
            <span>Digital Forensics Academy</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Learn & Explore Centre
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Master the mathematical, architectural, and evidentiary principles powering modern digital content provenance and anti-tampering defenses.
          </p>
        </div>
      </div>

      {/* Interactive 4-Step Cryptographic Pipeline Simulator */}
      <div className="p-6 bg-navy-900 border-2 border-cyan-500/40 rounded-2xl shadow-2xl relative overflow-hidden">
        <div className="flex items-center justify-between pb-4 border-b border-background-border mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
              <Play className="w-5 h-5 text-cyan-accent" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                Live Interactive Cryptographic Pipeline Simulator
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Observe the atomic workflow: Input String → SHA-256 Digest → Ed25519 Signature → Verification
              </p>
            </div>
          </div>

          <button
            onClick={handleRunSimulator}
            disabled={isSimulating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs transition-all shadow-glow-cyan/50"
          >
            {isSimulating ? 'Computing...' : 'Run Pipeline'}
          </button>
        </div>

        {/* Input Bar */}
        <div className="space-y-4 mb-6">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">
              Step 1: Input Digital Bitstream (Try modifying any single character to see the avalanche effect)
            </label>
            <input
              type="text"
              value={simText}
              onChange={(e) => setSimText(e.target.value)}
              className="w-full bg-navy-950 border border-background-border rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Pipeline Step Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {/* Step 2: SHA-256 */}
          <div className="p-4 bg-navy-950/80 rounded-xl border border-background-border">
            <div className="flex items-center gap-2 text-cyan-accent font-mono uppercase text-[11px] mb-1 font-bold">
              <Cpu className="w-3.5 h-3.5" />
              <span>Step 2: SHA-256 Digest</span>
            </div>
            <p className="text-[10px] text-slate-400 mb-2">256-bit cryptographic digest calculated via WebCrypto.</p>
            <div className="p-2.5 bg-navy-900 rounded border border-background-border font-mono text-[11px] text-cyan-300 break-all min-h-[50px]">
              {simHash || <span className="text-slate-600">Awaiting execution...</span>}
            </div>
          </div>

          {/* Step 3: Ed25519 Signature */}
          <div className="p-4 bg-navy-950/80 rounded-xl border border-background-border">
            <div className="flex items-center gap-2 text-cyan-accent font-mono uppercase text-[11px] mb-1 font-bold">
              <Key className="w-3.5 h-3.5" />
              <span>Step 3: Ed25519 Signature</span>
            </div>
            <p className="text-[10px] text-slate-400 mb-2">Detached signature generated using Curve25519 private key.</p>
            <div className="p-2.5 bg-navy-900 rounded border border-background-border font-mono text-[10px] text-slate-300 break-all min-h-[50px]">
              {simSignature || <span className="text-slate-600">Awaiting execution...</span>}
            </div>
          </div>

          {/* Step 4: Verification Result */}
          <div className="p-4 bg-navy-950/80 rounded-xl border border-background-border flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 text-cyan-accent font-mono uppercase text-[11px] mb-1 font-bold">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Step 4: Public Key Verification</span>
              </div>
              <p className="text-[10px] text-slate-400 mb-2">Cryptographic verification against public key.</p>
            </div>
            <div className="p-2.5 bg-navy-900 rounded border border-background-border flex items-center justify-center min-h-[50px]">
              {simVerified === null ? (
                <span className="text-slate-600 font-mono text-xs">Awaiting execution...</span>
              ) : simVerified ? (
                <span className="flex items-center gap-1.5 text-emerald-400 font-mono font-bold text-xs">
                  <CheckCircle className="w-4 h-4" /> MATHEMATICALLY VALID
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-rose-400 font-mono font-bold text-xs">
                  <AlertTriangle className="w-4 h-4" /> VERIFICATION FAILED
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex flex-wrap gap-1.5">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                activeCategory === cat
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'bg-navy-900 text-slate-400 hover:text-slate-200 border border-background-border'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search concepts or topics..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-navy-900 border border-background-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* 12 Educational Concept Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {filteredConcepts.map((concept) => {
          const Icon = concept.icon;
          const isExpanded = expandedId === concept.id;

          return (
            <div
              key={concept.id}
              className={`bg-navy-900/90 border rounded-2xl p-6 transition-all shadow-xl ${
                isExpanded ? 'border-cyan-500/50 shadow-glow-cyan/20' : 'border-background-border hover:border-cyan-500/30'
              }`}
            >
              <div
                onClick={() => setExpandedId(isExpanded ? null : concept.id)}
                className="cursor-pointer flex items-start justify-between gap-3"
              >
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className="w-5 h-5 text-cyan-accent" />
                  </div>
                  <div>
                    <span className="text-[10px] font-mono uppercase text-cyan-400/80 tracking-wider">
                      {concept.category}
                    </span>
                    <h3 className="text-base font-bold text-white leading-snug">
                      {concept.title}
                    </h3>
                  </div>
                </div>

                <button className="text-slate-400 hover:text-white p-1">
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              <p className="text-xs text-slate-300 mt-3 leading-relaxed">
                {concept.summary}
              </p>

              {/* Expandable Deep Dive */}
              {isExpanded && (
                <div className="mt-4 pt-4 border-t border-background-border space-y-3 animate-fade-in text-xs">
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">
                      Core Forensic Properties
                    </span>
                    <ul className="space-y-1.5">
                      {concept.keyPoints.map((point, i) => (
                        <li key={i} className="flex items-start gap-2 text-slate-300 leading-relaxed">
                          <CheckCircle className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                          <span>{point}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {concept.mathNote && (
                    <div className="p-3 bg-navy-950 rounded-lg border border-background-border font-mono text-[11px] text-cyan-300/90">
                      <strong className="text-slate-400 block text-[9px] uppercase tracking-wider mb-0.5">
                        Mathematical Specification
                      </strong>
                      {concept.mathNote}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

