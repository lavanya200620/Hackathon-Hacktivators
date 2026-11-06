/**
 * SourceMark Forensic Intelligence Scoring Engine
 * Rule-based forensic triage score (0-100) evaluating 8 distinct verification vectors.
 * 
 * DISCLAIMER: This is a rule-based forensic triage score, NOT a probability 
 * that a file is fake or malicious. Missing metadata alone is never treated as proof of tampering.
 */

export function computeForensicScore({
  hashMatched,
  signatureValid,
  registryFound,
  keyStatus = 'ACTIVE',
  checkpointIntegrity = 'VALID',
  metadataConsistency = 'CONSISTENT',
  provenanceHistoryDepth = 4,
  isAuthorizedDerivative = false,
  isUnauthorizedDerivative = false,
  signingKeyAgeDays = 30,
}) {
  let score = 0;
  const checks = [];
  const deductions = [];
  const recommendations = [];

  // 1. SHA-256 Hash Integrity (Max 25 pts)
  if (hashMatched) {
    score += 25;
    checks.push({
      vector: 'Cryptographic Hash Match',
      points: 25,
      maxPoints: 25,
      status: 'PASS',
      description: 'Bitstream exact SHA-256 fingerprint matches registered master record.',
    });
  } else if (isAuthorizedDerivative) {
    score += 20;
    checks.push({
      vector: 'Cryptographic Hash Match',
      points: 20,
      maxPoints: 25,
      status: 'PASS',
      description: 'Hash divergence tracked and attributed to authorized derivative transformation.',
    });
  } else {
    deductions.push('SHA-256 hash divergence from registered source baseline (-25 pts)');
    recommendations.push('Inspect visual pixel-level or line-level variance using Digital Tamper Analysis.');
    checks.push({
      vector: 'Cryptographic Hash Match',
      points: 0,
      maxPoints: 25,
      status: 'FAIL',
      description: 'Submitted content hash does not match the registered baseline hash.',
    });
  }

  // 2. Ed25519 Digital Signature Validity (Max 25 pts)
  if (signatureValid) {
    score += 25;
    checks.push({
      vector: 'Ed25519 Signature Validity',
      points: 25,
      maxPoints: 25,
      status: 'PASS',
      description: 'Curve25519 digital signature verified mathematically with registered public key.',
    });
  } else {
    deductions.push('Ed25519 signature missing or mathematically invalid (-25 pts)');
    recommendations.push('Re-verify signer public key identity and check for signature forgery.');
    checks.push({
      vector: 'Ed25519 Signature Validity',
      points: 0,
      maxPoints: 25,
      status: 'FAIL',
      description: 'Digital signature did not pass detached asymmetric curve verification.',
    });
  }

  // 3. Signing Key Trust Status (Max 15 pts)
  if (keyStatus === 'ACTIVE' || keyStatus === 'PRE_COMPROMISE_VALID') {
    score += 15;
    checks.push({
      vector: 'Signing Key Status',
      points: 15,
      maxPoints: 15,
      status: 'PASS',
      description: keyStatus === 'PRE_COMPROMISE_VALID' 
        ? 'Signed prior to key compromise date with verified pre-breach timestamp.' 
        : 'Signing key is active, uncompromised, and validly anchored.',
    });
  } else if (keyStatus === 'REPLACED') {
    score += 10;
    checks.push({
      vector: 'Signing Key Status',
      points: 10,
      maxPoints: 15,
      status: 'WARNING',
      description: 'Key was rotated under scheduled protocol. Legacy signatures preserved.',
    });
    deductions.push('Signing key has been superseded by rotated key (-5 pts)');
  } else if (keyStatus === 'COMPROMISED' || keyStatus === 'REVOKED' || keyStatus === 'POST_COMPROMISE_BREACH') {
    score += 0;
    deductions.push('CRITICAL: Originating signing key is marked as COMPROMISED / REVOKED (-15 pts)');
    recommendations.push('Correlate registration timestamp with known key compromise timestamp in Key Security Centre.');
    checks.push({
      vector: 'Signing Key Status',
      points: 0,
      maxPoints: 15,
      status: 'CRITICAL',
      description: 'Signer key has been compromised or revoked due to security breach.',
    });
  } else {
    // Missing or unavailable key status
    score += 0;
    deductions.push('Signing key status information is missing, uncatalogued, or undetermined (-15 pts)');
    recommendations.push('Investigate public key registry in Key Security Centre to catalogue authority credentials.');
    checks.push({
      vector: 'Signing Key Status',
      points: 0,
      maxPoints: 15,
      status: 'WARNING',
      description: 'Key status unverified or unavailable in trust catalog.',
    });
  }

  // 4. Checkpoint & Rollback Integrity (Max 15 pts)
  if (checkpointIntegrity === 'VALID') {
    score += 15;
    checks.push({
      vector: 'Checkpoint Rollback Integrity',
      points: 15,
      maxPoints: 15,
      status: 'PASS',
      description: 'Ledger block validated against independently sealed checkpoint.',
    });
  } else if (checkpointIntegrity === 'CHECKPOINT_MISSING' || checkpointIntegrity === 'UNAVAILABLE') {
    score += 7;
    deductions.push('Preserved external checkpoint not available for cross-verification (-8 pts)');
    recommendations.push('Generate a periodic checkpoint in Checkpoint Monitor.');
    checks.push({
      vector: 'Checkpoint Rollback Integrity',
      points: 7,
      maxPoints: 15,
      status: 'WARNING',
      description: 'Independent rollback checkpoint is missing or unavailable.',
    });
  } else {
    score += 0;
    deductions.push('CRITICAL: Checkpoint divergence or ledger truncation detected – possible rollback attack (-15 pts)');
    recommendations.push('Initiate Rollback Recovery workflow immediately to inspect truncated blocks.');
    checks.push({
      vector: 'Checkpoint Rollback Integrity',
      points: 0,
      maxPoints: 15,
      status: 'CRITICAL',
      description: 'Current ledger state does not match sealed checkpoint.',
    });
  }

  // 5. Derivative Authorization Check (Penalty if unauthorized)
  if (isUnauthorizedDerivative) {
    deductions.push('Unauthorized derivative transformation detected without custodian approval (-15 pts)');
    recommendations.push('Verify whether derivative modifications were approved by original asset creator.');
    checks.push({
      vector: 'Derivative Authorization Status',
      points: 0,
      maxPoints: 10,
      status: 'FAIL',
      description: 'Transformation is not registered as an authorized derivative version.',
    });
  }

  // 6. Metadata Consistency (Max 10 pts)
  if (metadataConsistency === 'CONSISTENT') {
    score += 10;
    checks.push({
      vector: 'Metadata Consistency',
      points: 10,
      maxPoints: 10,
      status: 'PASS',
      description: 'File headers, dimensions, and temporal timestamps correlate logically.',
    });
  } else if (metadataConsistency === 'STRIPPED' || metadataConsistency === 'INCOMPLETE') {
    score += 6;
    deductions.push('EXIF / header metadata is stripped or absent (-4 pts)');
    recommendations.push('Advisory Note: Messaging and privacy tools commonly strip EXIF; missing metadata alone is not conclusive evidence of tampering.');
    checks.push({
      vector: 'Metadata Consistency',
      points: 6,
      maxPoints: 10,
      status: 'NEUTRAL',
      description: 'EXIF metadata stripped or missing (advisory observation, not conclusive tampering proof).',
    });
  } else {
    score += 3;
    deductions.push('Inconsistency detected between filesystem timestamps and image header metadata (-7 pts)');
    recommendations.push('Review Metadata Intelligence module for editing software markers.');
    checks.push({
      vector: 'Metadata Consistency',
      points: 3,
      maxPoints: 10,
      status: 'WARNING',
      description: 'Software modification stamps or temporal contradictions observed.',
    });
  }

  // 7. Provenance History Depth & Audit Chain (Max 10 pts)
  if (registryFound && provenanceHistoryDepth >= 3) {
    score += 10;
    checks.push({
      vector: 'Provenance Chain Depth',
      points: 10,
      maxPoints: 10,
      status: 'PASS',
      description: 'Record has comprehensive multi-event custody history in immutable ledger.',
    });
  } else if (registryFound) {
    score += 7;
    checks.push({
      vector: 'Provenance Chain Depth',
      points: 7,
      maxPoints: 10,
      status: 'PASS',
      description: 'Source registered; limited post-registration audit inquiries recorded.',
    });
  } else {
    deductions.push('Uncatalogued file without prior provenance record (-10 pts)');
    recommendations.push('Register this file to anchor an authoritative zero-knowledge baseline.');
    checks.push({
      vector: 'Provenance Chain Depth',
      points: 0,
      maxPoints: 10,
      status: 'FAIL',
      description: 'No prior registration found in provenance registry.',
    });
  }

  // Determine Risk Level
  let riskLevel = 'Low';
  let riskColor = 'emerald';
  if (score >= 85) {
    riskLevel = 'Low Risk';
    riskColor = 'emerald';
    if (recommendations.length === 0) {
      recommendations.push('Asset is fully verified and suitable for official archive or legal submission.');
    }
  } else if (score >= 65) {
    riskLevel = 'Medium Risk';
    riskColor = 'cyan';
    recommendations.push('Correlate registration context and check for minor metadata or version warnings.');
  } else if (score >= 40) {
    riskLevel = 'High Risk';
    riskColor = 'amber';
    recommendations.push('Detailed forensic inspection recommended before treating as authentic.');
  } else {
    riskLevel = 'Critical Risk';
    riskColor = 'rose';
    recommendations.push('Integrity failure. Do not rely on content authenticity without primary evidence recovery.');
  }

  return {
    score: Math.max(0, Math.min(100, score)),
    riskLevel,
    riskColor,
    checks,
    deductions,
    recommendations,
    disclaimer: 'This score is a rules-based forensic triage indicator, NOT a probability of forgery or fraud. Missing metadata alone is never treated as proof of tampering.',
    evaluatedAt: new Date().toISOString(),
  };
}

export const forensicScoreService = {
  calculateScore({ sourceRecord, hashMatch = true, signatureValid = true, hasMetadata = true, isCompromisedKey = false }) {
    return computeForensicScore({
      hashMatched: hashMatch,
      signatureValid: signatureValid,
      registryFound: !!sourceRecord,
      keyStatus: isCompromisedKey ? 'COMPROMISED' : 'ACTIVE',
      metadataConsistency: hasMetadata ? 'CONSISTENT' : 'INCOMPLETE',
      provenanceHistoryDepth: 4,
      isAuthorizedDerivative: false,
    });
  },
  computeForensicScore,
};
