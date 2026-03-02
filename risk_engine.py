"""
risk_engine.py — QuantumReady Risk Assessment Engine v2.0

What's improved:
  ✅ Added CRITICAL risk level (was missing — only had High/Medium/Low)
  ✅ Quantum-safe CODE EXAMPLES for every vulnerability
  ✅ NIST standard references for every recommendation
  ✅ Timeline info (when does this become dangerous?)
  ✅ File-level AND project-level risk scores
  ✅ Severity counts (critical/high/medium totals)
"""

from typing import Dict, Any, List


# ─── QUANTUM-SAFE FIX DATABASE ────────────────────────────────
QUANTUM_SAFE_FIXES = {
    'RSA': {
        'recommendation': 'Replace RSA with CRYSTALS-Kyber (encryption) or CRYSTALS-Dilithium (signatures)',
        'nist_standard': 'NIST FIPS 203 (Kyber) / NIST FIPS 204 (Dilithium)',
        'timeline': 'URGENT — RSA breaks by 2030 via Shor\'s Algorithm',
        'code_before': 'from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)',
        'code_after': '# pip install liboqs-python\nimport oqs\nkem = oqs.KeyEncapsulation("Kyber512")\npublic_key = kem.generate_keypair()',
    },
    'ECC': {
        'recommendation': 'Replace ECC with CRYSTALS-Dilithium for digital signatures',
        'nist_standard': 'NIST FIPS 204 (Dilithium)',
        'timeline': 'URGENT — ECC breaks by 2030 via Shor\'s Algorithm',
        'code_before': 'from Crypto.PublicKey import ECC\nkey = ECC.generate(curve="P-256")',
        'code_after': 'import oqs\nsig = oqs.Signature("Dilithium3")\npublic_key = sig.generate_keypair()',
    },
    'MD5': {
        'recommendation': 'Replace MD5 with SHA3-256 for hashing, or Argon2 for passwords',
        'nist_standard': 'NIST FIPS 202 (SHA-3)',
        'timeline': 'IMMEDIATE — MD5 is broken on classical computers already',
        'code_before': 'import hashlib\nhash_val = hashlib.md5(data).hexdigest()',
        'code_after': 'import hashlib\nhash_val = hashlib.sha3_256(data).hexdigest()\n\n# For passwords use Argon2:\nfrom argon2 import PasswordHasher\nph = PasswordHasher()\nhashed = ph.hash(password)',
    },
    'SHA1': {
        'recommendation': 'Replace SHA1 with SHA3-256 — collision-resistant and quantum-safe',
        'nist_standard': 'NIST FIPS 202 (SHA-3)',
        'timeline': 'IMMEDIATE — SHA1 collisions demonstrated (SHAttered, 2017)',
        'code_before': 'import hashlib\nhash_val = hashlib.sha1(data).hexdigest()',
        'code_after': 'import hashlib\nhash_val = hashlib.sha3_256(data).hexdigest()',
    },
    'DiffieHellman': {
        'recommendation': 'Replace Diffie-Hellman with CRYSTALS-Kyber key encapsulation',
        'nist_standard': 'NIST FIPS 203 (Kyber)',
        'timeline': 'URGENT — DH key exchange breaks by 2030 via Shor\'s Algorithm',
        'code_before': '# Old DH key exchange\nDiffieHellman.generateKey()',
        'code_after': 'import oqs\nkem = oqs.KeyEncapsulation("Kyber768")\npublic_key = kem.generate_keypair()\nciphertext, shared_secret = kem.encap_secret(public_key)',
    },
    'WeakRSAKeySize': {
        'recommendation': 'Migrate away from RSA entirely — key size cannot save it from Shor\'s Algorithm',
        'nist_standard': 'NIST FIPS 203 (Kyber)',
        'timeline': 'URGENT — RSA of any key size breaks against quantum computers',
        'code_before': 'key = RSA.generate(1024)  # Dangerously small',
        'code_after': 'import oqs\nkem = oqs.KeyEncapsulation("Kyber512")\npublic_key = kem.generate_keypair()',
    },
    'WeakTLS': {
        'recommendation': 'Enforce TLS 1.3 minimum — removes all quantum-weak cipher suites',
        'nist_standard': 'NIST SP 800-52 Rev. 2',
        'timeline': 'IMMEDIATE — TLS 1.0/1.1 deprecated by RFC 8996 (2021)',
        'code_before': 'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)',
        'code_after': 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.minimum_version = ssl.TLSVersion.TLSv1_3\nctx.verify_mode = ssl.CERT_REQUIRED',
    },
    'KeyPairGenerator': {
        'recommendation': 'Verify key algorithm — if RSA or EC, replace with post-quantum alternative',
        'nist_standard': 'NIST FIPS 203/204',
        'timeline': 'REVIEW NEEDED — depends on which algorithm is used',
        'code_before': 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        'code_after': '// Java BouncyCastle PQC\nKeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");\nkpg.initialize(new DilithiumParameterSpec(DilithiumParameterSpec.dilithium3));',
    },
    'AES': {
        'recommendation': 'Use AES-256-GCM — Grover\'s Algorithm halves key strength so AES-128 → 64-bit security',
        'nist_standard': 'NIST FIPS 197 (AES)',
        'timeline': 'LOW PRIORITY — AES-256 remains secure against quantum computers',
        'code_before': 'AES.new(key_128bit, AES.MODE_CBC)',
        'code_after': 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\nkey = os.urandom(32)  # 256-bit\naesgcm = AESGCM(key)\nnonce = os.urandom(12)\nciphertext = aesgcm.encrypt(nonce, plaintext, None)',
    },
}

# Risk hierarchy for comparison
RISK_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

# Map vulnerability type → risk level
VULN_RISK_MAP = {
    'RSA': 'CRITICAL', 'ECC': 'CRITICAL',
    'DiffieHellman': 'CRITICAL', 'WeakRSAKeySize': 'CRITICAL',
    'MD5': 'HIGH', 'SHA1': 'HIGH', 'WeakTLS': 'HIGH',
    'KeyPairGenerator': 'MEDIUM', 'AES': 'LOW',
}


def classify_risk(matches: List[str]) -> Dict[str, Any]:
    """Classify file risk level from a list of vulnerability matches."""
    if any(m in ('RSA', 'ECC', 'DiffieHellman', 'WeakRSAKeySize') for m in matches):
        risk = 'CRITICAL'
    elif any(m in ('MD5', 'SHA1', 'WeakTLS') for m in matches):
        risk = 'HIGH'
    elif any(m in ('KeyPairGenerator', 'AES') for m in matches):
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    recommendations = []
    seen = set()
    for m in matches:
        if m in QUANTUM_SAFE_FIXES and m not in seen:
            seen.add(m)
            fix = QUANTUM_SAFE_FIXES[m]
            recommendations.append({
                'vulnerability': m,
                'recommendation': fix['recommendation'],
                'nist_standard': fix['nist_standard'],
                'timeline': fix['timeline'],
                'code_before': fix['code_before'],
                'code_after': fix['code_after'],
            })

    return {'risk': risk, 'reasons': matches, 'recommendations': recommendations}


def analyze_findings(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Full project-level analysis from scanner output."""
    files = findings.get('files', [])
    analyzed_files = []

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    highest_risk = 'LOW'

    for f in files:
        matches = f.get('matches', [])
        line_findings = f.get('findings', [])
        result = classify_risk(matches)

        risk = result['risk']
        counts[risk] = counts.get(risk, 0) + 1
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(highest_risk, 0):
            highest_risk = risk

        # Build flat recommendation text for backward compat
        rec_text = '; '.join(r['recommendation'] for r in result['recommendations']) or 'No changes required.'

        analyzed_files.append({
            'path': f.get('path'),
            'matches': matches,
            'findings': line_findings,
            'score': f.get('score', 100),
            'label': f.get('label', 'SAFE'),
            'analysis': {
                'risk': risk,
                'reasons': matches,
                'recommendation': rec_text,
                'recommendations': result['recommendations'],
            }
        })

    return {
        'overall_risk': highest_risk,
        'overall_score': findings.get('overall_score', 100),
        'overall_label': findings.get('overall_label', 'SAFE'),
        'files': analyzed_files,
        'summary': findings.get('summary', {}),
        'counts': counts,
        'total_findings': findings.get('total_findings', 0),
    }


if __name__ == '__main__':
    import json
    sample = {
        'files': [
            {'path': 'auth.py', 'matches': ['RSA', 'MD5'], 'findings': [], 'score': 35, 'label': 'CRITICAL RISK'},
            {'path': 'utils.py', 'matches': ['SHA1'], 'findings': [], 'score': 65, 'label': 'MODERATE RISK'},
        ],
        'summary': {'RSA': 1, 'MD5': 1, 'SHA1': 1},
        'overall_score': 35,
        'overall_label': 'CRITICAL RISK',
        'total_findings': 3,
    }
    print(json.dumps(analyze_findings(sample), indent=2))