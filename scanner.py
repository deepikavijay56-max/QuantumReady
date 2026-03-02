"""
scanner.py — QuantumReady Static Analysis Engine v2.0

What's improved:
  ✅ Added MD5 detection (was completely missing!)
  ✅ Line-by-line scanning with exact line numbers
  ✅ Penalty scores per vulnerability type
  ✅ Weak RSA key size detection (512/1024-bit)
  ✅ Weak TLS detection
  ✅ False-positive reduction (skips comments)
  ✅ 8-feature ML vector (was 5)
  ✅ Overall score 0–100
"""

import os
import re
import zipfile
import tempfile
import shutil
from typing import Dict, List, Any, Tuple

# ─── VULNERABILITY PATTERNS ───────────────────────────────────
# Each entry: regex, risk level, score penalty, description, fix
VULNERABILITY_PATTERNS = {
    "RSA": {
        "pattern": re.compile(r"\bRSA\b|rsa\.generate|RSA\.generate|generate_private_key.*rsa", re.IGNORECASE),
        "risk": "CRITICAL", "penalty": 25,
        "description": "RSA is broken by Shor's Algorithm on quantum computers.",
        "fix": "Replace with CRYSTALS-Kyber512 (NIST FIPS 203)"
    },
    "ECC": {
        "pattern": re.compile(r"\bECC\b|elliptic.?curve|ec\.generate|ECC\.generate|curve=['\"]P-\d+|secp256k1", re.IGNORECASE),
        "risk": "CRITICAL", "penalty": 25,
        "description": "ECC is broken by Shor's Algorithm on quantum computers.",
        "fix": "Replace with CRYSTALS-Dilithium3 (NIST FIPS 204)"
    },
    "MD5": {
        "pattern": re.compile(r"\bMD5\b|hashlib\.md5|MessageDigest.*MD5|DigestUtils\.md5", re.IGNORECASE),
        "risk": "HIGH", "penalty": 15,
        "description": "MD5 has known collisions — never use for passwords or integrity.",
        "fix": "Replace with hashlib.sha3_256() or Argon2 for passwords"
    },
    "SHA1": {
        "pattern": re.compile(r"SHA[-_]?1\b|hashlib\.sha1|MessageDigest.*SHA.1", re.IGNORECASE),
        "risk": "HIGH", "penalty": 15,
        "description": "SHA1 collisions demonstrated (SHAttered, 2017).",
        "fix": "Replace with hashlib.sha3_256() (NIST FIPS 202)"
    },
    "DiffieHellman": {
        "pattern": re.compile(r"Diffie[- ]?Hellman|DHKeyPairGenerator|\bdh\b.*key", re.IGNORECASE),
        "risk": "CRITICAL", "penalty": 25,
        "description": "Diffie-Hellman key exchange broken by Shor's Algorithm.",
        "fix": "Replace with CRYSTALS-Kyber KEM (NIST FIPS 203)"
    },
    "WeakRSAKeySize": {
        "pattern": re.compile(r"RSA\.generate\(\s*(512|1024|2048)\s*\)|key.?size\s*=\s*(512|1024)", re.IGNORECASE),
        "risk": "CRITICAL", "penalty": 25,
        "description": "Weak RSA key — even 2048-bit breaks against quantum computers.",
        "fix": "Migrate to CRYSTALS-Kyber — key size does not save RSA from Shor's"
    },
    "WeakTLS": {
        "pattern": re.compile(r"PROTOCOL_TLSv1(?!_2|_3)|SSLv2|SSLv3", re.IGNORECASE),
        "risk": "HIGH", "penalty": 15,
        "description": "TLS 1.0/1.1 deprecated (RFC 8996). Multiple known attacks.",
        "fix": "Use ssl.TLSVersion.TLSv1_3 minimum"
    },
    "KeyPairGenerator": {
        "pattern": re.compile(r"KeyPairGenerator|generateKeyPair", re.IGNORECASE),
        "risk": "MEDIUM", "penalty": 8,
        "description": "KeyPairGenerator — verify algorithm is not RSA or EC.",
        "fix": "Check algorithm parameter; replace RSA/EC with post-quantum alternative"
    },
    "AES": {
        "pattern": re.compile(r"\bAES\b", re.IGNORECASE),
        "risk": "LOW", "penalty": 0,
        "description": "AES-256 remains safe. AES-128 is quantum-weakened by Grover's.",
        "fix": "Use AES-256-GCM (256-bit key gives 128-bit post-quantum security)"
    },
    "PQC": {
        "pattern": re.compile(r"Lattice|CRYSTALS|Kyber|Dilithium|NTRU|post.?quantum|PQC|quantum.?safe|SPHINCS", re.IGNORECASE),
        "risk": "SAFE", "penalty": 0,
        "description": "Post-quantum cryptography in use — good!",
        "fix": "No action needed."
    },
}

# For backward compat with app.py that uses KEYWORD_PATTERNS
KEYWORD_PATTERNS = {k: v["pattern"] for k, v in VULNERABILITY_PATTERNS.items()}

SUPPORTED_EXTENSIONS = {
    '.py', '.java', '.js', '.ts', '.jsx', '.tsx',
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.cs',
    '.go', '.rs', '.rb', '.php', '.swift', '.kt',
    '.txt', '.xml', '.json', '.yaml', '.yml', '.properties',
    '.scala', '.groovy'
}


def scan_text_with_lines(text: str) -> List[Dict[str, Any]]:
    """Scan text line-by-line and return detailed findings with line numbers."""
    findings = []
    seen = set()
    for line_num, line in enumerate(text.split('\n'), start=1):
        stripped = line.strip()
        # Skip blank lines and comments
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        for vuln_name, vuln_info in VULNERABILITY_PATTERNS.items():
            if vuln_info["risk"] == "SAFE":
                continue
            if vuln_info["pattern"].search(line):
                key = (line_num, vuln_name)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "line_number": line_num,
                        "line_content": line.rstrip(),
                        "vulnerability_type": vuln_name,
                        "risk": vuln_info["risk"],
                        "penalty": vuln_info["penalty"],
                        "description": vuln_info["description"],
                        "fix": vuln_info["fix"],
                    })
    return findings


def calculate_score(findings: List[Dict]) -> Tuple[int, str]:
    """Calculate QuantumReady score (0–100) and label from findings."""
    score = 100
    for f in findings:
        score -= f["penalty"]
    score = max(0, score)
    if score >= 80:
        label = "SAFE"
    elif score >= 60:
        label = "MODERATE RISK"
    elif score >= 40:
        label = "HIGH RISK"
    else:
        label = "CRITICAL RISK"
    return score, label


def scan_text(text: str) -> List[str]:
    """Quick scan — returns list of matched vulnerability names (no line info)."""
    matches = []
    for name, info in VULNERABILITY_PATTERNS.items():
        if info["risk"] == "SAFE":
            continue
        if info["pattern"].search(text):
            matches.append(name)
    return list(dict.fromkeys(matches))


def scan_file(file_path: str) -> Dict[str, Any]:
    """Scan a single file. Returns findings with line numbers + score."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return {"findings": [], "matches": [], "score": 100, "label": "SAFE"}

    findings = scan_text_with_lines(content)
    score, label = calculate_score(findings)
    matches = list(dict.fromkeys([f["vulnerability_type"] for f in findings]))
    return {"findings": findings, "matches": matches, "score": score, "label": label}


def scan_directory(root: str, exts=None) -> Dict[str, Any]:
    """Walk directory and scan all supported source files."""
    if exts is None:
        exts = SUPPORTED_EXTENSIONS

    files_result = []
    summary = {k: 0 for k in VULNERABILITY_PATTERNS.keys()}
    all_findings = []

    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            _, ext = os.path.splitext(fn)
            if ext.lower() not in exts:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace('\\', '/')
            result = scan_file(full)
            for m in result["matches"]:
                summary[m] = summary.get(m, 0) + 1
            all_findings.extend(result["findings"])
            files_result.append({
                'path': rel,
                'matches': result["matches"],
                'findings': result["findings"],
                'score': result["score"],
                'label': result["label"],
            })

    overall_score, overall_label = calculate_score(all_findings)
    return {
        'files': files_result,
        'summary': summary,
        'overall_score': overall_score,
        'overall_label': overall_label,
        'total_findings': len(all_findings),
    }


def scan_zip(zip_path: str, exts=None) -> Dict[str, Any]:
    """Extract ZIP and scan all files inside."""
    if exts is None:
        exts = SUPPORTED_EXTENSIONS
    tmpdir = tempfile.mkdtemp(prefix='quantumready_')
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(tmpdir)
        return scan_directory(tmpdir, exts=exts)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def extract_features(summary: Dict[str, int]) -> List[int]:
    """
    8-feature ML vector for the Random Forest model.
    Order: [RSA, ECC, MD5, SHA1, DiffieHellman, WeakTLS, AES, PQC]
    """
    keys = ['RSA', 'ECC', 'MD5', 'SHA1', 'DiffieHellman', 'WeakTLS', 'AES', 'PQC']
    return [1 if summary.get(k, 0) > 0 else 0 for k in keys]


if __name__ == '__main__':
    import json
    result = scan_directory('.')
    print(f"Score: {result['overall_score']}/100 — {result['overall_label']}")
    print(f"Total findings: {result['total_findings']}")
    for f in result['files']:
        if f['findings']:
            print(f"\n  {f['path']} (score: {f['score']}):")
            for finding in f['findings']:
                print(f"    Line {finding['line_number']}: [{finding['risk']}] {finding['vulnerability_type']}")
                print(f"      {finding['line_content'].strip()[:80]}")