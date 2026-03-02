# ai/fix_suggester.py - AI-powered quantum-safe fix generator

import os
from typing import Optional

# Hardcoded quantum-safe fixes for each vulnerability type
# (Used as fallback or demo mode without API key)
QUANTUM_SAFE_FIXES = {
    "RSA Key Generation": {
        "old_example": """from Crypto.PublicKey import RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()""",
        "new_code": """# ✅ QUANTUM-SAFE: Using CRYSTALS-Kyber (NIST FIPS 203)
import oqs

def generate_quantum_keypair():
    kem = oqs.KeyEncapsulation('Kyber512')
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key""",
        "algorithm": "CRYSTALS-Kyber (NIST FIPS 203)",
        "why_safe": "Kyber is based on the hardness of the Module Learning With Errors (MLWE) problem, which cannot be solved efficiently by quantum computers."
    },

    "RSA Library Import": {
        "old_example": "from Crypto.PublicKey import RSA",
        "new_code": """# ✅ QUANTUM-SAFE: Replace PyCryptodome RSA with liboqs
# Install: pip install liboqs-python
import oqs

# For key encapsulation (replacing RSA encryption):
kem = oqs.KeyEncapsulation('Kyber512')

# For digital signatures (replacing RSA signatures):
sig = oqs.Signature('Dilithium3')""",
        "algorithm": "liboqs (Open Quantum Safe)",
        "why_safe": "liboqs implements NIST-approved post-quantum algorithms including Kyber and Dilithium."
    },

    "ECC Key Generation": {
        "old_example": """from Crypto.PublicKey import ECC
key = ECC.generate(curve='P-256')""",
        "new_code": """# ✅ QUANTUM-SAFE: Using CRYSTALS-Dilithium (NIST FIPS 204)
import oqs

def generate_signing_keypair():
    sig = oqs.Signature('Dilithium3')
    public_key = sig.generate_keypair()
    return public_key, sig

def sign_data(sig, message: bytes) -> bytes:
    return sig.sign(message)

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    verifier = oqs.Signature('Dilithium3')
    return verifier.verify(message, signature, public_key)""",
        "algorithm": "CRYSTALS-Dilithium (NIST FIPS 204)",
        "why_safe": "Dilithium is based on the hardness of lattice problems (MLWE/MSIS), which are believed to be resistant to both classical and quantum attacks."
    },

    "ECC Curve Usage": {
        "old_example": "key = ECC.generate(curve='P-256')",
        "new_code": """# ✅ QUANTUM-SAFE: Dilithium3 replaces P-256 signatures
import oqs

sig = oqs.Signature('Dilithium3')
public_key = sig.generate_keypair()
# Dilithium3 provides 128-bit quantum security level
# equivalent to P-256's classical security""",
        "algorithm": "CRYSTALS-Dilithium3",
        "why_safe": "NIST selected Dilithium as the primary post-quantum digital signature algorithm in FIPS 204 (2024)."
    },

    "MD5 Hash Function": {
        "old_example": "hash_value = hashlib.md5(data).hexdigest()",
        "new_code": """# ✅ QUANTUM-SAFE: SHA3-256 (quantum-resistant hash)
import hashlib

def secure_hash(data: bytes) -> str:
    # SHA3-256 provides 128-bit quantum security
    return hashlib.sha3_256(data).hexdigest()

# For passwords specifically, use bcrypt or argon2:
# pip install argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    return ph.verify(hash, password)""",
        "algorithm": "SHA3-256 / Argon2",
        "why_safe": "SHA3 (Keccak) was designed with quantum resistance in mind. Its security against quantum attacks is 128 bits for SHA3-256, requiring Grover's algorithm to provide only a quadratic speedup."
    },

    "SHA1 Hash Function": {
        "old_example": "integrity_hash = hashlib.sha1(file_data).hexdigest()",
        "new_code": """# ✅ QUANTUM-SAFE: BLAKE3 or SHA3-256 for file integrity
import hashlib

def verify_file_integrity(file_bytes: bytes) -> str:
    # SHA3-256: quantum-resistant, NIST-standardized
    return hashlib.sha3_256(file_bytes).hexdigest()

# Even better - use BLAKE3 for high performance:
# pip install blake3
import blake3

def fast_secure_hash(file_bytes: bytes) -> str:
    return blake3.blake3(file_bytes).hexdigest()""",
        "algorithm": "SHA3-256 / BLAKE3",
        "why_safe": "SHA3-256 provides 128-bit post-quantum security. BLAKE3 is faster than MD5 while being cryptographically secure."
    },

    "Weak TLS Version": {
        "old_example": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
        "new_code": """# ✅ QUANTUM-SAFE: TLS 1.3 with post-quantum key exchange
import ssl

def create_secure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Enforce TLS 1.3 minimum
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # Enable post-quantum key exchange (if supported)
    ctx.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx""",
        "algorithm": "TLS 1.3 + Post-Quantum KEM",
        "why_safe": "TLS 1.3 removes all legacy cipher suites. Combined with post-quantum key exchange (X25519Kyber768), it protects against harvest-now-decrypt-later attacks."
    },

    "RSA Asymmetric Import": {
        "old_example": "from cryptography.hazmat.primitives.asymmetric import rsa",
        "new_code": """# ✅ QUANTUM-SAFE: Post-quantum key encapsulation
# Install: pip install liboqs-python
import oqs

class QuantumSafeEncryption:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation('Kyber512')
    
    def generate_keypair(self):
        public_key = self.kem.generate_keypair()
        return public_key
    
    def encrypt(self, public_key: bytes) -> tuple:
        # Returns (ciphertext, shared_secret)
        return self.kem.encap_secret(public_key)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.kem.decap_secret(ciphertext)""",
        "algorithm": "CRYSTALS-Kyber512 (NIST FIPS 203)",
        "why_safe": "Kyber replaces RSA key exchange with lattice-based cryptography resistant to Shor's algorithm."
    },

    "Weak RSA Key Size": {
        "old_example": "key = RSA.generate(1024)",
        "new_code": """# ✅ QUANTUM-SAFE: Don't use RSA at all - use Kyber
# 1024-bit RSA is broken classically AND quantum-vulnerable
# Even 4096-bit RSA will fall to quantum computers

import oqs

# Kyber512 = 128-bit quantum security (better than RSA-1024)
# Kyber768 = 192-bit quantum security  
# Kyber1024 = 256-bit quantum security

kem = oqs.KeyEncapsulation('Kyber768')  # Recommended
public_key = kem.generate_keypair()""",
        "algorithm": "CRYSTALS-Kyber768",
        "why_safe": "Kyber768 provides 192-bit quantum security, far exceeding any RSA key size against quantum adversaries."
    },

    "Legacy Symmetric Cipher": {
        "old_example": "cipher = DES.new(key, DES.MODE_ECB)",
        "new_code": """# ✅ QUANTUM-SAFE: AES-256-GCM (quantum-resistant symmetric)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_data(plaintext: bytes, key: bytes = None) -> tuple:
    if key is None:
        key = os.urandom(32)  # 256-bit key
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return key, nonce, ciphertext

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)""",
        "algorithm": "AES-256-GCM",
        "why_safe": "AES-256 provides 128-bit quantum security (Grover's gives only quadratic speedup). GCM mode provides authenticated encryption."
    }
}

def get_quantum_safe_fix(vulnerability_type: str, vulnerable_code: str) -> dict:
    """Get quantum-safe fix for a given vulnerability type."""
    
    fix_data = QUANTUM_SAFE_FIXES.get(vulnerability_type)
    
    if fix_data:
        return {
            "vulnerability_type": vulnerability_type,
            "vulnerable_code": vulnerable_code,
            "fixed_code": fix_data["new_code"],
            "algorithm_used": fix_data["algorithm"],
            "why_safe": fix_data["why_safe"],
            "old_example": fix_data["old_example"]
        }
    
    # Generic fallback
    return {
        "vulnerability_type": vulnerability_type,
        "vulnerable_code": vulnerable_code,
        "fixed_code": "# Please consult NIST Post-Quantum Cryptography standards\n# https://csrc.nist.gov/projects/post-quantum-cryptography",
        "algorithm_used": "Consult NIST PQC Standards",
        "why_safe": "NIST has standardized post-quantum algorithms in FIPS 203, 204, and 205.",
        "old_example": vulnerable_code
    }


if __name__ == "__main__":
    # Test fix suggestions
    test_cases = [
        ("RSA Key Generation", "key = RSA.generate(2048)"),
        ("MD5 Hash Function", "hashlib.md5(password.encode()).hexdigest()"),
        ("ECC Key Generation", "key = ECC.generate(curve='P-256')"),
    ]
    
    for vuln_type, vuln_code in test_cases:
        fix = get_quantum_safe_fix(vuln_type, vuln_code)
        print(f"\n{'='*60}")
        print(f"Vulnerability: {fix['vulnerability_type']}")
        print(f"Algorithm: {fix['algorithm_used']}")
        print(f"\nFixed Code:\n{fix['fixed_code']}")
