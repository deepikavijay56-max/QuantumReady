# test_crypto.py
# QuantumReady Demo File — Contains intentionally vulnerable cryptographic code
# This file is for TESTING PURPOSES ONLY

import hashlib
import ssl
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

# ── RSA KEY GENERATION (VULNERABLE) ───────────────────────────────────────────
# RSA is broken by Shor's Algorithm on quantum computers
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# ── ECC KEY GENERATION (VULNERABLE) ───────────────────────────────────────────
# Elliptic Curve Cryptography is also broken by Shor's Algorithm
def generate_ecc_keypair():
    key = ECC.generate(curve='P-256')
    return key

# ── MD5 HASHING (VULNERABLE) ──────────────────────────────────────────────────
# MD5 has known collision attacks — never use for security
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# ── SHA1 HASHING (VULNERABLE) ─────────────────────────────────────────────────
# SHA-1 collision demonstrated in 2017 (SHAttered attack)
def hash_data_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

# ── DIFFIE-HELLMAN (VULNERABLE) ───────────────────────────────────────────────
# DiffieHellman key exchange broken by Shor's Algorithm
def simulate_dh_exchange():
    # Simulating Diffie-Hellman key exchange
    p = 23  # prime
    g = 5   # generator
    return p, g

# ── WEAK TLS (VULNERABLE) ─────────────────────────────────────────────────────
# TLS 1.0 deprecated by RFC 8996
def create_weak_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx

# ── AES (LOW RISK — flagged for key size review) ──────────────────────────────
# AES-128 weakened by Grover's Algorithm — use AES-256 instead
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== QuantumReady Demo — Vulnerable Crypto ===")

    # RSA
    priv, pub = generate_rsa_keypair()
    print(f"RSA Key generated: {len(priv)} bytes")

    # MD5
    h = hash_password_md5("password123")
    print(f"MD5 hash: {h}")

    # SHA1
    s = hash_data_sha1("hello world")
    print(f"SHA1 hash: {s}")

    print("All vulnerable operations complete.")
    print("Run QuantumReady to detect these vulnerabilities!")