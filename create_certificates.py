#!/usr/bin/env python3
"""
Certificate Generation Script for ZTA Government System
USES FULL PATH TO OPENSSL - No PATH variable needed
"""

import os
import subprocess
import json
from datetime import datetime, timedelta

# ========== CONFIGURATION ==========
# SET THIS TO YOUR OPENSSL PATH (from your test)
OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
CERT_DIR = "./certs"
# ===================================


def run_openssl(args):
    """Execute OpenSSL command with full path"""
    cmd = [OPENSSL_PATH] + args
    cmd_str = " ".join(cmd)
    print(f"  Running: {cmd_str}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"  Exception: {e}")
        return False


def generate_certificates():
    """Generate all necessary certificates"""
    print("=" * 60)
    print("ZTA Government System - Certificate Generation")
    print("=" * 60)

    # Verify OpenSSL exists
    if not os.path.exists(OPENSSL_PATH):
        print(f"\n❌ ERROR: OpenSSL not found at: {OPENSSL_PATH}")
        print("Please update OPENSSL_PATH in this script")
        return False

    print(f"✓ Using OpenSSL at: {OPENSSL_PATH}")
    os.makedirs(CERT_DIR, exist_ok=True)

    # 1. Generate Root CA
    print("\n1. Generating Root Certificate Authority...")

    # Generate CA key
    if not run_openssl(["genrsa", "-out", f"{CERT_DIR}/ca.key", "4096"]):
        print("Failed to generate CA key")
        return False

    # Generate CA certificate
    ca_args = [
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        f"{CERT_DIR}/ca.key",
        "-sha256",
        "-days",
        "3650",
        "-out",
        f"{CERT_DIR}/ca.crt",
        "-subj",
        "/C=GB/ST=England/L=London/O=Government ZTA/CN=ZTA Root CA",
    ]

    if not run_openssl(ca_args):
        print("Failed to generate CA certificate")
        return False

    print("✓ Root CA created")

    # 2. Generate Server Certificate
    print("\n2. Generating Server Certificate...")

    # Generate server key
    if not run_openssl(["genrsa", "-out", f"{CERT_DIR}/server.key", "2048"]):
        return False

    # Create CSR
    csr_args = [
        "req",
        "-new",
        "-key",
        f"{CERT_DIR}/server.key",
        "-out",
        f"{CERT_DIR}/server.csr",
        "-subj",
        "/C=GB/ST=England/L=London/O=Government Ministry/CN=localhost",
    ]

    if not run_openssl(csr_args):
        return False

    # Create extensions file
    ext_content = """authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = zta-server.gov
IP.1 = 127.0.0.1
"""

    with open(f"{CERT_DIR}/server.ext", "w") as f:
        f.write(ext_content)

    # Sign certificate
    sign_args = [
        "x509",
        "-req",
        "-in",
        f"{CERT_DIR}/server.csr",
        "-CA",
        f"{CERT_DIR}/ca.crt",
        "-CAkey",
        f"{CERT_DIR}/ca.key",
        "-CAcreateserial",
        "-out",
        f"{CERT_DIR}/server.crt",
        "-days",
        "365",
        "-sha256",
        "-extfile",
        f"{CERT_DIR}/server.ext",
    ]

    if not run_openssl(sign_args):
        return False

    print("✓ Server certificate created")

    # 3. Generate Client Certificates
    print("\n3. Generating Client Certificates...")

    # Test users
    test_users = [
        {
            "id": 1,
            "email": "superadmin@nsa.gov",
            "department": "NSA",
            "username": "superadmin",
        },
        {
            "id": 2,
            "email": "admin@mod.gov",
            "department": "MOD",
            "username": "admin_mod",
        },
        {"id": 3, "email": "user@mof.gov", "department": "MOF", "username": "user_mof"},
    ]

    certificates_generated = 0

    for user in test_users:
        user_dir = f"{CERT_DIR}/clients/{user['id']}"
        os.makedirs(user_dir, exist_ok=True)

        print(f"\n  Generating certificate for {user['email']}...")

        # Generate client key
        if not run_openssl(["genrsa", "-out", f"{user_dir}/client.key", "2048"]):
            continue

        # Create CSR
        csr_args = [
            "req",
            "-new",
            "-key",
            f"{user_dir}/client.key",
            "-out",
            f"{user_dir}/client.csr",
            "-subj",
            f"/C=GB/ST=England/L=London/O=Government {user['department']}/CN={user['email']}/emailAddress={user['email']}",
        ]

        if not run_openssl(csr_args):
            continue

        # Create extensions file
        ext_content = f"""[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
C = GB
ST = England
L = London
O = Government {user['department']}
CN = {user['email']}
emailAddress = {user['email']}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = email:{user['email']}
"""

        with open(f"{user_dir}/client.ext", "w") as f:
            f.write(ext_content)

        # Sign certificate
        sign_args = [
            "x509",
            "-req",
            "-in",
            f"{user_dir}/client.csr",
            "-CA",
            f"{CERT_DIR}/ca.crt",
            "-CAkey",
            f"{CERT_DIR}/ca.key",
            "-CAcreateserial",
            "-out",
            f"{user_dir}/client.crt",
            "-days",
            "365",
            "-sha256",
            "-extfile",
            f"{user_dir}/client.ext",
            "-extensions",
            "v3_req",
        ]

        if not run_openssl(sign_args):
            continue

        # Create PKCS12 bundle (optional)
        p12_args = [
            "pkcs12",
            "-export",
            "-out",
            f"{user_dir}/client.p12",
            "-inkey",
            f"{user_dir}/client.key",
            "-in",
            f"{user_dir}/client.crt",
            "-certfile",
            f"{CERT_DIR}/ca.crt",
            "-passout",
            "pass:password123",
        ]
        run_openssl(p12_args)  # Don't fail if this doesn't work

        # Create metadata
        metadata = {
            "user_id": user["id"],
            "email": user["email"],
            "department": user["department"],
            "username": user["username"],
            "issued_date": datetime.now().isoformat(),
            "expiry_date": (datetime.now() + timedelta(days=365)).isoformat(),
            "paths": {
                "key": f"{user_dir}/client.key",
                "cert": f"{user_dir}/client.crt",
                "p12": f"{user_dir}/client.p12",
                "ca": f"{CERT_DIR}/ca.crt",
            },
        }

        with open(f"{user_dir}/metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        certificates_generated += 1
        print(f"    ✓ Certificate created")

    print("\n" + "=" * 60)
    print("✅ CERTIFICATE GENERATION COMPLETE")
    print("=" * 60)
    print(f"\nGenerated certificates for {certificates_generated} users")
    print("\n📁 Certificate files:")
    print(f"  • Root CA: {CERT_DIR}/ca.crt")
    print(f"  • Server Certificate: {CERT_DIR}/server.crt")
    print(f"  • Server Key: {CERT_DIR}/server.key")
    print(f"  • Client Certificates: {CERT_DIR}/clients/[1,2,3]/")

    print("\n🚀 Next steps:")
    print("  1. Run: python run.py")
    print("  2. Test with PowerShell:")
    print(f'     curl --cert "{CERT_DIR}/clients/1/client.crt" ^')
    print(f'          --key "{CERT_DIR}/clients/1/client.key" ^')
    print(f'          --cacert "{CERT_DIR}/ca.crt" ^')
    print(f"          https://localhost:5000/api/documents")

    # Also show a quick test command
    print("\n🔍 Quick test:")
    print(f'python -c "import ssl; print("SSL available")"')

    return True


if __name__ == "__main__":
    generate_certificates()
