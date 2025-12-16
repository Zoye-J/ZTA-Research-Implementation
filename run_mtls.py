#!/usr/bin/env python3
"""
ZTA Government System - mTLS Enabled Server
Run with: python run_mtls.py
"""

import ssl
import sys
import os
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app


def setup_ssl_context():
    """Create SSL context for mTLS"""

    # Certificate paths
    cert_dir = Path("./certs")
    ca_cert = cert_dir / "ca.crt"
    server_cert = cert_dir / "server.crt"
    server_key = cert_dir / "server.key"

    # Check if certificates exist
    if not ca_cert.exists():
        print(f"ERROR: CA certificate not found at {ca_cert}")
        print("Please run: python create_certificates.py")
        sys.exit(1)

    if not server_cert.exists():
        print(f"ERROR: Server certificate not found at {server_cert}")
        print("Please run: python create_certificates.py")
        sys.exit(1)

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificates
    context.check_hostname = False

    # Load server certificate
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))

    # Load CA certificate for client verification
    context.load_verify_locations(cafile=str(ca_cert))

    # Set strong cipher suites
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    print(f"✓ SSL context created with mTLS enabled")
    print(f"  CA Certificate: {ca_cert}")
    print(f"  Server Certificate: {server_cert}")
    print(f"  Client certificate required: YES")

    return context


def main():
    """Main function to run the mTLS server"""

    print("=" * 60)
    print("ZTA Government System - mTLS Enabled Server")
    print("=" * 60)

    # Create app with production config (which has MTLS_ENABLED=True)
    app = create_app("production")

    if app.config.get("MTLS_ENABLED"):
        # Create SSL context
        ssl_context = setup_ssl_context()

        # Run with mTLS
        print("\nStarting mTLS server...")
        print(f"Server URL: https://localhost:8443")
        print(f"API Base URL: https://localhost:8443/api/")
        print("\nClient certificates are REQUIRED for access.")
        print("Use curl command with --cert and --key flags.")

        app.run(
            host="0.0.0.0",
            port=8443,
            ssl_context=ssl_context,
            debug=False,
            threaded=True,
        )
    else:
        print("ERROR: mTLS not enabled in configuration!")
        print("Set MTLS_ENABLED = True in ProductionConfig")
        sys.exit(1)


if __name__ == "__main__":
    main()
