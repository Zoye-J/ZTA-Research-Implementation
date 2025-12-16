#!/usr/bin/env python3
"""
Test mTLS connection to the ZTA Government System
"""

import requests
import os
import json
import ssl
import urllib3

# Disable warnings for now
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_mtls_connection():
    """Test mTLS connection with client certificate"""

    cert_dir = "./certs"
    client_dir = os.path.join(cert_dir, "clients", "1")

    if not os.path.exists(client_dir):
        print("ERROR: Client certificates not found!")
        return False

    cert_file = os.path.join(client_dir, "client.crt")
    key_file = os.path.join(client_dir, "client.key")
    ca_cert = os.path.join(cert_dir, "ca.crt")

    print(f"Certificate: {cert_file}")
    print(f"Key: {key_file}")
    print(f"CA: {ca_cert}")

    try:
        # First test without certificate verification
        print("\n1. Testing without certificate verification...")
        response = requests.get(
            "https://localhost:5000/api/documents",
            verify=False,  # Skip certificate verification
        )
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:100]}...")

        # Then test with certificates
        print("\n2. Testing with client certificate...")
        response = requests.get(
            "https://localhost:5000/api/documents",
            cert=(cert_file, key_file),
            verify=ca_cert,
        )

        print(f"✅ Success! Status: {response.status_code}")
        print(f"Response: {response.text}")
        return True

    except requests.exceptions.SSLError as e:
        print(f"\n❌ SSL Error details:")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Message: {str(e)}")

        # Try with verify=False to see if it's just a cert issue
        print("\nTrying with verify=False...")
        try:
            response = requests.get(
                "https://localhost:5000/api/documents",
                cert=(cert_file, key_file),
                verify=False,
            )
            print(f"   With verify=False: Status {response.status_code}")
            print(f"   This suggests certificate verification issue")
        except Exception as e2:
            print(f"   Still failing: {e2}")

        return False

    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        return False


def test_direct_connection():
    """Test if server is running"""
    print("\n" + "=" * 40)
    print("Checking if server is running...")

    try:
        # Try HTTP first
        response = requests.get("http://localhost:5000/", timeout=2, verify=False)
        print(f"HTTP: Status {response.status_code}")
    except:
        print("HTTP: Not responding")

    try:
        # Try HTTPS
        response = requests.get("https://localhost:5000/", timeout=2, verify=False)
        print(f"HTTPS: Status {response.status_code}")
        return True
    except Exception as e:
        print(f"HTTPS: Error - {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("ZTA Government System - mTLS Test")
    print("=" * 60)

    # First check if server is running
    if not test_direct_connection():
        print("\n⚠ Server may not be running!")
        print("Run in another terminal: python run.py")
        print("Then run this test again.")
    else:
        # Test mTLS
        print("\n" + "=" * 40)
        print("Testing mTLS connection...")
        test_mtls_connection()

    print("\n" + "=" * 60)
    input("Press Enter to exit...")
