#!/usr/bin/env python3
"""
Test ZTA policies with OPA
"""

import requests
import json

OPA_URL = "http://localhost:8181/v1/data/zta/main"


def test_policy(auth_method, user_role, resource_classification):
    """Test a policy scenario"""

    input_data = {
        "input": {
            "user": {
                "role": user_role,
                "clearance": "TOP_SECRET",
                "email": "admin@mod.gov",
                "department": "MOD",
                "facility": "MOD",
            },
            "resource": {
                "type": "document",
                "classification": resource_classification,
                "facility": "MOD",
                "department": "MOD",
            },
            "action": "read",
            "authentication": {
                "method": auth_method,
                "certificate": {
                    "issuer": {"organizationName": "Government ZTA"},
                    "subject": {"emailAddress": "admin@mod.gov"},
                    "keyUsage": {"clientAuth": True},
                    "not_valid_before": "2024-01-01T00:00:00Z",
                    "not_valid_after": "2025-12-31T23:59:59Z",
                },
            },
            "environment": {"time": {"hour": 14, "weekend": False}},
        }
    }

    response = requests.post(OPA_URL, json=input_data)
    result = response.json()

    print(f"\nTest: {auth_method} | {user_role} | {resource_classification}")
    print(f"Allowed: {result.get('result', {}).get('allow', False)}")
    print(f"Reason: {result.get('result', {}).get('reason', 'No reason')}")
    print(
        f"Auth Strength: {result.get('result', {}).get('authentication', {}).get('strength', 0)}"
    )

    return result.get("result", {}).get("allow", False)


if __name__ == "__main__":
    print("=" * 60)
    print("ZTA Policy Tests")
    print("=" * 60)

    # Test different authentication methods
    tests = [
        ("mTLS_JWT", "admin", "SECRET"),
        ("mTLS_JWT", "admin", "TOP_SECRET"),
        ("mTLS_service", "service", "CONFIDENTIAL"),
        ("JWT", "user", "BASIC"),
        ("JWT", "user", "SECRET"),  # Should fail - needs mTLS
    ]

    for test in tests:
        test_policy(*test)

    print("\n" + "=" * 60)
    print("Tests complete!")
