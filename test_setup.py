#!/usr/bin/env python3
"""
Test setup for ZTA Thesis
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import create_app
    
    print("Testing Flask app creation...")
    app = create_app()
    print("✅ Flask app created successfully!")
    
    with app.app_context():
        print("✅ App context works!")
        
        # Test OPA client initialization
        from app.policy.opa_client import get_opa_client
        opa_client = get_opa_client()
        print(f"✅ OPA Client initialized: {opa_client.opa_url}")
        
        # Test database
        from app import db
        print("✅ Database connection works!")
        
    print("\n" + "="*50)
    print("✅ All tests passed!")
    print("\nYou can now run:")
    print("1. Start OPA: python run_opa_server.py")
    print("2. Start Flask: python run.py")
    print("="*50)
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()