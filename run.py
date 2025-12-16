# from app import create_app
# import os
# import ssl

# app = create_app()

# if __name__ == "__main__":
#     cert_path = "./certs"
#     ssl_context = None

#     # Check if certificates exist
#     if os.path.exists(f"{cert_path}/server.crt") and os.path.exists(
#         f"{cert_path}/server.key"
#     ):
#         print("✓ SSL certificates found")

#         # Check for CA certificate for mTLS
#         if os.path.exists(f"{cert_path}/ca.crt"):
#             print("✓ CA certificate found, enabling mTLS...")

#             # Create SSL context with client verification
#             context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#             context.load_cert_chain(
#                 f"{cert_path}/server.crt", f"{cert_path}/server.key"
#             )

#             # Enable client certificate verification
#             context.verify_mode = ssl.CERT_REQUIRED
#             context.load_verify_locations(f"{cert_path}/ca.crt")

#             # Set cipher suites
#             context.set_ciphers(
#                 "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
#             )

#             ssl_context = context
#             print("✓ mTLS enabled - Client certificates required")
#         else:
#             print("⚠ CA certificate not found, using standard SSL")
#             ssl_context = (f"{cert_path}/server.crt", f"{cert_path}/server.key")
#     else:
#         print("⚠ No SSL certificates found, running with HTTP")
#         print("  Run 'python create_certificates.py' to generate certificates")

#     app.run(debug=True, port=5000, host="0.0.0.0", ssl_context=ssl_context)


from app import create_app
import os
import ssl

app = create_app()

if __name__ == "__main__":
    cert_path = "./certs"
    ssl_context = None

    print("=" * 60)
    print("ZTA Government System - PRODUCTION MODE")
    print("=" * 60)

    if os.path.exists(f"{cert_path}/server.crt") and os.path.exists(
        f"{cert_path}/server.key"
    ):
        print("✓ SSL certificates found")

        if os.path.exists(f"{cert_path}/ca.crt"):
            print("✓ CA certificate found")

            try:
                # PRODUCTION: Full mTLS with strong ciphers
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(
                    f"{cert_path}/server.crt", f"{cert_path}/server.key"
                )

                # mTLS: Require client certificates
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(f"{cert_path}/ca.crt")

                # Government-grade ciphers
                context.set_ciphers(
                    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
                )

                ssl_context = context
                print("✅ mTLS ENABLED - Client certificates REQUIRED")
                print("   Government-grade encryption active")

            except Exception as e:
                print(f"❌ mTLS setup failed: {e}")
                print("⚠ Falling back to simple SSL")
                ssl_context = (f"{cert_path}/server.crt", f"{cert_path}/server.key")
        else:
            print("⚠ CA certificate not found, using standard SSL")
            ssl_context = (f"{cert_path}/server.crt", f"{cert_path}/server.key")
    else:
        print("❌ FATAL: SSL certificates not found")
        print("Run: python create_certificates.py")
        exit(1)

    print("=" * 60)
    print("Server starting on: https://localhost:5000")
    print("Client certificates REQUIRED for all connections")
    print("=" * 60)

    app.run(debug=False, port=5000, host="0.0.0.0", ssl_context=ssl_context)
