from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    # Use SSL for development (for mTLS testing later)
    ssl_context = None
    cert_path = "./certs"

    # Check if certificates exist for SSL
    if os.path.exists(f"{cert_path}/server.crt") and os.path.exists(
        f"{cert_path}/server.key"
    ):
        ssl_context = (f"{cert_path}/server.crt", f"{cert_path}/server.key")
        print("✓ SSL certificates found, running with HTTPS")
    else:
        print("⚠ No SSL certificates found, running with HTTP")
        print("  Run 'python create_certs.py' to generate certificates")

    app.run(debug=True, port=5000, host="0.0.0.0", ssl_context=ssl_context)
