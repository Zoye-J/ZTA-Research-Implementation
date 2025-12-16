"""
mTLS Middleware for Flask
Extracts and validates client certificates
"""

from flask import request, jsonify, current_app
from functools import wraps
from app.mTLS.cert_manager import cert_manager
import base64


def extract_client_certificate():
    """Extract client certificate from request"""
    # Try different ways to get the certificate
    cert_pem = None

    # Method 1: From SSL environment variable
    if "SSL_CLIENT_CERT" in request.environ:
        cert_pem = request.environ["SSL_CLIENT_CERT"]

    # Method 2: From header (for proxy setups)
    elif "X-SSL-Client-Cert" in request.headers:
        # Certificate might be URL-encoded
        import urllib.parse

        cert_encoded = request.headers["X-SSL-Client-Cert"]
        cert_pem = urllib.parse.unquote(cert_encoded).replace("\t", "\n")

    # Method 3: From custom header
    elif "X-Client-Certificate" in request.headers:
        cert_b64 = request.headers["X-Client-Certificate"]
        cert_pem = base64.b64decode(cert_b64).decode("utf-8")

    return cert_pem


def require_mtls(f):
    """
    Decorator that requires mTLS authentication
    Falls back to JWT if certificate not present
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if mTLS is enabled in config
        if not current_app.config.get("MTLS_ENABLED", True):
            # mTLS not required, proceed with JWT
            return f(*args, **kwargs)

        # Extract certificate
        cert_pem = extract_client_certificate()

        if not cert_pem:
            current_app.logger.warning("No client certificate provided")

            # For admin endpoints, require certificate
            if request.path.startswith("/api/admin"):
                return (
                    jsonify(
                        {
                            "error": "Client certificate required for admin access",
                            "code": "CERTIFICATE_REQUIRED",
                        }
                    ),
                    401,
                )

            # For regular endpoints, fall back to JWT
            current_app.logger.info("Falling back to JWT authentication")
            return f(*args, **kwargs)

        # Validate certificate
        is_valid, result = cert_manager.validate_certificate(cert_pem)

        if not is_valid:
            current_app.logger.warning(f"Invalid certificate: {result}")
            return (
                jsonify(
                    {
                        "error": "Invalid client certificate",
                        "details": str(result),
                        "code": "INVALID_CERTIFICATE",
                    }
                ),
                401,
            )

        # Certificate is valid, check if revoked
        cert_info = result
        if cert_manager.is_certificate_revoked(cert_info["serial_number"]):
            current_app.logger.warning(
                f"Revoked certificate: {cert_info['serial_number']}"
            )
            return (
                jsonify(
                    {
                        "error": "Certificate has been revoked",
                        "code": "CERTIFICATE_REVOKED",
                    }
                ),
                401,
            )

        # Add certificate info to request for use in route
        request.client_certificate = cert_info

        # Log successful mTLS authentication
        email = cert_info["subject"].get("emailAddress", "Unknown")
        current_app.logger.info(f"mTLS authentication successful for {email}")

        return f(*args, **kwargs)

    return decorated_function


def require_admin_certificate(f):
    """
    Decorator that requires admin certificate
    Strict requirement - no fallback to JWT
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract and validate certificate
        cert_pem = extract_client_certificate()

        if not cert_pem:
            return (
                jsonify(
                    {
                        "error": "Admin certificate required",
                        "code": "ADMIN_CERTIFICATE_REQUIRED",
                    }
                ),
                401,
            )

        # Validate certificate
        is_valid, result = cert_manager.validate_certificate(cert_pem)

        if not is_valid:
            return (
                jsonify({"error": "Invalid admin certificate", "details": str(result)}),
                401,
            )

        # Check for admin email domain
        cert_info = result
        email = cert_info["subject"].get("emailAddress", "")

        # Only @nsa.gov or @admin.gov emails for admin access
        if not any(domain in email for domain in ["@nsa.gov", "@admin.gov"]):
            return (
                jsonify(
                    {
                        "error": "Insufficient certificate privileges",
                        "code": "INSUFFICIENT_PRIVILEGES",
                    }
                ),
                403,
            )

        request.client_certificate = cert_info
        return f(*args, **kwargs)

    return decorated_function
