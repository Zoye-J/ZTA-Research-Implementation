from flask import Blueprint, request, jsonify, render_template
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from app import db
from app.models.user import User, AccessLog
from app.logs.request_logger import log_request
import datetime

auth_bp = Blueprint("auth", __name__)


# Home/Landing page
@auth_bp.route("/")
def home():
    return render_template("login.html")


# Login page (GET)
@auth_bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


# Login API (POST)
@auth_bp.route("/login", methods=["POST"])
def login_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Find user
        user = User.query.filter_by(username=username).first()

        if not user:
            log_request(
                user_id=None,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User not found",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.is_active:
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User account inactive",
            )
            return jsonify({"error": "Account is inactive"}), 401

        # Check password
        if not user.check_password(password):
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="Invalid password",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        # Create JWT tokens
        additional_claims = {
            "user_class": user.user_class,
            "department": user.department,
            "facility": user.facility,
            "clearance_level": user.clearance_level,
            "is_superadmin": user.user_class == "superadmin",
            "is_admin": user.user_class in ["admin", "superadmin"],
        }

        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims,
            expires_delta=datetime.timedelta(hours=8),
        )

        refresh_token = create_refresh_token(
            identity=user.id, additional_claims=additional_claims
        )

        # Log successful login
        log_request(
            user_id=user.id,
            endpoint="/login",
            method="POST",
            status="allowed",
            reason="Authentication successful",
        )

        return (
            jsonify(
                {
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user.to_dict(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Login failed", "message": str(e)}), 500


# Token refresh
@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        additional_claims = {
            "user_class": user.user_class,
            "department": user.department,
            "facility": user.facility,
            "clearance_level": user.clearance_level,
            "is_superadmin": user.user_class == "superadmin",
            "is_admin": user.user_class in ["admin", "superadmin"],
        }

        new_access_token = create_access_token(
            identity=current_user_id, additional_claims=additional_claims
        )

        return jsonify({"access_token": new_access_token}), 200

    except Exception as e:
        return jsonify({"error": "Token refresh failed", "message": str(e)}), 500


# Logout - client-side only (just remove token)
@auth_bp.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "Logout successful (client should remove token)"}), 200


# Dashboard - handle both web and API access
@auth_bp.route("/dashboard", methods=["GET"])
def dashboard():
    # Check for Authorization header (API access)
    auth_header = request.headers.get("Authorization")

    if auth_header and auth_header.startswith("Bearer "):
        # This is an API call with JWT token
        @jwt_required()
        def protected_dashboard():
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)

            if not user:
                return jsonify({"error": "User not found"}), 404

            return jsonify({"user": user.to_dict(), "message": "Welcome to dashboard"})

        return protected_dashboard()

    else:
        # This is a web browser request - serve HTML template
        return render_template("dashboard.html")


# Simple registration page
@auth_bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


# Other routes (documents, users, etc.) - update to use JWT instead of sessions
@auth_bp.route("/documents", methods=["GET"])
@jwt_required()
def documents_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return render_template("documents.html")


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
def users_list_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Check admin privileges in JWT claims
    claims = get_jwt()
    if not claims.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403

    return render_template("users_list.html")


@auth_bp.route("/register-user", methods=["GET"])
@jwt_required()
def register_user_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Check admin privileges
    claims = get_jwt()
    if not claims.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403

    return render_template("register_user.html")
