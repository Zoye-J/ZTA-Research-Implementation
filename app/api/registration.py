from flask import Blueprint, request, jsonify
from app import db
from app.models.user import User
from werkzeug.security import generate_password_hash
from datetime import datetime
import re

registration_bp = Blueprint("registration", __name__)

# Email domain to facility mapping
DOMAIN_TO_FACILITY = {
    "mod.gov": "Ministry of Defence",
    "mof.gov": "Ministry of Finance",
    "nsa.gov": "National Security Agency",
}

# Email domain to default department mapping
DOMAIN_TO_DEFAULT_DEPT = {
    "mod.gov": "Operations",
    "mof.gov": "Budget",
    "nsa.gov": "Cyber Security",
}


@registration_bp.route("/register", methods=["POST"])
def register_user():
    try:
        data = request.get_json()
        print("Registration data received:", data)

        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate required fields
        required_fields = ["full_name", "email", "username", "password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        email = data["email"].lower()
        username = data["username"].lower()

        # Extract domain from email
        domain_match = re.search(r"@([a-zA-Z0-9.-]+)$", email)
        if not domain_match:
            return jsonify({"error": "Invalid email format"}), 400

        domain = domain_match.group(1)

        # Check if domain is allowed
        if domain not in DOMAIN_TO_FACILITY:
            return (
                jsonify(
                    {
                        "error": "Unauthorized email domain",
                        "message": f'Only government email domains are allowed: {", ".join(DOMAIN_TO_FACILITY.keys())}',
                    }
                ),
                400,
            )

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already taken"}), 400

        # Validate password strength
        password = data["password"]
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        if not re.search(r"[A-Z]", password):
            return (
                jsonify(
                    {"error": "Password must contain at least one uppercase letter"}
                ),
                400,
            )

        if not re.search(r"[a-z]", password):
            return (
                jsonify(
                    {"error": "Password must contain at least one lowercase letter"}
                ),
                400,
            )

        if not re.search(r"\d", password):
            return jsonify({"error": "Password must contain at least one number"}), 400

        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            return (
                jsonify(
                    {"error": "Password must contain at least one special character"}
                ),
                400,
            )

        # Get facility and department from domain
        facility = DOMAIN_TO_FACILITY[domain]
        department = DOMAIN_TO_DEFAULT_DEPT[domain]

        print(f"Creating user: {username}")
        print(f"Email: {email}")
        print(f"Facility: {facility}")
        print(f"Department: {department}")

        # Create new user
        new_user = User(
            username=username,
            email=email,
            user_class="user",  # Regular user by default
            facility=facility,
            department=department,
            clearance_level="BASIC",
            is_active=True,
            created_at=datetime.utcnow(),
        )

        # Set password with proper hashing
        new_user.password_hash = generate_password_hash(password)
        print(f"Password hashed successfully")

        db.session.add(new_user)
        db.session.commit()

        print(f"User {username} created with ID: {new_user.id}")

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Registration successful! You can now login.",
                    "user": {
                        "id": new_user.id,
                        "username": new_user.username,
                        "email": new_user.email,
                        "user_class": new_user.user_class,
                        "facility": new_user.facility,
                        "department": new_user.department,
                        "clearance_level": new_user.clearance_level,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


# Test endpoint
@registration_bp.route("/test", methods=["GET"])
def test():
    return jsonify({"message": "Registration API is working!"}), 200
