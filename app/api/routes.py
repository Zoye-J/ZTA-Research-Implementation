from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from app import db
from app.models.user import GovernmentDocument, AccessLog, User
from app.policy.opa_client import get_opa_client  # Change this import
from app.logs.request_logger import log_request
from datetime import datetime, timedelta
import uuid

api_bp = Blueprint("api", __name__)


# Dashboard statistics
@api_bp.route("/documents/stats", methods=["GET"])
@jwt_required()
def get_dashboard_stats():
    try:
        claims = get_jwt()
        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")

        # Count user's documents
        user_doc_count = GovernmentDocument.query.filter_by(owner_id=user_id).count()

        # Count today's accesses
        today = datetime.utcnow().date()
        today_accesses = AccessLog.query.filter(
            AccessLog.user_id == user_id, db.func.date(AccessLog.timestamp) == today
        ).count()

        return (
            jsonify(
                {
                    "your_documents": user_doc_count,
                    "today_accesses": today_accesses,
                    "facility": user_facility,
                    "department": user_department,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch stats", "message": str(e)}), 500


# Get documents
@api_bp.route("/documents", methods=["GET"])
@jwt_required()
def get_documents():
    try:
        claims = get_jwt()
        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")

        # Get OPA client
        opa_client = get_opa_client()

        # Build query
        query = GovernmentDocument.query.filter_by(
            facility=user_facility, is_archived=False
        )

        # Get query parameters
        classification = request.args.get("classification")
        department = request.args.get("department")
        category = request.args.get("category")
        search = request.args.get("search")

        # Apply filters
        if classification:
            query = query.filter_by(classification=classification)

        if department:
            query = query.filter_by(department=department)
        elif user_class in ["user", "admin"]:
            query = query.filter_by(department=user_department)

        if category:
            query = query.filter_by(category=category)

        if search:
            query = query.filter(
                db.or_(
                    GovernmentDocument.title.ilike(f"%{search}%"),
                    GovernmentDocument.description.ilike(f"%{search}%"),
                    GovernmentDocument.document_id.ilike(f"%{search}%"),
                )
            )

        # Execute query
        documents = query.order_by(GovernmentDocument.created_at.desc()).all()

        # Filter documents through OPA policy
        filtered_documents = []
        for doc in documents:
            allowed, reason, decision_id = opa_client.evaluate_document_access(
                claims, doc, "read"
            )
            if allowed:
                filtered_documents.append(doc)

        # Log the access
        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="GET",
            status="allowed",
            reason=f"User accessed documents list",
        )

        return (
            jsonify(
                {
                    "documents": [
                        {
                            "id": doc.id,
                            "document_id": doc.document_id,
                            "title": doc.title,
                            "description": doc.description,
                            "classification": doc.classification,
                            "department": doc.department,
                            "category": doc.category,
                            "created_at": doc.created_at.isoformat(),
                            "owner_id": doc.owner_id,
                            "facility": doc.facility,
                        }
                        for doc in filtered_documents
                    ]
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch documents", "message": str(e)}), 500


# Get single document with OPA policy
@api_bp.route("/documents/<int:document_id>", methods=["GET"])
@jwt_required()
def get_document(document_id):
    try:
        claims = get_jwt()

        # Find document
        document = GovernmentDocument.query.get_or_404(document_id)

        # Get OPA client
        opa_client = get_opa_client()

        # Evaluate policy with OPA
        allowed, reason, decision_id = opa_client.evaluate_document_access(
            claims, document, "read"
        )

        if not allowed:
            log_request(
                user_id=claims.get("sub"),
                endpoint=f"/api/documents/{document_id}",
                method="GET",
                status="denied",
                reason=f"OPA denied access: {reason}",
                document_id=document_id,
                decision_id=decision_id,
            )
            return (
                jsonify(
                    {
                        "error": "Access denied",
                        "reason": reason,
                        "decision_id": decision_id,
                    }
                ),
                403,
            )

        # Log access
        log_request(
            user_id=claims.get("sub"),
            endpoint=f"/api/documents/{document_id}",
            method="GET",
            status="allowed",
            reason=f"OPA allowed access: {reason}",
            document_id=document_id,
            decision_id=decision_id,
        )

        return (
            jsonify(
                {
                    "document": {
                        "id": document.id,
                        "document_id": document.document_id,
                        "title": document.title,
                        "description": document.description,
                        "content": document.content,
                        "classification": document.classification,
                        "facility": document.facility,
                        "department": document.department,
                        "category": document.category,
                    },
                    "policy_decision": {
                        "allowed": allowed,
                        "reason": reason,
                        "decision_id": decision_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch document", "message": str(e)}), 500


# Create document
@api_bp.route("/documents", methods=["POST"])
@jwt_required()
def create_document():
    try:
        claims = get_jwt()
        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")

        data = request.get_json()

        # Validate required fields
        required_fields = ["title", "classification", "category"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} is required"}), 400

        # Check if user has sufficient clearance
        clearance_levels = ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
        user_clearance = claims.get("clearance_level", "BASIC")
        doc_classification = data["classification"]

        user_idx = (
            clearance_levels.index(user_clearance)
            if user_clearance in clearance_levels
            else 0
        )
        doc_idx = (
            clearance_levels.index(doc_classification)
            if doc_classification in clearance_levels
            else 0
        )

        if doc_idx > user_idx:
            return (
                jsonify(
                    {
                        "error": "Insufficient clearance",
                        "message": f"Your clearance ({user_clearance}) is insufficient to create {doc_classification} documents",
                    }
                ),
                403,
            )

        # Generate document ID
        document_id = f"{user_facility[:3].upper()}-{user_department[:3].upper()}-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Create document
        new_document = GovernmentDocument(
            document_id=document_id,
            title=data["title"],
            description=data.get("description", ""),
            content=data.get("content", ""),
            classification=data["classification"],
            facility=user_facility,
            department=user_department,
            category=data["category"],
            owner_id=user_id,
            created_by=user_id,
            expiry_date=data.get("expiry_date"),
        )

        db.session.add(new_document)
        db.session.commit()

        # Log creation
        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="POST",
            status="allowed",
            reason=f"Created document {document_id}",
            document_id=new_document.id,
        )

        return (
            jsonify(
                {
                    "message": "Document created successfully",
                    "document": {
                        "id": new_document.id,
                        "document_id": new_document.document_id,
                        "title": new_document.title,
                        "classification": new_document.classification,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create document", "message": str(e)}), 500


# Get access logs
@api_bp.route("/logs", methods=["GET"])
@jwt_required()
def get_logs():
    try:
        claims = get_jwt()
        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")

        # Only admin and superadmin can access logs
        if user_class not in ["admin", "superadmin"]:
            return jsonify({"error": "Admin access required"}), 403

        # Get query parameters
        limit = request.args.get("limit", 100, type=int)
        user_filter = request.args.get("user_id", type=int)
        document_filter = request.args.get("document_id", type=int)

        # Build query
        query = AccessLog.query

        # Filter by user if requested
        if user_filter and user_class == "superadmin":
            query = query.filter(AccessLog.user_id == user_filter)
        else:
            # Admin can only see logs from their facility
            query = query.join(User).filter(User.facility == user_facility)

        if document_filter:
            query = query.filter(AccessLog.document_id == document_filter)

        # Order by most recent and limit
        logs = query.order_by(AccessLog.timestamp.desc()).limit(limit).all()

        return (
            jsonify(
                {
                    "logs": [
                        {
                            "id": log.id,
                            "user_id": log.user_id,
                            "username": log.user.username if log.user else "Unknown",
                            "document_id": log.document_id,
                            "document_title": (
                                log.document.title if log.document else "Unknown"
                            ),
                            "action": log.action,
                            "timestamp": log.timestamp.isoformat(),
                            "status": log.status,
                            "reason": log.reason,
                            "ip_address": log.ip_address,
                            "policy_evaluated": log.policy_evaluated,
                            "decision_id": log.decision_id,
                        }
                        for log in logs
                    ],
                    "total": len(logs),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "message": str(e)}), 500


# Get users (admin only)
@api_bp.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    try:
        claims = get_jwt()
        user_class = claims["user_class"]

        # Only admin and superadmin can access user list
        if user_class not in ["admin", "superadmin"]:
            return jsonify({"error": "Admin access required"}), 403

        user_facility = claims.get("facility")

        # Get query parameters
        department = request.args.get("department")
        user_class_filter = request.args.get("user_class")

        # Build query - only show users from the same facility
        query = User.query.filter_by(facility=user_facility)

        # Apply filters
        if department:
            query = query.filter_by(department=department)

        if user_class_filter:
            query = query.filter_by(user_class=user_class_filter)

        # Exclude password hash from response
        users = query.order_by(User.created_at.desc()).all()

        return (
            jsonify(
                {
                    "users": [
                        {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "user_class": user.user_class,
                            "facility": user.facility,
                            "department": user.department,
                            "clearance_level": user.clearance_level,
                            "created_at": user.created_at.isoformat(),
                            "is_active": user.is_active,
                        }
                        for user in users
                    ],
                    "total": len(users),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch users", "message": str(e)}), 500


# Test OPA endpoint
@api_bp.route("/opa-test", methods=["GET"])
def opa_test():
    """Test OPA integration"""
    try:
        opa_client = get_opa_client()

        # Test OPA connection
        if opa_client.health_check():
            return (
                jsonify(
                    {
                        "message": "OPA integration working",
                        "opa_url": opa_client.opa_url,
                        "status": "connected",
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "message": "OPA server not reachable",
                        "opa_url": opa_client.opa_url,
                        "status": "disconnected",
                    }
                ),
                503,
            )

    except Exception as e:
        return jsonify({"error": "OPA test failed", "message": str(e)}), 500
