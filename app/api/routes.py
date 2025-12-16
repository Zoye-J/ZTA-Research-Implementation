from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app import db
from app.models.user import GovernmentDocument, AccessLog, User
from app.policy.opa_client import get_opa_client
from app.logs.request_logger import log_request
from app.auth.mtls_jwt_auth import zta_auth  # NEW: Import ZTA authenticator
from datetime import datetime, timedelta
import uuid

api_bp = Blueprint("api", __name__)


# Helper function to get user claims from either JWT or mTLS
def get_user_claims():
    """
    Get user claims from either JWT or mTLS certificate
    Returns: claims dict or None if not authenticated
    """
    # First check if we have ZTA authentication
    if hasattr(request, "zta_identity"):
        zta_identity = request.zta_identity

        if zta_identity.get("type") == "user" and "user" in zta_identity:
            user = zta_identity["user"]
            return {
                "sub": user.id,
                "username": user.username,
                "email": user.email,
                "user_class": user.user_class,
                "facility": user.facility,
                "department": user.department,
                "clearance_level": user.clearance_level,
                "auth_method": request.zta_auth_method,
            }

    # Fall back to JWT if present
    try:
        from flask_jwt_extended import verify_jwt_in_request

        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    "sub": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_class": user.user_class,
                    "facility": user.facility,
                    "department": user.department,
                    "clearance_level": user.clearance_level,
                    "auth_method": "JWT",
                }
    except:
        pass

    return None


# Test ZTA authentication endpoint
@api_bp.route("/zta/test", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def test_zta_auth():
    """Test Zero Trust Authentication (JWT + mTLS)"""
    try:
        # Get user info from ZTA
        user = request.zta_identity.get("user")

        return (
            jsonify(
                {
                    "status": "success",
                    "message": "Zero Trust Authentication successful",
                    "authentication_layers": {
                        "layer1_mtls": "✓ Client certificate validated",
                        "layer2_jwt": "✓ JWT token validated",
                        "layer3_identity_match": "✓ Certificate matches JWT identity",
                    },
                    "user": {
                        "id": user.id if user else None,
                        "username": user.username if user else None,
                        "email": user.email if user else None,
                        "department": user.department if user else None,
                    },
                    "certificate_info": {
                        "fingerprint": request.zta_identity.get("fingerprint", "")[:16]
                        + "...",
                        "subject": request.zta_identity.get("subject", {}),
                        "type": request.zta_identity.get("type"),
                    },
                    "auth_method": request.zta_auth_method,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "ZTA test failed", "message": str(e)}), 500


# Dashboard statistics (ZTA enabled)
@api_bp.route("/documents/stats", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def get_dashboard_stats():
    """Get dashboard statistics - requires ZTA authentication"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

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
                    "auth_method": auth_method,
                    "zta_enforced": True,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch stats", "message": str(e)}), 500


# Get documents with ZTA + OPA
@api_bp.route("/documents", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def get_documents():
    """Get documents - requires ZTA authentication and OPA policy check"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

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

        # Check OPA policy for each document
        filtered_documents = []
        for doc in documents:
            # Prepare OPA input
            opa_input = {
                "identity": {
                    "user_id": user_id,
                    "user_class": user_class,
                    "facility": user_facility,
                    "department": user_department,
                    "clearance_level": claims.get("clearance_level", "BASIC"),
                    "auth_method": auth_method,
                },
                "resource": {
                    "document_id": doc.id,
                    "classification": doc.classification,
                    "facility": doc.facility,
                    "department": doc.department,
                    "owner_id": doc.owner_id,
                },
                "action": "read",
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Check OPA policy
            allowed, reason = zta_auth.check_opa_policy("zta/main", opa_input)
            if allowed:
                filtered_documents.append(doc)

        # Log the access with ZTA info
        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="GET",
            status="allowed",
            reason=f"ZTA access via {auth_method}",
            auth_method=auth_method,
            certificate_fingerprint=(
                request.zta_identity.get("fingerprint", "")[:16] + "..."
                if hasattr(request, "zta_identity")
                else None
            ),
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
                    ],
                    "zta_info": {
                        "auth_method": auth_method,
                        "policy_enforced": True,
                        "documents_filtered": len(documents) - len(filtered_documents),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch documents", "message": str(e)}), 500


# Get single document with ZTA + OPA
@api_bp.route("/documents/<int:document_id>", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def get_document(document_id):
    """Get single document - requires ZTA authentication"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        # Find document
        document = GovernmentDocument.query.get_or_404(document_id)

        # Get OPA client
        opa_client = get_opa_client()

        # Prepare OPA input with ZTA context
        opa_input = {
            "identity": {
                "user_id": claims["sub"],
                "user_class": claims["user_class"],
                "facility": claims.get("facility"),
                "department": claims.get("department"),
                "clearance_level": claims.get("clearance_level", "BASIC"),
                "auth_method": claims.get("auth_method", "unknown"),
                "certificate_fingerprint": (
                    request.zta_identity.get("fingerprint")
                    if hasattr(request, "zta_identity")
                    else None
                ),
            },
            "resource": {
                "document_id": document.id,
                "classification": document.classification,
                "facility": document.facility,
                "department": document.department,
                "owner_id": document.owner_id,
            },
            "action": "read",
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check OPA policy
        allowed, reason = zta_auth.check_opa_policy("zta/main", opa_input)

        if not allowed:
            log_request(
                user_id=claims.get("sub"),
                endpoint=f"/api/documents/{document_id}",
                method="GET",
                status="denied",
                reason=f"OPA denied access: {reason}",
                document_id=document_id,
                auth_method=claims.get("auth_method", "unknown"),
                certificate_fingerprint=(
                    request.zta_identity.get("fingerprint", "")[:16] + "..."
                    if hasattr(request, "zta_identity")
                    else None
                ),
            )
            return (
                jsonify(
                    {
                        "error": "Access denied",
                        "reason": reason,
                        "zta_context": {
                            "auth_method": claims.get("auth_method"),
                            "policy_violation": True,
                        },
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
            reason=f"ZTA access allowed: {reason}",
            document_id=document_id,
            auth_method=claims.get("auth_method", "unknown"),
            certificate_fingerprint=(
                request.zta_identity.get("fingerprint", "")[:16] + "..."
                if hasattr(request, "zta_identity")
                else None
            ),
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
                    "zta_context": {
                        "auth_method": claims.get("auth_method"),
                        "policy_decision": "allowed",
                        "policy_reason": reason,
                        "authentication_layers": (
                            ["mTLS", "JWT", "OPA"]
                            if hasattr(request, "zta_identity")
                            else ["JWT", "OPA"]
                        ),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch document", "message": str(e)}), 500


# Create document with ZTA
@api_bp.route("/documents", methods=["POST"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def create_document():
    """Create document - requires ZTA authentication"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

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
                        "zta_context": {
                            "user_clearance": user_clearance,
                            "required_clearance": doc_classification,
                        },
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

        # Log creation with ZTA info
        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="POST",
            status="allowed",
            reason=f"Created document {document_id} via {auth_method}",
            document_id=new_document.id,
            auth_method=auth_method,
            certificate_fingerprint=(
                request.zta_identity.get("fingerprint", "")[:16] + "..."
                if hasattr(request, "zta_identity")
                else None
            ),
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
                    "zta_context": {
                        "auth_method": auth_method,
                        "created_via": "Zero Trust Authentication",
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create document", "message": str(e)}), 500


# Get access logs (ZTA enabled)
@api_bp.route("/logs", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def get_logs():
    """Get access logs - requires ZTA authentication"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        auth_method = claims.get("auth_method", "unknown")

        # Only admin and superadmin can access logs
        if user_class not in ["admin", "superadmin"]:
            return (
                jsonify(
                    {
                        "error": "Admin access required",
                        "zta_context": {
                            "required_role": "admin or superadmin",
                            "your_role": user_class,
                        },
                    }
                ),
                403,
            )

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
                            "auth_method": getattr(log, "auth_method", "legacy"),
                            "certificate_fingerprint": getattr(
                                log, "certificate_fingerprint", None
                            ),
                            "policy_evaluated": log.policy_evaluated,
                            "decision_id": log.decision_id,
                        }
                        for log in logs
                    ],
                    "total": len(logs),
                    "zta_context": {
                        "auth_method": auth_method,
                        "facility": user_facility,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "message": str(e)}), 500


# Get users with ZTA (admin only)
@api_bp.route("/users", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=True)
def get_users():
    """Get users - requires ZTA authentication"""
    try:
        claims = get_user_claims()
        if not claims:
            return jsonify({"error": "Authentication required"}), 401

        user_class = claims["user_class"]
        auth_method = claims.get("auth_method", "unknown")

        # Only admin and superadmin can access user list
        if user_class not in ["admin", "superadmin"]:
            return (
                jsonify(
                    {
                        "error": "Admin access required",
                        "zta_context": {
                            "required_role": "admin or superadmin",
                            "your_role": user_class,
                        },
                    }
                ),
                403,
            )

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

        # Include certificate info in response
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
                            "has_certificate": bool(user.certificate_fingerprint),
                            "certificate_expires": (
                                user.certificate_expires.isoformat()
                                if user.certificate_expires
                                else None
                            ),
                            "mfa_enabled": user.mfa_enabled,
                        }
                        for user in users
                    ],
                    "total": len(users),
                    "zta_context": {
                        "auth_method": auth_method,
                        "facility": user_facility,
                        "certificate_based_auth_enabled": any(
                            user.certificate_fingerprint for user in users
                        ),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch users", "message": str(e)}), 500


# Test OPA endpoint with ZTA
@api_bp.route("/opa-test", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=False)  # Allow mTLS only for services
def opa_test():
    """Test OPA integration with ZTA"""
    try:
        opa_client = get_opa_client()

        # Add ZTA context to response
        zta_context = {}
        if hasattr(request, "zta_identity"):
            zta_context = {
                "auth_method": request.zta_auth_method,
                "identity_type": request.zta_identity.get("type"),
                "identity": request.zta_identity.get("service_name")
                or request.zta_identity.get("email"),
            }

        # Test OPA connection
        if opa_client.health_check():
            return (
                jsonify(
                    {
                        "message": "OPA integration working",
                        "opa_url": opa_client.opa_url,
                        "status": "connected",
                        "zta_context": zta_context,
                        "timestamp": datetime.utcnow().isoformat(),
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
                        "zta_context": zta_context,
                    }
                ),
                503,
            )

    except Exception as e:
        return jsonify({"error": "OPA test failed", "message": str(e)}), 500


# Service health endpoint (mTLS only - for service-to-service)
@api_bp.route("/service/health", methods=["GET"])
@zta_auth.require_zta_auth(require_jwt_for_users=False)  # Services only need mTLS
def service_health():
    """Service health check - mTLS only (service-to-service)"""
    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Government System",
            "auth_method": (
                request.zta_auth_method
                if hasattr(request, "zta_auth_method")
                else "unknown"
            ),
            "identity": (
                request.zta_identity.get("service_name", "unknown")
                if hasattr(request, "zta_identity")
                else "unknown"
            ),
            "timestamp": datetime.utcnow().isoformat(),
            "zta_enabled": True,
            "features": ["JWT", "mTLS", "OPA", "Certificate Validation", "RBAC"],
        }
    )


# Legacy JWT-only endpoint (for backward compatibility)
@api_bp.route("/legacy/documents", methods=["GET"])
@jwt_required()
def legacy_get_documents():
    """Legacy endpoint - JWT only (for backward compatibility)"""
    current_app.logger.warning(
        "Legacy JWT-only endpoint accessed - consider migrating to ZTA endpoints"
    )

    # Call the original function logic
    return get_documents()
