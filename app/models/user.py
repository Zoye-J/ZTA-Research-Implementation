from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    user_class = db.Column(
        db.String(20), nullable=False
    )  # 'superadmin', 'admin', 'user'
    facility = db.Column(db.String(100), nullable=False)  # Government facility/agency
    department = db.Column(db.String(100), nullable=False)  # Department within facility
    clearance_level = db.Column(
        db.String(20), default="BASIC"
    )  # BASIC, CONFIDENTIAL, SECRET, TOP_SECRET
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "user_class": self.user_class,
            "facility": self.facility,
            "department": self.department,
            "clearance_level": self.clearance_level,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active,
        }


class GovernmentDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.String(50), unique=True, nullable=False
    )  # Official document ID
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    content = db.Column(db.Text)
    classification = db.Column(
        db.String(50), nullable=False
    )  # UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET
    facility = db.Column(db.String(100), nullable=False)  # Owning facility
    department = db.Column(db.String(100), nullable=False)  # Owning department
    category = db.Column(db.String(100))  # Budget, Personnel, Operations, etc.
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    expiry_date = db.Column(db.DateTime)  # When document declassifies
    is_archived = db.Column(db.Boolean, default=False)

    owner = db.relationship("User", foreign_keys=[owner_id], backref="owned_documents")
    creator = db.relationship(
        "User", foreign_keys=[created_by], backref="created_documents"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "document_id": self.document_id,
            "title": self.title,
            "description": self.description,
            "content": self.content,
            "classification": self.classification,
            "facility": self.facility,
            "department": self.department,
            "category": self.category,
            "owner_id": self.owner_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "is_archived": self.is_archived,
        }


class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    document_id = db.Column(db.Integer, db.ForeignKey("government_document.id"))
    action = db.Column(
        db.String(50), nullable=False
    )  # 'view', 'download', 'create', 'update', 'delete', 'share'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # 'allowed', 'denied'
    reason = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    client_cert_verified = db.Column(db.Boolean, default=False)
    accessed_from = db.Column(db.String(100))  # Internal network, VPN, etc.

    user = db.relationship("User", backref="access_logs")
    document = db.relationship("GovernmentDocument", backref="access_logs")


class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)  # Facility code
    type = db.Column(db.String(50))  # Ministry, Department, Agency, etc.
    location = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    departments = db.relationship("Department", backref="facility", lazy=True)


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey("facility.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
