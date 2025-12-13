#!/usr/bin/env python3
"""
Database setup script for ZTA Government Document System
"""
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_database():
    """Create database tables and add government test users"""
    try:
        from app import create_app, db
        from app.models.user import User, GovernmentDocument, Facility, Department

        app = create_app()

        with app.app_context():

            # Create all tables
            print("Creating database tables...")
            db.create_all()
            print("✓ Tables created successfully!")

            # Create facilities
            print("\nCreating government facilities...")
            facilities = [
                {
                    "name": "Ministry of Defence",
                    "code": "MOD",
                    "type": "Ministry",
                    "location": "Capital City",
                },
                {
                    "name": "Ministry of Finance",
                    "code": "MOF",
                    "type": "Ministry",
                    "location": "Capital City",
                },
                {
                    "name": "National Security Agency",
                    "code": "NSA",
                    "type": "Agency",
                    "location": "Secure Location",
                },
            ]

            facility_objects = {}
            for fac_data in facilities:
                facility = Facility(**fac_data)
                db.session.add(facility)
                facility_objects[fac_data["code"]] = facility
                print(f"  Created: {fac_data['name']} ({fac_data['code']})")

            db.session.commit()

            # Create departments for each facility
            print("\nCreating departments...")
            departments = [
                {"facility_code": "MOD", "name": "Operations", "code": "OPS"},
                {"facility_code": "MOD", "name": "Intelligence", "code": "INT"},
                {"facility_code": "MOD", "name": "Logistics", "code": "LOG"},
                {"facility_code": "MOF", "name": "Budget", "code": "BUD"},
                {"facility_code": "MOF", "name": "Taxation", "code": "TAX"},
                {"facility_code": "NSA", "name": "Cyber Security", "code": "CYB"},
                {"facility_code": "NSA", "name": "Counter Intelligence", "code": "CTI"},
            ]

            for dept_data in departments:
                facility = facility_objects[dept_data["facility_code"]]
                department = Department(
                    name=dept_data["name"],
                    code=dept_data["code"],
                    facility_id=facility.id,
                )
                db.session.add(department)
                print(f"  Created: {dept_data['name']} in {dept_data['facility_code']}")

            db.session.commit()

            # Create test users for each facility
            print("\nCreating government test users...")

            # MOD Users
            superadmin = User(
                username="mod_admin",
                email="admin@mod.gov",
                user_class="superadmin",
                facility="Ministry of Defence",
                department="Operations",
                clearance_level="TOP_SECRET",
            )
            superadmin.set_password("Admin@123")
            db.session.add(superadmin)
            print("  Created: mod_admin (Ministry of Defence, Operations, TOP_SECRET)")

            # MOD Intelligence Officer
            mod_intel = User(
                username="intel_officer",
                email="intel@mod.gov",
                user_class="admin",
                facility="Ministry of Defence",
                department="Intelligence",
                clearance_level="SECRET",
            )
            mod_intel.set_password("Intel@123")
            db.session.add(mod_intel)
            print(
                "  Created: intel_officer (Ministry of Defence, Intelligence, SECRET)"
            )

            # MOD Logistics Officer
            mod_log = User(
                username="logistics",
                email="logistics@mod.gov",
                user_class="user",
                facility="Ministry of Defence",
                department="Logistics",
                clearance_level="CONFIDENTIAL",
            )
            mod_log.set_password("Logistics@123")
            db.session.add(mod_log)
            print("  Created: logistics (Ministry of Defence, Logistics, CONFIDENTIAL)")

            # MOF Users
            mof_admin = User(
                username="mof_admin",
                email="admin@mof.gov",
                user_class="admin",
                facility="Ministry of Finance",
                department="Budget",
                clearance_level="SECRET",
            )
            mof_admin.set_password("Admin@123")
            db.session.add(mof_admin)
            print("  Created: mof_admin (Ministry of Finance, Budget, SECRET)")

            # MOF Tax Officer
            mof_tax = User(
                username="tax_officer",
                email="tax@mof.gov",
                user_class="user",
                facility="Ministry of Finance",
                department="Taxation",
                clearance_level="CONFIDENTIAL",
            )
            mof_tax.set_password("Tax@123")
            db.session.add(mof_tax)
            print(
                "  Created: tax_officer (Ministry of Finance, Taxation, CONFIDENTIAL)"
            )

            # NSA Users
            nsa_analyst = User(
                username="cyber_analyst",
                email="cyber@nsa.gov",
                user_class="admin",
                facility="National Security Agency",
                department="Cyber Security",
                clearance_level="TOP_SECRET",
            )
            nsa_analyst.set_password("Cyber@123")
            db.session.add(nsa_analyst)
            print("  Created: cyber_analyst (NSA, Cyber Security, TOP_SECRET)")

            # Also keep the old admin user for compatibility
            old_admin = User(
                username="admin",
                email="admin@zta.gov",
                user_class="superadmin",
                facility="IT Department",
                department="Administration",
                clearance_level="TOP_SECRET",
            )
            old_admin.set_password("Admin123")
            db.session.add(old_admin)
            print(
                "  Created: admin (IT Department, Administration, TOP_SECRET) - Legacy user"
            )

            # Commit all users
            db.session.commit()

            # Create sample government documents
            print("\nCreating sample government documents...")
            create_sample_documents()

            print("\n" + "=" * 60)
            print("GOVERNMENT DOCUMENT SYSTEM - SETUP COMPLETE")
            print("=" * 60)
            print("\nTest Users Created:")
            print("-" * 60)
            print("Ministry of Defence:")
            print("  Superadmin: mod_admin / Admin@123 (TOP_SECRET)")
            print("  Intelligence Officer: intel_officer / Intel@123 (SECRET)")
            print("  Logistics Officer: logistics / Logistics@123 (CONFIDENTIAL)")
            print("\nMinistry of Finance:")
            print("  Admin: mof_admin / Admin@123 (SECRET)")
            print("  Tax Officer: tax_officer / Tax@123 (CONFIDENTIAL)")
            print("\nNational Security Agency:")
            print("  Cyber Analyst: cyber_analyst / Cyber@123 (TOP_SECRET)")
            print("\nLegacy User (for testing):")
            print("  Superadmin: admin / Admin123 (TOP_SECRET)")
            print("-" * 60)
            print("\nAccess the system at: http://localhost:5000")
            print("Use the credentials above to login")
            print("=" * 60)

    except ImportError as e:
        print(f"Import error: {e}")
        print("Please make sure all required files exist.")
        sys.exit(1)
    except Exception as e:
        print(f"Error setting up database: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def create_sample_documents():
    """Create sample government documents"""
    try:
        from app.models.user import User, GovernmentDocument
        from app import db
        from datetime import datetime, timedelta

        users = User.query.all()

        sample_documents = [
            {
                "title": "Defence Budget Allocation 2024",
                "description": "Annual budget allocation for defence operations",
                "content": "Confidential budget details for MOD operations...",
                "classification": "SECRET",
                "facility": "Ministry of Defence",
                "department": "Operations",
                "category": "Budget",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 5),
            },
            {
                "title": "Intelligence Report - Region X",
                "description": "Latest intelligence assessment",
                "content": "Top secret intelligence findings...",
                "classification": "TOP_SECRET",
                "facility": "Ministry of Defence",
                "department": "Intelligence",
                "category": "Intelligence",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 10),
            },
            {
                "title": "Logistics Supply Chain",
                "description": "Defence logistics supply chain details",
                "content": "Confidential logistics information...",
                "classification": "CONFIDENTIAL",
                "facility": "Ministry of Defence",
                "department": "Logistics",
                "category": "Operations",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 2),
            },
            {
                "title": "National Budget Framework",
                "description": "National budget framework document",
                "content": "Secret budget framework details...",
                "classification": "SECRET",
                "facility": "Ministry of Finance",
                "department": "Budget",
                "category": "Budget",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 3),
            },
            {
                "title": "Tax Policy Guidelines",
                "description": "Internal tax policy guidelines",
                "content": "Confidential tax policy details...",
                "classification": "CONFIDENTIAL",
                "facility": "Ministry of Finance",
                "department": "Taxation",
                "category": "Policy",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 2),
            },
            {
                "title": "Cyber Threat Assessment",
                "description": "National cyber threat assessment",
                "content": "Top secret threat intelligence...",
                "classification": "TOP_SECRET",
                "facility": "National Security Agency",
                "department": "Cyber Security",
                "category": "Security",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 7),
            },
            {
                "title": "Public Service Announcement",
                "description": "General public announcement",
                "content": "Public information for citizens...",
                "classification": "UNCLASSIFIED",
                "facility": "Ministry of Defence",
                "department": "Operations",
                "category": "Public",
                "expiry_date": None,
            },
        ]

        document_count = 0
        for doc_data in sample_documents:
            # Find a user from the same facility and department
            owner = next(
                (
                    u
                    for u in users
                    if u.facility == doc_data["facility"]
                    and u.department == doc_data["department"]
                ),
                users[0],
            )

            # Generate document ID
            doc_id = f"{doc_data['facility'][:3].upper()}-{doc_data['department'][:3].upper()}-{datetime.utcnow().strftime('%Y%m%d')}-{document_count + 1:04d}"

            document = GovernmentDocument(
                document_id=doc_id,
                title=doc_data["title"],
                description=doc_data["description"],
                content=doc_data["content"],
                classification=doc_data["classification"],
                facility=doc_data["facility"],
                department=doc_data["department"],
                category=doc_data["category"],
                owner_id=owner.id,
                created_by=owner.id,
                expiry_date=doc_data["expiry_date"],
            )
            db.session.add(document)
            document_count += 1
            print(
                f"  Created: {doc_id} - {doc_data['title']} ({doc_data['classification']})"
            )

        db.session.commit()
        print(f"✓ {document_count} sample government documents created!")

    except Exception as e:
        print(f"Warning: Could not create sample documents: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    setup_database()
