package zta.main

import future.keywords

# ZTA Core Policies
default allow := false

#############################################
# AUTHENTICATION TIER SYSTEM
#############################################

# Authentication tiers (3 = strongest)
auth_tier := tier {
    # Tier 3: mTLS + JWT + Biometric (Future)
    input.auth.method == "mTLS_JWT_BIOMETRIC"
    tier := 3
} else := tier {
    # Tier 2: mTLS + JWT (Current implementation)
    input.auth.method == "mTLS_JWT"
    input.certificate.valid == true
    input.jwt.valid == true
    input.certificate.email == input.jwt.email
    tier := 2
} else := tier {
    # Tier 1: mTLS Service
    input.auth.method == "mTLS_service"
    input.certificate.valid == true
    valid_services[input.certificate.cn]
    tier := 1
} else := 0

# Valid services in ZTA ecosystem
valid_services["opa-agent.zta.gov"]
valid_services["api-server.zta.gov"]
valid_services["auth-service.zta.gov"]
valid_services["document-service.zta.gov"]

#############################################
# RISK-BASED ACCESS CONTROL
#############################################

# Calculate risk score
risk_score := score {
    # Higher clearance = higher risk if compromised
    clearance_risk := {
        "BASIC": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4
    }[input.user.clearance]
    
    # Authentication strength reduces risk
    auth_mitigation := {
        3: 0.9,  # Strongest auth
        2: 0.7,  # Strong auth
        1: 0.4,  # Weak auth
        0: 0.0   # No auth
    }[auth_tier]
    
    # Time risk
    time_risk := 1.0 {
        input.time.hour >= 9
        input.time.hour <= 17
        not input.time.weekend
    } else := 1.5
    
    score := clearance_risk * time_risk * (1 - auth_mitigation)
}

# Allow if risk is acceptable
allow {
    auth_tier >= required_tier[input.resource.classification]
    risk_score <= max_risk_score[input.resource.classification]
}

# Required authentication tier per classification
required_tier["TOP_SECRET"] := 2  # mTLS + JWT
required_tier["SECRET"] := 2      # mTLS + JWT
required_tier["CONFIDENTIAL"] := 1 # mTLS service
required_tier["BASIC"] := 0       # Any

# Maximum risk scores
max_risk_score["TOP_SECRET"] := 1.0
max_risk_score["SECRET"] := 1.5
max_risk_score["CONFIDENTIAL"] := 2.0
max_risk_score["BASIC"] := 3.0

#############################################
# SERVICE MESH POLICIES
#############################################

# Service communication policies
allow_service_communication {
    input.source.type == "service"
    input.destination.type == "service"
    
    # Both must have valid certificates
    input.source.certificate.valid
    input.destination.certificate.valid
    
    # Communication matrix
    service_communication_allowed[input.source.name][input.destination.name]
}

# Service communication matrix
service_communication_allowed["opa-agent.zta.gov"]["api-server.zta.gov"]
service_communication_allowed["api-server.zta.gov"]["document-service.zta.gov"]
service_communication_allowed["auth-service.zta.gov"]["api-server.zta.gov"]
service_communication_allowed["document-service.zta.gov"]["api-server.zta.gov"]

# Transitive trust is NOT allowed (Zero Trust principle)
service_communication_allowed[source][destination] {
    # Explicitly list allowed communications
}

#############################################
# CERTIFICATE LIFECYCLE POLICIES
#############################################

# Certificate issuance
allow_certificate_issue {
    input.action == "issue_certificate"
    
    # Only specific roles can issue certificates
    input.requester.role == "superadmin"
    or input.requester.role == "admin"
    
    # Certificate type restrictions
    input.certificate.type == "user" {
        # Admins can only issue for their department
        input.requester.role == "admin"
        input.certificate.department == input.requester.department
    }
    
    input.certificate.type == "service" {
        # Only superadmins can issue service certificates
        input.requester.role == "superadmin"
    }
}

# Certificate revocation
allow_certificate_revoke {
    input.action == "revoke_certificate"
    
    # Can revoke own certificate
    input.certificate.email == input.requester.email
    
    # Or higher role can revoke
    role_hierarchy := {"user": 1, "admin": 2, "superadmin": 3}
    role_hierarchy[input.requester.role] > role_hierarchy[input.certificate.owner.role]
    
    # Or certificate is compromised
    input.reason == "compromised"
}