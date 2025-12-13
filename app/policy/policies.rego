package zta

import future.keywords

# Default deny everything
default allow := false

#############################################
# DOCUMENT ACCESS POLICIES
#############################################

# Allow superadmin to do anything
allow {
    input.user.role == "superadmin"
    reason := "Superadmin has full access"
}

# Admin can manage documents in their facility
allow {
    input.user.role == "admin"
    input.resource.type == "document"
    input.resource.facility == input.user.facility
    input.action == "read"
    reason := "Admin can read documents in their facility"
}

allow {
    input.user.role == "admin"
    input.resource.type == "document"
    input.resource.facility == input.user.facility
    input.resource.department == input.user.department
    input.action == "write"
    reason := "Admin can write to documents in their department"
}

# Regular user access rules
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    
    # Check clearance level hierarchy
    clearance_levels := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
    clearance_index(resource_level) := i {
        clearance_levels[i] == resource_level
    }
    user_clearance_index := clearance_index(input.user.clearance)
    resource_clearance_index := clearance_index(input.resource.classification)
    user_clearance_index >= resource_clearance_index
    
    reason := sprintf("User has sufficient clearance: %s >= %s", [input.user.clearance, input.resource.classification])
}

# Users can read their own documents regardless of department
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.resource.owner == input.user.id
    reason := "User can read their own documents"
}

# Time-based restrictions for regular users
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.environment.time.hour >= 9
    input.environment.time.hour <= 17
    not input.environment.time.weekend
    input.resource.department == input.user.department
    reason := "Access allowed during business hours"
}

# Deny access to TOP_SECRET for non-superadmins after hours
deny {
    input.resource.type == "document"
    input.resource.classification == "TOP_SECRET"
    input.user.role != "superadmin"
    (input.environment.time.hour < 9 or input.environment.time.hour > 17)
    reason := "TOP_SECRET access restricted to business hours"
}

#############################################
# USER MANAGEMENT POLICIES
#############################################

# Separate policy for user management
user_management := decision {
    decision := {"allow": false, "reason": "Default deny"}
}

user_management := {"allow": true, "reason": "Superadmin can manage any user"} {
    input.user.role == "superadmin"
}

user_management := {"allow": true, "reason": "Admin can manage users in their facility"} {
    input.user.role == "admin"
    input.action == "read"
    input.resource.facility == input.user.facility
}

user_management := {"allow": true, "reason": "Admin can create users in their department"} {
    input.user.role == "admin"
    input.action == "create"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    input.resource.role != "superadmin"
}

user_management := {"allow": true, "reason": "Admin can update users in their department"} {
    input.user.role == "admin"
    input.action == "update"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    input.resource.role != "superadmin"
}

# Prevent privilege escalation
user_management := {"allow": false, "reason": "Cannot assign higher role than self"} {
    input.user.role == "admin"
    input.action == "create"
    role_hierarchy := {"user": 1, "admin": 2, "superadmin": 3}
    role_hierarchy[input.resource.role] > role_hierarchy[input.user.role]
}

user_management := {"allow": false, "reason": "Cannot assign higher role than self"} {
    input.user.role == "admin"
    input.action == "update"
    role_hierarchy := {"user": 1, "admin": 2, "superadmin": 3}
    role_hierarchy[input.resource.role] > role_hierarchy[input.user.role]
}

#############################################
# AUDIT LOG ACCESS POLICIES
#############################################

audit_access := decision {
    decision := {"allow": false, "reason": "Default deny"}
}

audit_access := {"allow": true, "reason": "Superadmin can view all audit logs"} {
    input.user.role == "superadmin"
    input.action == "read"
}

audit_access := {"allow": true, "reason": "Admin can view logs from their facility"} {
    input.user.role == "admin"
    input.action == "read"
    input.resource.facility == input.user.facility
}

#############################################
# DECISION AGGREGATION
#############################################

# Main decision function
decision := {
    "allow": allow,
    "reason": reason,
    "timestamp": time.now_ns(),
    "request_id": input.request_id
} {
    allow
    reason := reason_allow
} else = {
    "allow": false,
    "reason": reason_deny,
    "timestamp": time.now_ns(),
    "request_id": input.request_id
} {
    not allow
    reason_deny := "Access denied by policy"
}

# Extract reason from allow rules
reason_allow := reason {
    some reason
    reason = reason
}

# Extract reason from deny rules
reason_deny := reason {
    some reason
    reason = reason
} else := "Access denied by default policy"