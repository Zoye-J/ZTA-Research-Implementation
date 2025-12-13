"""
Open Policy Agent (OPA) Client for ZTA System
"""

import requests
import json
from flask import current_app, request
from datetime import datetime
from app.logs.request_logger import log_request
import logging

logger = logging.getLogger(__name__)


class OPAClient:
    def __init__(self, opa_url=None, timeout=5):
        # Don't use current_app.config here - will be set later
        self.opa_url = opa_url or "http://localhost:8181"
        self.timeout = timeout
        self._initialized = False

    def init_app(self, app):
        """Initialize with Flask app config"""
        self.opa_url = app.config.get("OPA_URL", "http://localhost:8181")
        self.timeout = app.config.get("OPA_TIMEOUT", 5)
        self._initialized = True
        logger.info(f"OPA Client initialized with URL: {self.opa_url}")

    def health_check(self):
        """Check if OPA server is healthy"""
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=self.timeout)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA health check failed: {e}")
            return False

    def evaluate_policy(self, input_data, policy_path="zta/allow"):
        """
        Evaluate policy against OPA

        Args:
            input_data: Dictionary containing user, resource, action, environment
            policy_path: OPA policy path (default: zta/allow)

        Returns:
            tuple: (allowed: bool, reason: str, decision_id: str)
        """
        try:
            url = f"{self.opa_url}/v1/data/{policy_path}"

            logger.debug(f"OPA Request to {url}")

            response = requests.post(
                url,
                json={"input": input_data},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            logger.debug(f"OPA Response Status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                decision_id = response.headers.get("X-Decision-Id", "unknown")

                # OPA returns {"result": true/false} for allow policies
                allowed = result.get("result", False)

                # Try to get reason from decision if available
                if isinstance(result, dict) and "decision" in result:
                    decision = result["decision"]
                    reason = decision.get("reason", "Policy evaluation complete")
                else:
                    reason = "Policy evaluation complete"

                return allowed, reason, decision_id

            elif response.status_code == 404:
                logger.error(f"OPA policy path not found: {policy_path}")
                return False, f"Policy path '{policy_path}' not found", None
            else:
                logger.error(
                    f"OPA request failed with status {response.status_code}: {response.text}"
                )
                return False, f"OPA server error: {response.status_code}", None

        except requests.exceptions.Timeout:
            logger.error(f"OPA request timeout after {self.timeout}s")
            return False, "OPA evaluation timeout", None
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA request failed: {e}")
            return False, f"OPA communication error: {str(e)}", None
        except Exception as e:
            logger.error(f"Unexpected error in OPA evaluation: {e}")
            return False, f"Policy evaluation error: {str(e)}", None

    def evaluate_document_access(self, user_claims, document, action):
        """
        Evaluate document access policy

        Args:
            user_claims: JWT claims dictionary
            document: Document object or dictionary
            action: string - 'read', 'write', 'delete', 'create'

        Returns:
            tuple: (allowed: bool, reason: str, decision_id: str)
        """
        # Prepare input for OPA
        if hasattr(document, "to_dict"):
            doc_dict = document.to_dict()
        else:
            doc_dict = document

        input_data = {
            "user": {
                "id": user_claims.get("sub"),
                "username": user_claims.get("username", user_claims.get("sub")),
                "role": user_claims.get("user_class"),
                "department": user_claims.get("department"),
                "facility": user_claims.get("facility"),
                "clearance": user_claims.get("clearance_level", "BASIC"),
            },
            "resource": {
                "type": "document",
                "id": doc_dict.get("id"),
                "classification": doc_dict.get("classification"),
                "department": doc_dict.get("department"),
                "facility": doc_dict.get("facility"),
                "owner": doc_dict.get("owner_id"),
            },
            "action": action,
            "environment": {
                "time": {
                    "hour": datetime.now().hour,
                    "day_of_week": datetime.now().strftime("%A"),
                    "weekend": datetime.now().weekday() >= 5,
                },
                "ip_address": request.remote_addr if request else None,
                "user_agent": (
                    request.user_agent.string
                    if request and request.user_agent
                    else None
                ),
            },
            "request_id": user_claims.get("request_id", "unknown"),
        }

        return self.evaluate_policy(input_data)

    def evaluate_user_management(self, admin_claims, target_user, action):
        """
        Evaluate user management policy

        Args:
            admin_claims: Admin user JWT claims
            target_user: Target user object or dictionary
            action: string - 'create', 'update', 'delete', 'promote'

        Returns:
            tuple: (allowed: bool, reason: str, decision_id: str)
        """
        if hasattr(target_user, "to_dict"):
            target_dict = target_user.to_dict()
        else:
            target_dict = target_user

        input_data = {
            "user": {
                "id": admin_claims.get("sub"),
                "role": admin_claims.get("user_class"),
                "department": admin_claims.get("department"),
                "facility": admin_claims.get("facility"),
                "clearance": admin_claims.get("clearance_level", "BASIC"),
            },
            "resource": {
                "type": "user",
                "id": target_dict.get("id"),
                "role": target_dict.get("user_class"),
                "department": target_dict.get("department"),
                "facility": target_dict.get("facility"),
            },
            "action": action,
            "environment": {"time": {"hour": datetime.now().hour}},
            "request_id": admin_claims.get("request_id", "unknown"),
        }

        return self.evaluate_policy(input_data, policy_path="zta/user_management")


# Create instance but don't initialize with config yet
opa_client_instance = OPAClient()


def init_opa_client(app):
    """Initialize OPA client with Flask app"""
    opa_client_instance.init_app(app)


# Function to get the client (for imports)
def get_opa_client():
    return opa_client_instance
