import re
from datetime import datetime


class PrivacyTransformer:

    def __init__(self):
        # Consistent mappings across the entire dataset
        self.actor_map = {}
        self.ip_map = {}

    # =========================================================
    # L1 — PSEUDONYMIZATION
    # =========================================================

    def pseudonymize_actor(self, actor):
        """Replace actor with a consistent pseudonym."""

        if actor in [None, "", "N/A"]:
            return "N/A"

        if actor not in self.actor_map:
            number = len(self.actor_map) + 1
            self.actor_map[actor] = f"USER_{number:03d}"

        return self.actor_map[actor]

    def pseudonymize_ip(self, ip):
        """Replace IP with a consistent pseudonym."""

        if ip in [None, "", "0.0.0.0"]:
            return "UNKNOWN_IP"

        if ip not in self.ip_map:
            number = len(self.ip_map) + 1
            self.ip_map[ip] = f"IP_{number:03d}"

        return self.ip_map[ip]

    # =========================================================
    # L2 — MASKING
    # =========================================================

    def mask_actor(self, actor):
        """Mask actor identity."""

        if actor in [None, "", "N/A"]:
            return "N/A"

        return "USER_***"

    def mask_ip(self, ip):
        """Mask the last two octets of an IPv4 address."""

        if not ip or ip in ["0.0.0.0"]:
            return "UNKNOWN_IP"

        parts = ip.split(".")

        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"

        return "MASKED_IP"

    # =========================================================
    # TIMESTAMP GENERALIZATION
    # =========================================================

    def generalize_timestamp(self, timestamp, level):
        """
        L2 → minute precision
        L3 → hour precision
        """

        try:
            dt = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if level == 2:
                dt = dt.replace(
                    second=0,
                    microsecond=0
                )

            elif level == 3:
                dt = dt.replace(
                    minute=0,
                    second=0,
                    microsecond=0
                )

            return dt.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        except (ValueError, AttributeError):
            return timestamp

    # =========================================================
    # ACTION GENERALIZATION
    # =========================================================

    def categorize_action(self, action):

        if not action:
            return "UNKNOWN_ACTION"

        action_upper = action.upper()

        # System commands
        if action_upper.startswith("COMMAND="):
            return "SYSTEM_COMMAND"

        # Login/authentication
        if "LOGIN" in action_upper:
            return "AUTHENTICATION"

        if "SUDO" in action_upper or "SU/" in action_upper:
            return "PRIVILEGED_ACCESS"

        # File access
        if "/FILES/" in action_upper:
            return "FILE_ACCESS"

        # Sensitive resources
        if (
            "SHADOW" in action_upper
            or "PASSWD" in action_upper
            or "EXPORT_DB" in action_upper
        ):
            return "SENSITIVE_RESOURCE_ACCESS"

        # General web access
        if action_upper.startswith("GET "):
            return "WEB_ACCESS"

        # Network connection
        if action_upper.startswith("CONNECT"):
            return "NETWORK_CONNECTION"

        return "OTHER_ACTION"

    # =========================================================
    # L3 ACTOR GENERALIZATION
    # =========================================================

    def generalize_actor(self, actor):

        if actor in [None, "", "N/A"]:
            return "N/A"

        return "USER"

    # =========================================================
    # L3 IP GENERALIZATION
    # =========================================================

    def generalize_ip(self, ip):

        if not ip or ip == "0.0.0.0":
            return "UNKNOWN_NETWORK"

        parts = ip.split(".")

        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0/16"

        return "GENERALIZED_NETWORK"

    # =========================================================
    # RESULT GENERALIZATION
    # =========================================================

    def categorize_result(self, result):

        if result in ["SUCCESS", "ALLOW"]:
            return "SUCCESSFUL"

        if result in ["FAILED", "DENIED"]:
            return "UNSUCCESSFUL"

        return "UNKNOWN_RESULT"

    # =========================================================
    # ATTACK TYPE GENERALIZATION
    # =========================================================

    def categorize_attack(self, attack_type):

        if attack_type == "NONE":
            return "NONE"

        if attack_type == "BRUTE_FORCE":
            return "AUTH_ATTACK"

        if attack_type == "WEB_RECON":
            return "WEB_ATTACK"

        if attack_type == "DATA_EXFILTRATION":
            return "DATA_ATTACK"

        return "OTHER_ATTACK"