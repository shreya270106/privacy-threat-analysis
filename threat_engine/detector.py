"""
Privacy-aware rule-based Threat Detection Engine.

The detector uses only observable log fields for prediction.
Ground-truth fields (is_attack and attack_type) are never
used to make predictions.
"""


def detect_attack(log):
    """
    Detect the likely attack type for a single log record.

    Returns:
        BRUTE_FORCE
        WEB_RECON
        DATA_EXFILTRATION
        NONE
    """

    source_type = str(log.get("source_type", "")).upper()
    action = str(log.get("action", "")).upper()
    result = str(log.get("result", "")).upper()

    resource_details = log.get("resource_details", {})

    if not isinstance(resource_details, dict):
        resource_details = {}

    action_lower = action.lower()

    user_agent = str(
        resource_details.get("user_agent", "")
    ).lower()

    # =========================================================
    # 1. BRUTE FORCE
    # =========================================================

    # Detailed representation: L0 / L1
    if (
        source_type == "AUTH"
        and "LOGIN_ATTEMPT" in action
        and result in {"FAILED", "UNSUCCESSFUL"}
    ):
        return "BRUTE_FORCE"

    # Generalized representation: L2 / L3
    #
    # L2 uses:
    #     AUTHENTICATION + FAILED
    #
    # L3 uses:
    #     AUTHENTICATION + UNSUCCESSFUL
    #
    # Both represent unsuccessful authentication activity.
    if (
        source_type == "AUTH"
        and action == "AUTHENTICATION"
        and result in {"FAILED", "UNSUCCESSFUL"}
    ):
        return "BRUTE_FORCE"

    # =========================================================
    # 2. WEB RECONNAISSANCE
    # =========================================================

    # Detailed representation: L0 / L1
    if (
        source_type == "WEB_ACCESS"
        and (
            "/etc/passwd" in action_lower
            or "traversal" in action_lower
            or "sqlmap" in user_agent
        )
    ):
        return "WEB_RECON"

    # We deliberately do NOT classify generic WEB_ACCESS
    # as an attack because L2/L3 remove the exact resource
    # information needed to identify reconnaissance reliably.

    # =========================================================
    # 3. DATA EXFILTRATION
    # =========================================================

    sensitive_resources = [
        "/api/v1/export_db",
        "/admin/shadow.bak",
        "/downloads/confidential_report.pdf",
    ]

    # Detailed representation: L0 / L1
    if (
        source_type == "FILE_DOWNLOAD"
        and result in {"SUCCESS", "SUCCESSFUL"}
        and any(
            resource in action_lower
            for resource in sensitive_resources
        )
    ):
        return "DATA_EXFILTRATION"

    # Generalized representation: L2 / L3
    #
    # Only the explicit sensitive-resource category is
    # treated as data exfiltration.
    if (
        action == "SENSITIVE_RESOURCE_ACCESS"
        and result in {"SUCCESS", "SUCCESSFUL"}
    ):
        return "DATA_EXFILTRATION"

    # =========================================================
    # No detected attack
    # =========================================================

    return "NONE"