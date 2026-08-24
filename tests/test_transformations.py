from privacy_engine.transformations import PrivacyTransformer


transformer = PrivacyTransformer()


print("=== L1 PSEUDONYMIZATION ===")

print(
    transformer.pseudonymize_actor("alice")
)

print(
    transformer.pseudonymize_actor("alice")
)

print(
    transformer.pseudonymize_ip("192.168.1.15")
)

print(
    transformer.pseudonymize_ip("192.168.1.15")
)


print("\n=== L2 MASKING ===")

print(
    transformer.mask_actor("alice")
)

print(
    transformer.mask_ip("192.168.1.15")
)


print("\n=== TIMESTAMP ===")

timestamp = "2026-08-21T10:04:54Z"

print(
    "Original:",
    timestamp
)

print(
    "L2:",
    transformer.generalize_timestamp(
        timestamp,
        2
    )
)

print(
    "L3:",
    transformer.generalize_timestamp(
        timestamp,
        3
    )
)


print("\n=== ACTION CATEGORIZATION ===")

actions = [
    "COMMAND=/usr/bin/uptime",
    "GET /files/doc1.pdf",
    "GET /admin/shadow.bak",
    "GET /index.html HTTP/1.1",
    "CONNECT 192.168.1.1:443"
]

for action in actions:
    print(
        action,
        "→",
        transformer.categorize_action(action)
    )


print("\n=== RESULT CATEGORIZATION ===")

for result in [
    "SUCCESS",
    "ALLOW",
    "FAILED",
    "DENIED"
]:
    print(
        result,
        "→",
        transformer.categorize_result(result)
    )


print("\n=== ATTACK CATEGORIZATION ===")

for attack in [
    "NONE",
    "BRUTE_FORCE",
    "WEB_RECON",
    "DATA_EXFILTRATION"
]:
    print(
        attack,
        "→",
        transformer.categorize_attack(attack)
    )