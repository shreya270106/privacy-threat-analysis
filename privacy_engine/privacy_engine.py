import copy
import json

from .transformations import PrivacyTransformer


class PrivacyEngine:

    def __init__(self):
        self.transformer = PrivacyTransformer()

    # =========================================================
    # L0 — RAW
    # =========================================================

    def apply_l0(self, logs):
        """
        L0 keeps the normalized logs unchanged.
        A deep copy is returned so the original data
        is never modified.
        """

        return copy.deepcopy(logs)

    # =========================================================
    # L1 — LOW PRIVACY
    # =========================================================

    def apply_l1(self, logs):
        """
        L1 applies pseudonymization to direct identifiers.
        """

        transformed = []

        for log in logs:

            record = copy.deepcopy(log)

            record["actor"] = (
                self.transformer.pseudonymize_actor(
                    record["actor"]
                )
            )

            record["source_ip"] = (
                self.transformer.pseudonymize_ip(
                    record["source_ip"]
                )
            )

            transformed.append(record)

        return transformed

    # =========================================================
    # L2 — MEDIUM PRIVACY
    # =========================================================

    def apply_l2(self, logs):
        """
        L2 applies masking and partial generalization.
        """

        transformed = []

        for log in logs:

            record = copy.deepcopy(log)

            # Mask direct identifiers
            record["actor"] = (
                self.transformer.mask_actor(
                    record["actor"]
                )
            )

            record["source_ip"] = (
                self.transformer.mask_ip(
                    record["source_ip"]
                )
            )

            # Reduce timestamp precision
            record["timestamp"] = (
                self.transformer.generalize_timestamp(
                    record["timestamp"],
                    level=2
                )
            )

            # Generalize detailed actions
            record["action"] = (
                self.transformer.categorize_action(
                    record["action"]
                )
            )

            transformed.append(record)

        return transformed

    # =========================================================
    # L3 — HIGH PRIVACY
    # =========================================================

    def apply_l3(self, logs):
        """
        L3 applies strong generalization.
        """

        transformed = []

        for log in logs:

            record = copy.deepcopy(log)

            # Generalize actor
            record["actor"] = (
                self.transformer.generalize_actor(
                    record["actor"]
                )
            )

            # Generalize IP to network
            record["source_ip"] = (
                self.transformer.generalize_ip(
                    record["source_ip"]
                )
            )

            # Reduce timestamp to hour
            record["timestamp"] = (
                self.transformer.generalize_timestamp(
                    record["timestamp"],
                    level=3
                )
            )

            # Generalize action
            record["action"] = (
                self.transformer.categorize_action(
                    record["action"]
                )
            )

            # Generalize result
            record["result"] = (
                self.transformer.categorize_result(
                    record["result"]
                )
            )

            # Generalize attack type
            record["attack_type"] = (
                self.transformer.categorize_attack(
                    record["attack_type"]
                )
            )

            transformed.append(record)

        return transformed

    # =========================================================
    # SAVE OUTPUT
    # =========================================================

    @staticmethod
    def save_json(logs, filepath):

        with open(
            filepath,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                logs,
                f,
                indent=2
            )

        print(
            f"Saved {len(logs)} records → {filepath}"
        )


# =============================================================
# MAIN EXECUTION
# =============================================================

if __name__ == "__main__":

    from .log_parser import LogParser

    parser = LogParser()

    logs = parser.parse_file(
        "data/raw_logs.json"
    )

    print(
        f"Loaded {len(logs)} normalized logs."
    )

    engine = PrivacyEngine()

    # Generate all privacy levels

    l0 = engine.apply_l0(logs)
    l1 = engine.apply_l1(logs)
    l2 = engine.apply_l2(logs)
    l3 = engine.apply_l3(logs)

    # Save outputs

    engine.save_json(
        l0,
        "output/L0_raw.json"
    )

    engine.save_json(
        l1,
        "output/L1_low.json"
    )

    engine.save_json(
        l2,
        "output/L2_med.json"
    )

    engine.save_json(
        l3,
        "output/L3_high.json"
    )

    print("\nPrivacy Engine completed successfully.")