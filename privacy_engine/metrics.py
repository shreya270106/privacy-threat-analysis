import json
from collections import Counter


class PrivacyMetrics:

    # =========================================================
    # BASIC DATA METRICS
    # =========================================================

    @staticmethod
    def unique_values(logs, field):
        """Count unique values for a field."""

        return len(
            set(
                str(log.get(field, "UNKNOWN"))
                for log in logs
            )
        )

    @staticmethod
    def record_count(logs):
        return len(logs)

    # =========================================================
    # ACTOR METRICS
    # =========================================================

    @staticmethod
    def actor_metrics(logs):

        actors = [
            log.get("actor", "UNKNOWN")
            for log in logs
        ]

        return {
            "unique_actors": len(set(actors)),
            "total_records": len(actors)
        }

    # =========================================================
    # IP METRICS
    # =========================================================

    @staticmethod
    def ip_metrics(logs):

        ips = [
            log.get("source_ip", "UNKNOWN")
            for log in logs
        ]

        return {
            "unique_ips": len(set(ips)),
            "total_records": len(ips)
        }

    # =========================================================
    # ACTION METRICS
    # =========================================================

    @staticmethod
    def action_metrics(logs):

        actions = [
            log.get("action", "UNKNOWN")
            for log in logs
        ]

        return {
            "unique_actions": len(set(actions)),
            "total_records": len(actions)
        }

    # =========================================================
    # RESULT METRICS
    # =========================================================

    @staticmethod
    def result_metrics(logs):

        results = [
            log.get("result", "UNKNOWN")
            for log in logs
        ]

        return {
            "unique_results": len(set(results)),
            "distribution": dict(
                Counter(results)
            )
        }

    # =========================================================
    # ATTACK METRICS
    # =========================================================

    @staticmethod
    def attack_metrics(logs):

        attacks = [
            log.get("attack_type", "NONE")
            for log in logs
        ]

        return {
            "unique_attack_types": len(
                set(attacks)
            ),
            "distribution": dict(
                Counter(attacks)
            )
        }

    # =========================================================
    # TIMESTAMP PRECISION
    # =========================================================

    @staticmethod
    def timestamp_metrics(logs):

        timestamps = [
            log.get("timestamp", "")
            for log in logs
        ]

        unique_timestamps = len(
            set(timestamps)
        )

        return {
            "unique_timestamps": unique_timestamps,
            "total_timestamps": len(timestamps)
        }

    # =========================================================
    # COMPLETE METRICS
    # =========================================================

    def calculate(self, logs):

        return {
            "records": self.record_count(logs),

            "actors": self.actor_metrics(logs),

            "source_ips": self.ip_metrics(logs),

            "actions": self.action_metrics(logs),

            "results": self.result_metrics(logs),

            "attacks": self.attack_metrics(logs),

            "timestamps": self.timestamp_metrics(logs)
        }

    # =========================================================
    # COMPARE PRIVACY LEVELS
    # =========================================================

    def compare_levels(self, levels):

        comparison = {}

        for level_name, logs in levels.items():

            metrics = self.calculate(logs)

            comparison[level_name] = {
                "records": metrics["records"],
                "unique_actors": metrics[
                    "actors"
                ]["unique_actors"],
                "unique_ips": metrics[
                    "source_ips"
                ]["unique_ips"],
                "unique_actions": metrics[
                    "actions"
                ]["unique_actions"],
                "unique_timestamps": metrics[
                    "timestamps"
                ]["unique_timestamps"],
                "unique_attack_types": metrics[
                    "attacks"
                ]["unique_attack_types"]
            }

        return comparison


# =============================================================
# LOAD JSON FILE
# =============================================================

def load_json(filepath):

    with open(
        filepath,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    metrics = PrivacyMetrics()

    levels = {
        "L0": load_json(
            "output/L0_raw.json"
        ),

        "L1": load_json(
            "output/L1_low.json"
        ),

        "L2": load_json(
            "output/L2_med.json"
        ),

        "L3": load_json(
            "output/L3_high.json"
        )
    }

    comparison = metrics.compare_levels(
        levels
    )

    print("\n======================================")
    print("       PRIVACY LEVEL COMPARISON")
    print("======================================\n")

    print(
        f"{'Level':<8}"
        f"{'Actors':<10}"
        f"{'IPs':<10}"
        f"{'Actions':<12}"
        f"{'Timestamps':<15}"
        f"{'Attack Types':<15}"
    )

    print("-" * 70)

    for level, data in comparison.items():

        print(
            f"{level:<8}"
            f"{data['unique_actors']:<10}"
            f"{data['unique_ips']:<10}"
            f"{data['unique_actions']:<12}"
            f"{data['unique_timestamps']:<15}"
            f"{data['unique_attack_types']:<15}"
        )