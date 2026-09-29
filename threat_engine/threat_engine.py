"""
Main Threat Engine.

Runs the same detector against L0, L1, L2 and L3 logs.
"""

import json
from pathlib import Path

from threat_engine.detector import detect_attack
from threat_engine.metrics import evaluate_predictions, print_metrics


LEVEL_FILES = {
    "L0": "output/L0_raw.json",
    "L1": "output/L1_low.json",
    "L2": "output/L2_med.json",
    "L3": "output/L3_high.json",
}


def load_logs(path):
    """Load JSON log records."""

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def run_level(level, path):
    """Run threat detection for one privacy level."""

    logs = load_logs(path)

    predictions = [
        detect_attack(log)
        for log in logs
    ]

    metrics = evaluate_predictions(
        logs,
        predictions
    )

    print(f"\n{'=' * 60}")
    print(f"PRIVACY LEVEL: {level}")
    print(f"{'=' * 60}")

    print_metrics(metrics)

    return {
        "level": level,
        "metrics": metrics,
    }


def main():
    """Run Threat Engine across all privacy levels."""

    results = {}

    for level, path in LEVEL_FILES.items():

        if not Path(path).exists():
            print(f"Skipping {level}: {path} not found.")
            continue

        results[level] = run_level(level, path)

    print("\n\n=== PRIVACY VS THREAT UTILITY ===")

    for level, result in results.items():

        metrics = result["metrics"]

        print(
            f"{level}: "
            f"Accuracy={metrics['accuracy']:.4f}, "
            f"Detection Rate={metrics['attack_detection_rate']:.4f}"
        )


if __name__ == "__main__":
    main()