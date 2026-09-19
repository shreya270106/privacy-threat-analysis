"""
Threat Engine evaluation metrics.

Ground-truth labels are used ONLY after prediction,
for evaluating detector performance.
"""

ATTACK_LABEL_MAP = {
    "NONE": "NONE",
    "BRUTE_FORCE": "BRUTE_FORCE",
    "WEB_RECON": "WEB_RECON",
    "DATA_EXFILTRATION": "DATA_EXFILTRATION",

    # Privacy Engine generalized labels
    "AUTH_ATTACK": "BRUTE_FORCE",
    "WEB_ATTACK": "WEB_RECON",
    "DATA_ATTACK": "DATA_EXFILTRATION",
}


def evaluate_predictions(logs, predictions):
    """
    Compare predicted attack types against ground truth.

    Args:
        logs: Protected log records containing ground truth.
        predictions: Detector predictions in the same order.

    Returns:
        Dictionary containing accuracy, precision, recall, F1,
        attack detection rate, and per-class results.
    """

    if len(logs) != len(predictions):
        raise ValueError(
            "Logs and predictions must have the same length."
        )

    # Normalize ground-truth labels so that the generalized
    # labels used by L2/L3 can be compared with the detector's
    # original attack categories.
    ground_truth = [
        ATTACK_LABEL_MAP.get(
            log.get("attack_type", "NONE"),
            log.get("attack_type", "NONE")
        )
        for log in logs
    ]

    total = len(logs)

    # Overall accuracy
    correct = sum(
        actual == predicted
        for actual, predicted in zip(
            ground_truth,
            predictions
        )
    )

    accuracy = correct / total if total else 0.0

    # Attack classes used by the Threat Engine
    attack_classes = [
        "BRUTE_FORCE",
        "WEB_RECON",
        "DATA_EXFILTRATION",
    ]

    per_class = {}

    for attack_type in attack_classes:

        # True positives
        tp = sum(
            actual == attack_type
            and predicted == attack_type
            for actual, predicted in zip(
                ground_truth,
                predictions
            )
        )

        # False positives
        fp = sum(
            actual != attack_type
            and predicted == attack_type
            for actual, predicted in zip(
                ground_truth,
                predictions
            )
        )

        # False negatives
        fn = sum(
            actual == attack_type
            and predicted != attack_type
            for actual, predicted in zip(
                ground_truth,
                predictions
            )
        )

        # Precision
        precision = (
            tp / (tp + fp)
            if (tp + fp)
            else 0.0
        )

        # Recall
        recall = (
            tp / (tp + fn)
            if (tp + fn)
            else 0.0
        )

        # F1 score
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )

        per_class[attack_type] = {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    # Total number of actual attack records
    actual_attacks = sum(
        actual != "NONE"
        for actual in ground_truth
    )

    # Number of actual attacks detected as any attack
    detected_attacks = sum(
        actual != "NONE"
        and predicted != "NONE"
        for actual, predicted in zip(
            ground_truth,
            predictions
        )
    )

    # Overall attack detection rate
    attack_detection_rate = (
        detected_attacks / actual_attacks
        if actual_attacks
        else 0.0
    )

    return {
        "total_records": total,
        "correct_predictions": correct,
        "accuracy": accuracy,
        "attack_records": actual_attacks,
        "detected_attacks": detected_attacks,
        "attack_detection_rate": attack_detection_rate,
        "per_class": per_class,
    }


def print_metrics(metrics):
    """Print evaluation results in a readable format."""

    print("\n=== Threat Detection Results ===")

    print(
        f"Total records: "
        f"{metrics['total_records']}"
    )

    print(
        f"Correct predictions: "
        f"{metrics['correct_predictions']}"
    )

    print(
        f"Accuracy: "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Attack records: "
        f"{metrics['attack_records']}"
    )

    print(
        f"Detected attacks: "
        f"{metrics['detected_attacks']}"
    )

    print(
        f"Attack Detection Rate: "
        f"{metrics['attack_detection_rate']:.4f}"
    )

    print("\n--- Per Attack Type ---")

    for attack_type, values in metrics["per_class"].items():

        print(f"\n{attack_type}")

        print(
            f"  Precision: "
            f"{values['precision']:.4f}"
        )

        print(
            f"  Recall:    "
            f"{values['recall']:.4f}"
        )

        print(
            f"  F1:        "
            f"{values['f1']:.4f}"
        )

        print(
            f"  TP:        "
            f"{values['true_positive']}"
        )

        print(
            f"  FP:        "
            f"{values['false_positive']}"
        )

        print(
            f"  FN:        "
            f"{values['false_negative']}"
        )