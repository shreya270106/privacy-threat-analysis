import json
from datetime import datetime, timezone


class LogParser:

    REQUIRED_FIELDS = [
        "event_id",
        "source_type",
        "timestamp",
        "actor",
        "source_ip",
        "action",
        "resource_details",
        "result",
        "is_attack",
        "attack_type"
    ]

    def parse_file(self, filepath):
        """Load and normalize the complete JSON dataset."""

        with open(filepath, "r", encoding="utf-8") as f:
            raw_logs = json.load(f)

        return [self.normalize(log) for log in raw_logs]

    def normalize(self, log):
        """Normalize one log record."""

        normalized = {
            "event_id": log.get("event_id", "UNKNOWN_EVENT"),
            "source_type": log.get("source_type", "UNKNOWN"),
            "timestamp": self.normalize_timestamp(
                log.get("timestamp")
            ),
            "actor": log.get("actor", "UNKNOWN"),
            "source_ip": log.get("source_ip", "0.0.0.0"),
            "action": log.get("action", "UNKNOWN_ACTION"),
            "resource_details": log.get(
                "resource_details", {}
            ),
            "result": log.get("result", "UNKNOWN"),
            "is_attack": bool(
                log.get("is_attack", False)
            ),
            "attack_type": log.get(
                "attack_type", "NONE"
            )
        }

        return normalized

    def normalize_timestamp(self, timestamp):
        """Convert timestamp to ISO 8601 UTC format."""

        if not timestamp:
            return datetime.utcnow().strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        # If already ISO format, keep it.
        try:
            dt = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if dt.tzinfo is not None:
                dt = dt.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

            return dt.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        except ValueError:
            return timestamp


if __name__ == "__main__":

    parser = LogParser()

    logs = parser.parse_file(
        "data/raw_logs.json"
    )

    print(
        f"Successfully parsed {len(logs)} logs."
    )

    print("\nFirst normalized record:")
    print(json.dumps(
        logs[0],
        indent=2
    ))