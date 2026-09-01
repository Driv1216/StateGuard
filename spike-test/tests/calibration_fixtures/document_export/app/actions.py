archive_rows: dict[str, dict] = {}


def deliver_export_bundle(payload: dict) -> str:
    key = f"archive:{payload['job_id']}"
    archive_rows[key] = {"recipient": payload["recipient"], "uri": payload["uri"]}
    return key


def notify_export_operator(payload: dict) -> str:
    return f"operator:{payload['job_id']}"

