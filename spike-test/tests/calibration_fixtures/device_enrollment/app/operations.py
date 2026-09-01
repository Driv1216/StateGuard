device_profiles: dict[str, dict] = {}
refund_rows: dict[str, dict] = {}


def activate_device_profile(payload: dict) -> str:
    key = f"device:{payload['serial']}"
    device_profiles[key] = {"owner": payload["owner"], "mode": "online"}
    return key


def issue_refund_record(payload: dict) -> str:
    key = f"refund:{payload['serial']}"
    refund_rows[key] = {"owner": payload["owner"]}
    return key

