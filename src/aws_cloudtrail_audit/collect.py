"""boto3 collection.

The only job here is to turn a live account into the same plain dict that the
test fixtures contain. Everything downstream works on that dict, so the rule
engine never imports boto3 and the suite runs with no credentials.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from . import SCHEMA_VERSION

TRAIL_KEYS = (
    "Name",
    "TrailARN",
    "HomeRegion",
    "S3BucketName",
    "S3KeyPrefix",
    "KmsKeyId",
    "CloudWatchLogsLogGroupArn",
    "CloudWatchLogsRoleArn",
    "IsMultiRegionTrail",
    "IsOrganizationTrail",
    "IncludeGlobalServiceEvents",
    "LogFileValidationEnabled",
)

STATUS_KEYS = (
    "IsLogging",
    "LatestDeliveryTime",
    "LatestDeliveryError",
    "StartLoggingTime",
    "StopLoggingTime",
)


def _jsonable(value: Any) -> Any:
    if isinstance(value, _dt.datetime):
        return value.astimezone(_dt.UTC).isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _pick(source: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: _jsonable(source[k]) for k in keys if k in source}


def enabled_regions(session: Any) -> list[str]:
    ec2 = session.client("ec2")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in response.get("Regions", []))


def _account_id(session: Any) -> str | None:
    try:
        return session.client("sts").get_caller_identity().get("Account")
    except Exception:  # pragma: no cover - depends on live credentials
        return None


def _selectors(client: Any, arn: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        response = client.get_event_selectors(TrailName=arn)
    except Exception:  # pragma: no cover - depends on live credentials
        return out
    for key in ("EventSelectors", "AdvancedEventSelectors"):
        if response.get(key):
            out[key] = _jsonable(response[key])
    return out


def collect(session: Any, regions: list[str] | None = None) -> dict[str, Any]:
    """Walk every enabled region and return the raw audit payload."""
    regions = regions or enabled_regions(session)

    trails: dict[str, dict[str, Any]] = {}
    for region in regions:
        client = session.client("cloudtrail", region_name=region)
        described = client.describe_trails(includeShadowTrails=False)
        for raw in described.get("trailList", []):
            arn = raw.get("TrailARN")
            if not arn or arn in trails:
                continue
            trail = _pick(raw, TRAIL_KEYS)
            try:
                status = client.get_trail_status(Name=arn)
            except Exception:  # pragma: no cover - depends on live credentials
                status = {}
            trail["Status"] = _pick(status, STATUS_KEYS)
            trail.update(_selectors(client, arn))
            trails[arn] = trail

    return {
        "schema_version": SCHEMA_VERSION,
        "account_id": _account_id(session),
        "regions": regions,
        "trails": [trails[arn] for arn in sorted(trails)],
    }
