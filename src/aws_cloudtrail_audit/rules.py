"""Rule engine.

Every rule takes the plain dict produced by :mod:`aws_cloudtrail_audit.collect`
(or loaded from a cached JSON payload) and returns findings. No rule touches the
network, which is what makes the whole suite testable from JSON fixtures.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high")

DATA_EVENT_RESOURCE_TYPES = (
    "AWS::S3::Object",
    "AWS::Lambda::Function",
)

# The managed key is not a customer-managed key, so a trail pointing at it is
# treated as unencrypted for audit purposes.
MANAGED_KEY_HINTS = ("alias/aws/", "/aws/")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    trail: str | None = None
    region: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "trail": self.trail,
            "region": self.region,
            "message": self.message,
            "detail": self.detail,
        }


def _truthy(trail: dict[str, Any], key: str) -> bool:
    return bool(trail.get(key))


def _trail_name(trail: dict[str, Any]) -> str:
    return trail.get("Name") or trail.get("TrailARN") or "<unnamed>"


def _regions(payload: dict[str, Any]) -> list[str]:
    return sorted({r for r in payload.get("regions") or [] if r})


def _trails(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in payload.get("trails") or [] if isinstance(t, dict)]


def _covered_regions(trail: dict[str, Any], all_regions: Iterable[str]) -> set[str]:
    if _truthy(trail, "IsMultiRegionTrail"):
        return set(all_regions)
    home = trail.get("HomeRegion")
    return {home} if home else set()


def _status(trail: dict[str, Any]) -> dict[str, Any]:
    status = trail.get("Status")
    return status if isinstance(status, dict) else {}


def _advanced_selectors(trail: dict[str, Any]) -> list[dict[str, Any]]:
    sel = trail.get("AdvancedEventSelectors")
    return [s for s in sel or [] if isinstance(s, dict)]


def _basic_selectors(trail: dict[str, Any]) -> list[dict[str, Any]]:
    sel = trail.get("EventSelectors")
    return [s for s in sel or [] if isinstance(s, dict)]


def _advanced_field(selector: dict[str, Any], name: str) -> list[str]:
    values: list[str] = []
    for item in selector.get("FieldSelectors") or []:
        if not isinstance(item, dict) or item.get("Field") != name:
            continue
        for key in ("Equals", "StartsWith", "EndsWith", "NotEquals"):
            values.extend(str(v) for v in item.get(key) or [])
    return values


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------


def rule_no_trail(payload: dict[str, Any]) -> list[Finding]:
    """A region (or the whole account) that no trail covers at all."""
    trails = _trails(payload)
    regions = _regions(payload)

    if not trails:
        return [
            Finding(
                rule="no-trail",
                severity="high",
                message=(
                    "no CloudTrail trail exists in this account: "
                    "there is no record of any API call"
                ),
                detail={"uncovered_regions": regions},
            )
        ]

    covered: set[str] = set()
    for trail in trails:
        covered |= _covered_regions(trail, regions)

    uncovered = sorted(set(regions) - covered)
    if not uncovered:
        return []
    return [
        Finding(
            rule="no-trail",
            severity="high",
            message=(
                f"{len(uncovered)} enabled region(s) are covered by no trail: "
                + ", ".join(uncovered)
            ),
            detail={"uncovered_regions": uncovered},
        )
    ]


def rule_not_multi_region(payload: dict[str, Any]) -> list[Finding]:
    regions = _regions(payload)
    findings = []
    for trail in _trails(payload):
        if _truthy(trail, "IsMultiRegionTrail"):
            continue
        home = trail.get("HomeRegion")
        uncovered = sorted(set(regions) - ({home} if home else set()))
        suffix = (
            ", leaving " + ", ".join(uncovered) + " unseen"
            if uncovered
            else ""
        )
        findings.append(
            Finding(
                rule="not-multi-region",
                severity="high",
                trail=_trail_name(trail),
                region=home,
                message=(
                    f"trail only records events in {home or 'its home region'}"
                    f"{suffix}"
                ),
                detail={"home_region": home, "uncovered_regions": uncovered},
            )
        )
    return findings


def rule_logging_stopped(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        status = _status(trail)
        if "IsLogging" not in status:
            continue
        if status.get("IsLogging"):
            continue
        stopped = status.get("StopLoggingTime")
        when = f" since {stopped}" if stopped else " (stop time unknown)"
        findings.append(
            Finding(
                rule="logging-stopped",
                severity="high",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=f"StopLogging was called: the trail records nothing{when}",
                detail={
                    "stop_logging_time": stopped,
                    "latest_delivery_time": status.get("LatestDeliveryTime"),
                },
            )
        )
    return findings


def rule_no_log_validation(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        if _truthy(trail, "LogFileValidationEnabled"):
            continue
        findings.append(
            Finding(
                rule="no-log-validation",
                severity="medium",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    "log file validation is off: a modified or deleted log "
                    "object cannot be detected"
                ),
            )
        )
    return findings


def rule_no_kms_encryption(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        key = (trail.get("KmsKeyId") or "").strip()
        if key and not any(hint in key for hint in MANAGED_KEY_HINTS):
            continue
        reason = (
            f"the AWS-managed key {key}" if key else "SSE-S3 only, no KMS key set"
        )
        findings.append(
            Finding(
                rule="no-kms-encryption",
                severity="medium",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    f"log objects are not encrypted with a customer-managed key "
                    f"({reason})"
                ),
                detail={"kms_key_id": key or None},
            )
        )
    return findings


def rule_no_cloudwatch_logs(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        if (trail.get("CloudWatchLogsLogGroupArn") or "").strip():
            continue
        findings.append(
            Finding(
                rule="no-cloudwatch-logs",
                severity="medium",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    "no CloudWatch Logs destination: no metric filter and no "
                    "alarm can ever fire on an API call"
                ),
            )
        )
    return findings


def rule_no_global_events(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        if _truthy(trail, "IncludeGlobalServiceEvents"):
            continue
        findings.append(
            Finding(
                rule="no-global-events",
                severity="high",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    "global service events are off: IAM, STS and CloudFront "
                    "activity is invisible"
                ),
            )
        )
    return findings


def _has_data_events(trail: dict[str, Any]) -> bool:
    for selector in _basic_selectors(trail):
        for resource in selector.get("DataResources") or []:
            if not isinstance(resource, dict):
                continue
            if resource.get("Type") in DATA_EVENT_RESOURCE_TYPES:
                return True
    for selector in _advanced_selectors(trail):
        if "Data" in _advanced_field(selector, "eventCategory"):
            return True
    return False


def rule_no_data_events(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        if _has_data_events(trail):
            continue
        findings.append(
            Finding(
                rule="no-data-events",
                severity="medium",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    "no event selector covers S3 object-level or Lambda invoke "
                    "activity: the trail sees PutBucketPolicy but not the "
                    "object deletions"
                ),
            )
        )
    return findings


def rule_management_events_partial(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for trail in _trails(payload):
        partial: list[str] = []
        for selector in _basic_selectors(trail):
            rw = selector.get("ReadWriteType")
            if rw and rw != "All":
                partial.append(rw)
        for selector in _advanced_selectors(trail):
            categories = _advanced_field(selector, "eventCategory")
            if categories and "Management" not in categories:
                continue
            read_only = _advanced_field(selector, "readOnly")
            if read_only:
                partial.append("readOnly=" + ",".join(sorted(set(read_only))))
        if not partial:
            continue
        findings.append(
            Finding(
                rule="management-events-partial",
                severity="low",
                trail=_trail_name(trail),
                region=trail.get("HomeRegion"),
                message=(
                    "management events are filtered rather than All: "
                    + ", ".join(sorted(set(partial)))
                ),
                detail={"read_write_types": sorted(set(partial))},
            )
        )
    return findings


RULES: dict[str, Callable[[dict[str, Any]], list[Finding]]] = {
    "no-trail": rule_no_trail,
    "not-multi-region": rule_not_multi_region,
    "logging-stopped": rule_logging_stopped,
    "no-log-validation": rule_no_log_validation,
    "no-kms-encryption": rule_no_kms_encryption,
    "no-cloudwatch-logs": rule_no_cloudwatch_logs,
    "no-global-events": rule_no_global_events,
    "no-data-events": rule_no_data_events,
    "management-events-partial": rule_management_events_partial,
}

RULE_NAMES = tuple(RULES)


def evaluate(
    payload: dict[str, Any],
    *,
    ignore_rules: Iterable[str] = (),
    ignore_trails: Iterable[str] = (),
    min_severity: str = "low",
) -> list[Finding]:
    """Run every enabled rule and return findings in a stable order."""
    ignored_rules = set(ignore_rules)
    ignored_trails = set(ignore_trails)
    floor = SEVERITIES.index(min_severity)

    findings: list[Finding] = []
    for name, rule in RULES.items():
        if name in ignored_rules:
            continue
        for finding in rule(payload):
            if finding.trail and finding.trail in ignored_trails:
                continue
            if SEVERITIES.index(finding.severity) < floor:
                continue
            findings.append(finding)

    order = {name: i for i, name in enumerate(RULE_NAMES)}
    findings.sort(key=lambda f: (f.trail or "", order[f.rule]))
    return findings
