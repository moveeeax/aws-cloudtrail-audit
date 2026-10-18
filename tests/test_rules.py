import pytest

from aws_cloudtrail_audit.rules import RULE_NAMES, evaluate


def rules_fired(findings):
    return sorted({f.rule for f in findings})


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def test_well_configured_trail_is_silent(fixture):
    assert evaluate(fixture("well-configured")) == []


def test_single_region_trail_names_the_uncovered_regions(fixture):
    payload = fixture("single-region")
    findings = by_rule(evaluate(payload), "not-multi-region")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.trail == "legacy-ireland-trail"
    assert finding.detail["uncovered_regions"] == ["eu-central-1", "us-east-1"]
    assert "eu-central-1" in finding.message


def test_flipping_multi_region_clears_the_rule(fixture):
    payload = fixture("single-region")
    payload["trails"][0]["IsMultiRegionTrail"] = True

    assert by_rule(evaluate(payload), "not-multi-region") == []


def test_uncovered_regions_also_raise_no_trail(fixture):
    findings = by_rule(evaluate(fixture("single-region")), "no-trail")

    assert len(findings) == 1
    assert findings[0].detail["uncovered_regions"] == ["eu-central-1", "us-east-1"]


def test_account_without_any_trail(fixture):
    findings = by_rule(evaluate(fixture("no-trails")), "no-trail")

    assert len(findings) == 1
    assert findings[0].trail is None
    assert "no CloudTrail trail exists" in findings[0].message


def test_logging_stopped_fires_on_an_otherwise_perfect_trail(fixture):
    payload = fixture("neglected")
    findings = by_rule(evaluate(payload), "logging-stopped")

    assert [f.trail for f in findings] == ["paused-forensics-trail"]
    assert "2026-07-04T02:13:51+00:00" in findings[0].message

    trail = [t for t in payload["trails"] if t["Name"] == "paused-forensics-trail"][0]
    assert trail["LogFileValidationEnabled"] is True
    assert trail["KmsKeyId"]
    assert trail["CloudWatchLogsLogGroupArn"]
    assert rules_fired(evaluate({"regions": [], "trails": [trail]})) == [
        "logging-stopped"
    ]


def test_one_trail_can_produce_several_independent_findings(fixture):
    findings = [
        f for f in evaluate(fixture("neglected")) if f.trail == "bootstrap-trail"
    ]

    assert rules_fired(findings) == [
        "management-events-partial",
        "no-cloudwatch-logs",
        "no-data-events",
        "no-global-events",
        "no-kms-encryption",
        "no-log-validation",
    ]


@pytest.mark.parametrize(
    "key,rule",
    [
        ("LogFileValidationEnabled", "no-log-validation"),
        ("KmsKeyId", "no-kms-encryption"),
        ("CloudWatchLogsLogGroupArn", "no-cloudwatch-logs"),
        ("IncludeGlobalServiceEvents", "no-global-events"),
    ],
)
def test_each_missing_attribute_owns_its_rule(fixture, key, rule):
    payload = fixture("well-configured")
    assert by_rule(evaluate(payload), rule) == []

    del payload["trails"][0][key]
    findings = by_rule(evaluate(payload), rule)

    assert len(findings) == 1
    assert findings[0].trail == "org-audit-trail"


def test_aws_managed_key_counts_as_unencrypted(fixture):
    payload = fixture("well-configured")
    payload["trails"][0]["KmsKeyId"] = "alias/aws/cloudtrail"

    findings = by_rule(evaluate(payload), "no-kms-encryption")

    assert len(findings) == 1
    assert "AWS-managed key" in findings[0].message


def test_no_data_events_fires_exactly_once_per_trail(fixture):
    payload = fixture("neglected")
    findings = by_rule(evaluate(payload), "no-data-events")

    assert [f.trail for f in findings] == ["bootstrap-trail"]


def test_advanced_data_selector_satisfies_the_data_event_rule(fixture):
    payload = fixture("neglected")
    trail = [t for t in payload["trails"] if t["Name"] == "paused-forensics-trail"][0]

    assert by_rule(evaluate({"regions": [], "trails": [trail]}), "no-data-events") == []

    trail["AdvancedEventSelectors"] = [
        s for s in trail["AdvancedEventSelectors"] if s["Name"] != "S3 object activity"
    ]
    assert len(by_rule(evaluate({"regions": [], "trails": [trail]}), "no-data-events")) == 1


def test_partial_management_events(fixture):
    payload = fixture("neglected")
    findings = by_rule(evaluate(payload), "management-events-partial")

    assert [f.trail for f in findings] == ["bootstrap-trail"]
    assert findings[0].detail["read_write_types"] == ["WriteOnly"]

    payload["trails"][0]["EventSelectors"][0]["ReadWriteType"] = "All"
    assert by_rule(evaluate(payload), "management-events-partial") == []


def test_ignore_rule_suppresses_only_its_target(fixture):
    payload = fixture("neglected")
    baseline = rules_fired(evaluate(payload))

    kept = rules_fired(evaluate(payload, ignore_rules=["no-log-validation"]))

    assert "no-log-validation" in baseline
    assert kept == [r for r in baseline if r != "no-log-validation"]


def test_ignore_trail_suppresses_only_its_target(fixture):
    payload = fixture("neglected")
    kept = evaluate(payload, ignore_trails=["bootstrap-trail"])

    assert {f.trail for f in kept} == {"paused-forensics-trail"}


def test_severity_floor(fixture):
    payload = fixture("neglected")

    assert {f.severity for f in evaluate(payload, min_severity="high")} == {"high"}
    assert {f.severity for f in evaluate(payload, min_severity="medium")} == {
        "high",
        "medium",
    }


def test_findings_are_ordered_deterministically(fixture):
    payload = fixture("neglected")
    first = [(f.trail, f.rule) for f in evaluate(payload)]

    assert first == sorted(first, key=lambda p: (p[0], RULE_NAMES.index(p[1])))
    assert first == [(f.trail, f.rule) for f in evaluate(payload)]


def test_rules_tolerate_a_sparse_payload():
    assert rules_fired(evaluate({})) == ["no-trail"]
    assert rules_fired(evaluate({"trails": [{}], "regions": []})) == [
        "no-cloudwatch-logs",
        "no-data-events",
        "no-global-events",
        "no-kms-encryption",
        "no-log-validation",
        "not-multi-region",
    ]
