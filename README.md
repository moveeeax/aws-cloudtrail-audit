# aws-cloudtrail-audit

[![ci](https://github.com/moveeeax/aws-cloudtrail-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-cloudtrail-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

CloudTrail is the only witness to an incident, and it is configured exactly once —
by whoever bootstrapped the account, years before anyone needs it. The day you go
looking for who deleted the bucket, you find out the trail was single-region, data
events were off, and log file validation was never enabled. What you have is a
story, not evidence.

`aws-cloudtrail-audit` asks the questions the compliance checklist does not: is the
trail multi-region, does it include global service events, is log file validation
on, is it encrypted with a customer-managed key, does anything reach CloudWatch
Logs, are S3 and Lambda data events selected, and has somebody called `StopLogging`
since.

## Rules

| rule | severity | what it means |
| --- | --- | --- |
| `no-trail` | high | an enabled region — or the whole account — that no trail covers |
| `not-multi-region` | high | `IsMultiRegionTrail` is false; the finding names the regions left unseen |
| `logging-stopped` | high | `StopLogging` was called; the finding carries `StopLoggingTime` |
| `no-global-events` | high | `IncludeGlobalServiceEvents` is off, so IAM, STS and CloudFront are invisible |
| `no-log-validation` | medium | `LogFileValidationEnabled` is false, so tampering is undetectable |
| `no-kms-encryption` | medium | no `KmsKeyId`, or the AWS-managed key, instead of a CMK you can audit grants on |
| `no-cloudwatch-logs` | medium | no `CloudWatchLogsLogGroupArn`, so no alarm can ever fire on an API call |
| `no-data-events` | medium | no selector covers S3 object-level or Lambda activity |
| `management-events-partial` | low | the selector's `ReadWriteType` is not `All` |

## Install

```console
$ pip install git+https://github.com/moveeeax/aws-cloudtrail-audit@v0.1.0
```

Collection needs read-only CloudTrail access — see
[`examples/iam-policy.json`](examples/iam-policy.json).

## Usage

```console
$ aws-cloudtrail-audit --profile prod
CloudTrail audit — account 444455556666, 2 trail(s), 3 region(s)

bootstrap-trail
  MEDIUM no-log-validation          log file validation is off: a modified or deleted log object cannot be detected
  MEDIUM no-kms-encryption          log objects are not encrypted with a customer-managed key (SSE-S3 only, no KMS key set)
  MEDIUM no-cloudwatch-logs         no CloudWatch Logs destination: no metric filter and no alarm can ever fire on an API call
  HIGH   no-global-events           global service events are off: IAM, STS and CloudFront activity is invisible
  MEDIUM no-data-events             no event selector covers S3 object-level or Lambda invoke activity: the trail sees PutBucketPolicy but not the object deletions
  LOW    management-events-partial  management events are filtered rather than All: WriteOnly

paused-forensics-trail
  HIGH   logging-stopped  StopLogging was called: the trail records nothing since 2026-07-04T02:13:51+00:00

7 finding(s): 2 high, 4 medium, 1 low
```

Cache the raw API payload and replay it offline:

```console
$ aws-cloudtrail-audit --profile prod --dump-json /tmp/trails.json
$ aws-cloudtrail-audit --from-json /tmp/trails.json --format json \
    | jq '.findings[] | select(.rule == "logging-stopped")'
```

Gate CI on the rules you actually care about:

```console
$ aws-cloudtrail-audit --fail-on logging-stopped,no-log-validation \
    --ignore-trail legacy-audit-trail
```

Exit codes: `0` clean (or nothing in `--fail-on` fired), `1` a `--fail-on` rule
fired, `2` a bad argument — including an unknown rule name, so a typo in
`--fail-on` never silently passes a pipeline.

### Flags

| flag | effect |
| --- | --- |
| `--profile NAME` | AWS profile to collect with |
| `--region REGION` | limit collection to this region (repeatable) |
| `--from-json FILE` | replay a cached payload; no network calls at all |
| `--dump-json FILE` | write the collected payload to `FILE` |
| `--format text\|json` | grouped table (default) or machine-readable JSON |
| `--severity low\|medium\|high` | minimum severity to report |
| `--ignore-rule RULE` | drop a rule entirely (repeatable) |
| `--ignore-trail NAME` | drop a trail entirely (repeatable) |
| `--fail-on RULES` | comma-separated rules that make the run exit `1` |
| `--list-rules` | print the rule names and exit |

## How it works

Collection and evaluation are separate on purpose. `collect.py` walks every
enabled region, pairs `describe_trails` with `get_trail_status` and
`get_event_selectors`, deduplicates by trail ARN (shadow trails of a multi-region
trail show up in every region) and returns one plain dict. `rules.py` takes that
dict and nothing else — it never imports `boto3`.

That split is what makes `--from-json` exact rather than approximate: the replay
path and the live path feed the rule engine the identical structure, so a payload
captured during an incident reproduces the same findings a year later. It is also
why the test suite is a pile of JSON fixtures that runs in CI with no AWS account
and no credentials.

## Development

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ ruff check src tests && pytest
```

## License

MIT
