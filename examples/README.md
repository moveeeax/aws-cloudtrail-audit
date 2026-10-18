# Examples

- `iam-policy.json` — the least-privilege policy the collector needs. Everything
  it calls is read-only: `DescribeTrails`, `GetTrailStatus`, `GetEventSelectors`,
  plus `ec2:DescribeRegions` to learn which regions are enabled.
- `ci-gate.yml` — a nightly GitHub Actions job that fails on the rules that mean
  the account cannot be investigated today, and uploads the raw payload so the
  run can be replayed later with `--from-json`.

The JSON fixtures under [`../tests/fixtures/`](../tests/fixtures) are real payload
shapes and double as a playground:

```console
$ aws-cloudtrail-audit --from-json tests/fixtures/neglected.json --format json \
    | jq -r '.findings[] | "\(.severity)\t\(.trail)\t\(.rule)"'
medium  bootstrap-trail         no-log-validation
medium  bootstrap-trail         no-kms-encryption
medium  bootstrap-trail         no-cloudwatch-logs
high    bootstrap-trail         no-global-events
medium  bootstrap-trail         no-data-events
low     bootstrap-trail         management-events-partial
high    paused-forensics-trail  logging-stopped
```
