import json
import sys

import pytest

from aws_cloudtrail_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_text_output_groups_by_trail(capsys, fixtures_dir):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "neglected.json"))

    assert code == 0
    assert "bootstrap-trail" in out
    assert "paused-forensics-trail" in out
    assert "logging-stopped" in out
    assert out.rstrip().endswith("7 finding(s): 2 high, 4 medium, 1 low")


def test_clean_account_says_so(capsys, fixtures_dir):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "well-configured.json"))

    assert code == 0
    assert "No findings." in out


def test_json_output_is_parseable(capsys, fixtures_dir):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "neglected.json"), "--format", "json"
    )
    document = json.loads(out)

    assert code == 0
    assert document["account_id"] == "444455556666"
    assert document["trail_count"] == 2
    assert document["finding_count"] == len(document["findings"])
    assert {f["rule"] for f in document["findings"]} >= {"logging-stopped"}


def test_fail_on_a_rule_that_fired_exits_1(capsys, fixtures_dir):
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "neglected.json"),
        "--fail-on",
        "logging-stopped,no-log-validation",
    )

    assert code == 1


def test_fail_on_a_rule_that_did_not_fire_exits_0(capsys, fixtures_dir):
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "neglected.json"),
        "--fail-on",
        "not-multi-region",
    )

    assert code == 0


def test_unknown_rule_name_exits_2(capsys, fixtures_dir):
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--from-json",
                str(fixtures_dir / "neglected.json"),
                "--fail-on",
                "no-such-rule",
            ]
        )

    assert excinfo.value.code == 2
    assert "unknown rule name" in capsys.readouterr().err


def test_unknown_ignore_rule_also_exits_2(capsys, fixtures_dir):
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--from-json",
                str(fixtures_dir / "neglected.json"),
                "--ignore-rule",
                "nope",
            ]
        )

    assert excinfo.value.code == 2
    capsys.readouterr()


def test_ignore_trail_removes_it_from_the_report(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "neglected.json"),
        "--ignore-trail",
        "bootstrap-trail",
    )

    assert code == 0
    assert "bootstrap-trail" not in out
    assert "paused-forensics-trail" in out


def test_severity_filter_drops_the_quiet_rules(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "neglected.json"),
        "--severity",
        "high",
        "--format",
        "json",
    )

    assert code == 0
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}


def test_missing_payload_file_exits_2(capsys, tmp_path):
    code, _, err = run(capsys, "--from-json", str(tmp_path / "absent.json"))

    assert code == 2
    assert "absent.json" in err


def test_broken_payload_file_exits_2(capsys, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    code, _, err = run(capsys, "--from-json", str(broken))

    assert code == 2
    assert "invalid payload JSON" in err


def test_from_json_never_touches_the_network(capsys, fixtures_dir, monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)

    code, first, _ = run(
        capsys, "--from-json", str(fixtures_dir / "neglected.json"), "--format", "json"
    )
    _, second, _ = run(
        capsys, "--from-json", str(fixtures_dir / "neglected.json"), "--format", "json"
    )

    assert code == 0
    assert first == second


def test_dump_json_round_trips(capsys, fixtures_dir, tmp_path):
    dumped = tmp_path / "payload.json"
    run(
        capsys,
        "--from-json",
        str(fixtures_dir / "neglected.json"),
        "--dump-json",
        str(dumped),
        "--format",
        "json",
    )
    _, replayed, _ = run(capsys, "--from-json", str(dumped), "--format", "json")
    _, original, _ = run(
        capsys, "--from-json", str(fixtures_dir / "neglected.json"), "--format", "json"
    )

    assert replayed == original


def test_list_rules(capsys):
    code, out, _ = run(capsys, "--list-rules")

    assert code == 0
    assert "logging-stopped" in out.split()
