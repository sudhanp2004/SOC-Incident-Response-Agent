from pathlib import Path
from data_pipeline.parsers import parse_suricata, parse_cloudtrail, parse_dns, RawEvent

FIXTURES = Path(__file__).parent / "fixtures" / "bots_samples"


def _lines(name):
    return (FIXTURES / name).read_text().splitlines()


def test_parse_suricata_valid_line():
    event = parse_suricata(_lines("suricata_sample.jsonl")[0])
    assert isinstance(event, RawEvent)
    assert event.host == "10.0.2.10"
    assert event.event_type == "ET SCAN Potential SSH Scan"
    assert ("ip", "203.0.113.42") in event.indicators
    assert ("ip", "10.0.2.10") in event.indicators


def test_parse_suricata_malformed_line_returns_none():
    assert parse_suricata(_lines("suricata_sample.jsonl")[2]) is None


def test_parse_cloudtrail_valid_line():
    event = parse_cloudtrail(_lines("cloudtrail_sample.jsonl")[0])
    assert event.host == "198.51.100.77"
    assert event.user == "svc_finance"
    assert event.event_type == "ConsoleLogin"
    assert ("user", "svc_finance") in event.indicators
    assert ("ip", "198.51.100.77") in event.indicators


def test_parse_cloudtrail_malformed_line_returns_none():
    assert parse_cloudtrail(_lines("cloudtrail_sample.jsonl")[2]) is None


def test_parse_dns_valid_line():
    event = parse_dns(_lines("dns_sample.jsonl")[0])
    assert event.host == "10.0.1.11"
    assert event.event_type == "dns_query"
    assert ("domain", "file-share-quick.net") in event.indicators
    assert ("ip", "198.51.100.77") in event.indicators


def test_parse_dns_malformed_line_returns_none():
    assert parse_dns(_lines("dns_sample.jsonl")[2]) is None
