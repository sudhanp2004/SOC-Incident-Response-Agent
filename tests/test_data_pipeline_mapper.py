from data_pipeline.parsers import RawEvent
from data_pipeline.mapper import load_ioc_table, is_malicious, to_siem_alert, to_network_host
from soc_env.models import AlertSeverity, HostStatus, MITRETactic

IOC_PATH = "data_pipeline/known_iocs.json"


def test_load_ioc_table_returns_sets():
    table = load_ioc_table(IOC_PATH)
    assert "203.0.113.42" in table["ip"]
    assert "svc_finance" in table["user"]


def test_is_malicious_true_when_indicator_matches():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("t", "h", None, "et", [("ip", "203.0.113.42")], "raw")
    assert is_malicious(event, table) is True


def test_is_malicious_false_when_no_match():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("t", "h", None, "et", [("ip", "1.2.3.4")], "raw")
    assert is_malicious(event, table) is False


def test_to_siem_alert_malicious_event():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent(
        "2024-03-15T08:14:00Z", "10.0.2.10", None,
        "ET SCAN Potential SSH Scan", [("ip", "203.0.113.42")], "raw-line",
    )
    alert = to_siem_alert(event, 0, table)
    assert alert.alert_id == "ALT-RW-0000"
    assert alert.ground_truth is True
    assert alert.severity == AlertSeverity.HIGH
    assert alert.host_id == "HOST-10-0-2-10"
    assert alert.mitre_tactic == MITRETactic.DISCOVERY
    assert alert.raw_log == "raw-line"


def test_to_siem_alert_benign_event():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("2024-03-15T08:20:00Z", "10.0.1.5", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw")
    alert = to_siem_alert(event, 1, table)
    assert alert.ground_truth is False
    assert alert.severity == AlertSeverity.LOW
    assert alert.mitre_tactic is None


def test_to_network_host_compromised_is_suspicious():
    host = to_network_host("HOST-10-0-2-10", compromised=True)
    assert host.status == HostStatus.SUSPICIOUS
    assert host.host_id == "HOST-10-0-2-10"


def test_to_network_host_clean_by_default():
    host = to_network_host("HOST-10-0-1-5")
    assert host.status == HostStatus.CLEAN
