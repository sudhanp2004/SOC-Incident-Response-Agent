from data_pipeline.parsers import RawEvent
from data_pipeline.mapper import load_ioc_table
from data_pipeline.assembler import assemble_episodes

IOC_PATH = "data_pipeline/known_iocs.json"


def _events():
    return [
        RawEvent("2024-03-15T08:00:00Z", "10.0.2.10", None, "ET SCAN Potential SSH Scan", [("ip", "203.0.113.42")], "raw1"),
        RawEvent("2024-03-15T08:05:00Z", "10.0.1.5", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw2"),
        RawEvent("2024-03-15T08:10:00Z", "10.0.3.20", None, "ConsoleLogin", [("user", "svc_finance")], "raw3"),
        # far outside the first window -> separate episode
        RawEvent("2024-03-15T11:00:00Z", "10.0.4.1", None, "ET SCAN Potential SSH Scan", [("ip", "198.51.100.77")], "raw4"),
        RawEvent("2024-03-15T11:02:00Z", "10.0.4.2", None, "DNS Query Observed", [("ip", "1.1.1.1")], "raw5"),
    ]


def test_assemble_episodes_groups_by_window():
    table = load_ioc_table(IOC_PATH)
    episodes = assemble_episodes(_events(), table, window_minutes=45)
    assert len(episodes) == 2


def test_episode_has_alerts_hosts_and_attack_chain():
    table = load_ioc_table(IOC_PATH)
    episodes = assemble_episodes(_events(), table, window_minutes=45)
    ep = episodes[0]
    assert len(ep["alerts"]) == 3
    assert len(ep["hosts"]) == 3
    assert ep["attack_chain"]["patient_zero_host"] == "HOST-10-0-2-10"
    assert "HOST-10-0-3-20" in ep["attack_chain"]["lateral_movement_targets"]


def test_episode_dropped_if_all_malicious_or_all_benign():
    table = load_ioc_table(IOC_PATH)
    all_benign = [
        RawEvent("2024-03-15T08:00:00Z", "10.0.1.1", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw1"),
        RawEvent("2024-03-15T08:01:00Z", "10.0.1.2", None, "DNS Query Observed", [("ip", "1.1.1.1")], "raw2"),
    ]
    episodes = assemble_episodes(all_benign, table, window_minutes=45)
    assert episodes == []


def test_assemble_episodes_empty_input_returns_empty_list():
    table = load_ioc_table(IOC_PATH)
    assert assemble_episodes([], table) == []
