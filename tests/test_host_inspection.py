from unittest.mock import patch

from hexshield.tools.host_inspection import ExposureCheckTool, PersistenceCheckTool


def test_exposure_check_flags_broad_smb_listener() -> None:
    tool = ExposureCheckTool()
    listeners = [{"proto": "TCP", "bind": "0.0.0.0", "port": 445, "process": "System"}]
    with patch.object(tool, "_get_listeners", return_value=listeners), patch(
        "hexshield.tools.host_inspection.platform.system", return_value="Windows"
    ):
        result = tool.run(".")

    assert result.status == "warning"
    assert any(finding["type"] == "open_service" for finding in result.findings)
    assert result.severity == "critical"


def test_persistence_check_flags_temp_execution() -> None:
    tool = PersistenceCheckTool()
    entries = [
        {
            "kind": "scheduled_task",
            "location": "\\SuspiciousTask",
            "detail": r"C:\Users\analyst\AppData\Local\Temp\payload.exe",
        }
    ]
    with patch.object(tool, "_collect_entries", return_value=entries), patch(
        "hexshield.tools.host_inspection.platform.system", return_value="Windows"
    ):
        result = tool.run(".")

    assert result.status == "warning"
    assert any(finding["type"] == "suspicious_persistence" for finding in result.findings)


def test_listener_parser_handles_ipv4_and_ipv6() -> None:
    assert ExposureCheckTool._split_host_port("0.0.0.0:3389") == ("0.0.0.0", 3389)
    assert ExposureCheckTool._split_host_port("[::]:443") == ("::", 443)
