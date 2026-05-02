from fastapi.testclient import TestClient

from redakt.management.dashboard.server import create_app


def make_client(tmp_path) -> TestClient:
    return TestClient(create_app(tmp_path / "rules.json"))


def test_dashboard_serves_index(tmp_path) -> None:
    response = make_client(tmp_path).get("/")

    assert response.status_code == 200
    assert "redakt dashboard" in response.text


def test_list_rules_creates_defaults(tmp_path) -> None:
    response = make_client(tmp_path).get("/api/rules")

    assert response.status_code == 200
    assert any(rule["label"] == "EMAIL" for rule in response.json())


def test_add_custom_rule_and_redact(tmp_path) -> None:
    client = make_client(tmp_path)

    add_response = client.post(
        "/api/rules",
        json={"label": "EMPLOYEE_ID", "pattern": r"EMP-\d{5}", "description": "Employee IDs"},
    )
    redact_response = client.post("/api/redact", json={"text": "Owner EMP-12345"})

    assert add_response.status_code == 201
    assert redact_response.status_code == 200
    assert redact_response.json()["redacted_text"] == "Owner [PII_EMPLOYEE_ID_1]"


def test_disable_and_enable_rule(tmp_path) -> None:
    client = make_client(tmp_path)

    disabled = client.post("/api/rules/EMAIL/disable")
    redact_disabled = client.post("/api/redact", json={"text": "test@example.com"})
    enabled = client.post("/api/rules/EMAIL/enable")
    redact_enabled = client.post("/api/redact", json={"text": "test@example.com"})

    assert disabled.status_code == 200
    assert redact_disabled.json()["redacted_text"] == "test@example.com"
    assert enabled.status_code == 200
    assert redact_enabled.json()["redacted_text"] == "[PII_EMAIL_1]"


def test_update_rule(tmp_path) -> None:
    client = make_client(tmp_path)
    client.post("/api/rules", json={"label": "CODE", "pattern": r"OLD-\d+"})

    response = client.patch("/api/rules/CODE", json={"pattern": r"NEW-\d+", "priority": 3})
    redact_response = client.post("/api/redact", json={"text": "OLD-1 NEW-2"})

    assert response.status_code == 200
    assert response.json()["priority"] == 3
    assert redact_response.json()["redacted_text"] == "OLD-1 [PII_CODE_1]"


def test_delete_rule(tmp_path) -> None:
    client = make_client(tmp_path)
    client.post("/api/rules", json={"label": "CODE", "pattern": r"CODE-\d+"})

    response = client.delete("/api/rules/CODE")
    rules = client.get("/api/rules").json()

    assert response.status_code == 200
    assert all(rule["label"] != "CODE" for rule in rules)


def test_reset_rules_removes_custom_rules(tmp_path) -> None:
    client = make_client(tmp_path)
    client.post("/api/rules", json={"label": "CODE", "pattern": r"CODE-\d+"})

    response = client.post("/api/rules/reset")

    assert response.status_code == 200
    assert all(rule["label"] != "CODE" for rule in response.json())


def test_duplicate_rule_returns_400(tmp_path) -> None:
    client = make_client(tmp_path)

    response = client.post("/api/rules", json={"label": "EMAIL", "pattern": r"x"})

    assert response.status_code == 400
