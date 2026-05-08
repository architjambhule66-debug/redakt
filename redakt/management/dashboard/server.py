import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from redakt import DEFAULT_RULES, Redactor, Rule
from redakt.management import RuleStore


DEFAULT_RULES_PATH = Path(os.environ.get("REDAKT_RULES_PATH", "rules.json"))
STATIC_DIR = Path(__file__).parent / "static"


class RulePayload(BaseModel):
    label: str = Field(min_length=1)
    pattern: str = Field(min_length=1)
    description: str = ""
    enabled: bool = True
    priority: int = 0


class RuleUpdatePayload(BaseModel):
    pattern: str | None = None
    description: str | None = None
    enabled: bool | None = None
    priority: int | None = None


class RedactPayload(BaseModel):
    text: str = ""
    mode: str = "replace"
    hash_salt: str = ""


def create_app(rules_path: str | Path | None = None) -> FastAPI:
    store = RuleStore(rules_path or DEFAULT_RULES_PATH)
    app = FastAPI(title="redakt dashboard")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/rules")
    def list_rules() -> list[dict[str, Any]]:
        rules = store.load_or_create_defaults()
        return [_rule_to_dict(rule) for rule in rules]

    @app.post("/api/rules", status_code=201)
    def add_rule(payload: RulePayload) -> dict[str, Any]:
        store.load_or_create_defaults()
        try:
            rule = store.add_regex_rule(
                label=payload.label,
                pattern=payload.pattern,
                description=payload.description,
                enabled=payload.enabled,
                priority=payload.priority,
                replace=False,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _rule_to_dict(rule)

    @app.patch("/api/rules/{label}")
    def update_rule(label: str, payload: RuleUpdatePayload) -> dict[str, Any]:
        rules = store.load_or_create_defaults()
        existing = _find_rule(rules, label)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Rule '{label}' not found")

        try:
            rule = store.add_regex_rule(
                label=label,
                pattern=payload.pattern if payload.pattern is not None else existing.pattern or "",
                description=payload.description if payload.description is not None else existing.description,
                enabled=payload.enabled if payload.enabled is not None else existing.enabled,
                priority=payload.priority if payload.priority is not None else existing.priority,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _rule_to_dict(rule)

    @app.post("/api/rules/{label}/enable")
    def enable_rule(label: str) -> dict[str, Any]:
        store.load_or_create_defaults()
        try:
            store.enable(label)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"label": label, "enabled": True}

    @app.post("/api/rules/{label}/disable")
    def disable_rule(label: str) -> dict[str, Any]:
        store.load_or_create_defaults()
        try:
            store.disable(label)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"label": label, "enabled": False}

    @app.delete("/api/rules/{label}")
    def delete_rule(label: str) -> dict[str, Any]:
        store.load_or_create_defaults()
        if not store.remove(label):
            raise HTTPException(status_code=404, detail=f"Rule '{label}' not found")
        return {"label": label, "deleted": True}

    @app.post("/api/rules/reset")
    def reset_rules() -> list[dict[str, Any]]:
        return [_rule_to_dict(rule) for rule in store.reset_to_defaults()]

    @app.post("/api/redact")
    def redact(payload: RedactPayload) -> dict[str, Any]:
        rules = store.load_or_create_defaults()
        try:
            result = Redactor(rules=rules, mode=payload.mode, hash_salt=payload.hash_salt).redact(payload.text)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "redacted_text": result.redacted_text,
            "mode": result.mode,
            "pii_count": result.pii_count,
            "labels_found": result.labels_found,
            "matches": [match.__dict__ for match in result.matches],
            "token_map": result.token_map,
        }

    return app


def _find_rule(rules: list[Rule], label: str) -> Rule | None:
    for rule in rules:
        if rule.label == label:
            return rule
    return None


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "label": rule.label,
        "pattern": rule.pattern,
        "method": rule.method.value,
        "description": rule.description,
        "enabled": rule.enabled,
        "priority": rule.priority,
        "builtin": any(default.label == rule.label for default in DEFAULT_RULES),
    }


app = create_app()
