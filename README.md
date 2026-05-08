# redakt

`redakt` is a Python module for detecting and redacting personally identifiable information from text.

It ships with default regex rules for common global and Indian PII, and supports JSON-backed rule management for custom regex rules.

## Install

```bash
pip install redakt
```

Install optional dashboard support:

```bash
pip install "redakt[dashboard]"
```

Install optional NER support:

```bash
pip install "redakt[ner]"
```

For local development:

```bash
uv sync --all-extras --dev
```

## Basic Usage

```python
from redakt import Redactor

redactor = Redactor()
result = redactor.redact("Email test@example.com and PAN ABCDE1234F")

print(result.redacted_text)
print(result.matches)
print(result.token_map)
print(result.restore())
```

Example output:

```text
Email [PII_EMAIL_1] and PAN [PII_PAN_1]
```

Change the redaction mode when you need different output:

```python
from redakt import Redactor

print(Redactor(mode="replace").redact("Email test@example.com").redacted_text)
print(Redactor(mode="mask").redact("Email test@example.com").redacted_text)
print(Redactor(mode="remove").redact("Email test@example.com").redacted_text)
print(Redactor(mode="hash", hash_salt="secret").redact("Email test@example.com").redacted_text)
```

Modes:

- `replace`: token output like `[PII_EMAIL_1]`
- `mask`: keeps some shape, for example `t***@example.com`
- `remove`: removes the matched text entirely
- `hash`: deterministic `sha256:...` replacement, optionally salted

`restore()` is available only in `replace` mode.

## Default Rules

`Redactor()` loads the default rules automatically.

Default rules include:

- Email addresses
- Phone numbers
- IPv4 addresses
- Credit card numbers
- US SSNs
- Date-like values
- Aadhaar numbers
- PAN numbers
- Indian mobile numbers

You can also pass a custom rule list:

```python
from redakt import Redactor, Rule

rules = [Rule(label="EMPLOYEE_ID", pattern=r"EMP-\d{5}")]
redactor = Redactor(rules=rules)
```

## JSON Rule Management

Use `RuleStore` when you want a simple `rules.json` file for toggling and custom regex rules.

```python
from redakt import Redactor
from redakt.management import RuleStore

store = RuleStore("rules.json")
rules = store.load_or_create_defaults()

store.disable("AADHAAR")
store.add_regex_rule(
    label="EMPLOYEE_ID",
    pattern=r"EMP-\d{5}",
    description="Employee IDs",
)

redactor = Redactor(rules=store.get_rules())
result = redactor.redact("Employee EMP-12345")
```

Supported rule-store operations:

- `load()`
- `save()`
- `load_or_create_defaults()`
- `reset_to_defaults()`
- `add_regex_rule()`
- `enable(label)`
- `disable(label)`
- `remove(label)`

`rules.json` currently supports regex rules only. Python callback detectors and NER rules are kept in code for now.

## Dashboard

Install with the dashboard extra, then run the local dashboard:

```bash
redakt dashboard
```

Then open:

```text
http://127.0.0.1:8765
```

Open the browser automatically:

```bash
redakt dashboard --open
```

By default, the dashboard stores rules in `rules.json` in the current working directory. To use a different path:

```bash
redakt dashboard --rules ./config/rules.json
```

Use a custom host or port:

```bash
redakt dashboard --host 0.0.0.0 --port 9000
```

Dashboard API endpoints:

- `GET /api/rules`
- `POST /api/rules`
- `PATCH /api/rules/{label}`
- `POST /api/rules/{label}/enable`
- `POST /api/rules/{label}/disable`
- `DELETE /api/rules/{label}`
- `POST /api/rules/reset`
- `POST /api/redact`

## CLI

Redact text from the terminal:

```bash
redakt redact "Email test@example.com"
```

Choose a mode:

```bash
redakt redact "Email test@example.com" --mode mask
redakt redact "Email test@example.com" --mode remove
redakt redact "Email test@example.com" --mode hash --hash-salt my-secret
```

Use a rules file:

```bash
redakt redact "Email test@example.com" --rules ./rules.json
```

Print the full JSON result:

```bash
redakt redact "Email test@example.com" --json
```

Manage a `rules.json` file from the terminal:

```bash
redakt rules init
redakt rules list
redakt rules add EMPLOYEE_ID 'EMP-\d{5}' --description "Employee IDs" --priority 5
redakt rules disable AADHAAR
redakt rules enable AADHAAR
redakt rules remove EMPLOYEE_ID
redakt rules reset
```

Use a custom rules file path:

```bash
redakt rules --rules ./config/rules.json init
redakt rules --rules ./config/rules.json add EMPLOYEE_ID 'EMP-\d{5}'
redakt redact "Employee EMP-12345" --rules ./config/rules.json
```

Rule command notes:

- `rules init` creates defaults and refuses to overwrite unless `--force` is used.
- `rules list --json` prints machine-readable rule data.
- `rules add --replace` updates an existing rule with the same label.
- Higher `priority` wins when two rules match overlapping text.

## Run Tests

```bash
uv run pytest
```

## Releases

Release automation is documented in [`RELEASE.md`](RELEASE.md). GitHub tags are used to publish matching package versions to TestPyPI and PyPI.
