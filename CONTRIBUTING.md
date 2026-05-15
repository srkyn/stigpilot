# Contributing

STIGPilot is intentionally narrow. Contributions should improve STIG release change triage, remediation planning, evidence preparation, or ticket-ready exports.

Good contributions:

- Parser resilience for real XCCDF variants
- Clearer impact reasons
- Better local exports
- Stronger tests
- Documentation that helps analysts try the tool quickly

Avoid contributions that turn STIGPilot into a scanner, STIG Viewer clone, GRC platform, or auto-remediation engine.

Run before opening a pull request:

```bash
python -m pip install -e ".[dev]"
python -m pytest
stigpilot demo
```
