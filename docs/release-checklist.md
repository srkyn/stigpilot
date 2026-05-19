# Release Checklist

Run this before tagging a STIGPilot release:

- [ ] `python -m pip install -e ".[dev]"`
- [ ] `python -m pytest`
- [ ] `stigpilot doctor`
- [ ] `stigpilot demo`
- [ ] `stigpilot chrome-demo`
- [ ] `.\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir examples\government_mode_output`
- [ ] Regenerate `examples/sample_output/`
- [ ] Regenerate `examples/chrome_windows_output/`
- [ ] Regenerate `examples/government_mode_output/`
- [ ] Verify README commands are accurate
- [ ] Verify no personal local paths are present
- [ ] Verify no sensitive files are committed
- [ ] Verify official-tool and compliance language does not imply endorsement or validation
- [ ] Review generated Markdown in raw and rendered form
