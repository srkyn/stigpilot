# Release Checklist

Run this before tagging a STIGPilot release:

- [ ] `python -m pip install -e ".[dev]"`
- [ ] `python -m pytest`
- [ ] `python -m pytest tests/test_output_quality.py`
- [ ] `stigpilot doctor`
- [ ] `stigpilot demo`
- [ ] `stigpilot chrome-demo`
- [ ] `.\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir examples\government_mode_output`
- [ ] Regenerate `examples/sample_output/`
- [ ] Regenerate `examples/chrome_windows_output/`
- [ ] Regenerate `examples/government_mode_output/`
- [ ] Verify README commands are accurate
- [ ] Verify no personal local paths are present
- [ ] Verify committed sample outputs avoid local paths, emoji severity markers, em dashes, and remote HTML assets
- [ ] Verify no sensitive files are committed
- [ ] Verify official-tool and compliance language does not imply endorsement or validation
- [ ] Confirm generated artifacts stop at review/planning and do not apply system changes
- [ ] Review generated Markdown in raw and rendered form
