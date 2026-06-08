# Where To Put STIG Files

STIGPilot works best when your inputs and outputs have a predictable shape.

## Recommended Local Layout

Keep official STIG downloads under `stigs/` and generated reports under `output/`:

```text
stigs/
  product-or-platform/
    old-release/
      *_Manual-xccdf.xml
    new-release/
      *_Manual-xccdf.xml

output/
  product-or-platform-old-to-new/
    START_HERE.md
    change-brief.md
    manager-summary.md
    remediation-backlog.csv
    evidence-checklist.md
```

Example:

```text
stigs/
  chrome-windows/
    v2r10/
      U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml
    v2r11/
      U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml

output/
  chrome-windows-v2r10-to-v2r11/
```

## What File To Use

After extracting a STIG ZIP, look for the XCCDF XML file. It usually ends with:

```text
_Manual-xccdf.xml
```

That is the file STIGPilot compares. Do not point STIGPilot at the original ZIP file, a checklist file, or a PDF.

## Python CLI

```bash
stigpilot packet \
  stigs/chrome-windows/v2r10/U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml \
  stigs/chrome-windows/v2r11/U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml \
  --out output/chrome-windows-v2r10-to-v2r11
```

Then open:

```text
output/chrome-windows-v2r10-to-v2r11/START_HERE.md
```

## Government Mode

```powershell
.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old stigs\chrome-windows\v2r10\U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml `
  -New stigs\chrome-windows\v2r11\U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml `
  -OutDir output\chrome-windows-v2r10-to-v2r11
```

Then run:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command inspect -OutDir output\chrome-windows-v2r10-to-v2r11
.\tools\STIGPilot-Gov.ps1 -Command archive -OutDir output\chrome-windows-v2r10-to-v2r11 -Zip output\chrome-windows-v2r10-to-v2r11.zip
```

## Git Safety

The repository ignores downloaded STIG ZIPs, extracted XMLs, checklists, and generated outputs by default. Keep sanitized examples under `examples/`; keep official working files under `stigs/`.
