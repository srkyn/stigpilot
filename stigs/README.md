# Local STIG Input Workspace

Use this folder for official STIG ZIPs and extracted XCCDF XML files that you download locally.

Recommended layout:

```text
stigs/
  chrome-windows/
    v2r10/
      U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml
    v2r11/
      U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml
```

Then run:

```bash
stigpilot packet \
  stigs/chrome-windows/v2r10/U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml \
  stigs/chrome-windows/v2r11/U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml \
  --out output/chrome-windows-v2r10-to-v2r11
```

PowerShell Government Mode:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old stigs\chrome-windows\v2r10\U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml `
  -New stigs\chrome-windows\v2r11\U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml `
  -OutDir output\chrome-windows-v2r10-to-v2r11
```

Notes:

- STIGPilot does not download official STIG content.
- Download official public STIG ZIPs from DoD Cyber Exchange or your approved internal source.
- Extract the file ending in `_Manual-xccdf.xml`.
- Use the older release as `old` and the newer release as `new`.
- Official downloaded XMLs and ZIPs under this folder are ignored by git by default.
