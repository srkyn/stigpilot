# Official Chrome STIG Input Directory

Place official Google Chrome Current Windows STIG XCCDF files here if you want `stigpilot chrome-demo` to run against official DoD Cyber Exchange content.

Expected filenames:

- `old.xml` for Google Chrome Current Windows STIG V2R10
- `new.xml` for Google Chrome Current Windows STIG V2R11

Source ZIPs:

- `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R10_STIG.zip`
- `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip`

The official XML files are not vendored in this repository. If these files are missing, `stigpilot chrome-demo` uses the bundled sanitized Chrome sample under `examples/chrome_windows_sample/`.
