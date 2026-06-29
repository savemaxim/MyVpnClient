# GitHub Publish Checklist

- Keep source in git; attach ZIP/MSI builds only to GitHub Releases.
- Do not commit `artifacts/`, `state/`, `.tools/`, `.wix/`, `bin/`, `obj/`, or `__pycache__/`.
- Do not commit `config.json`, `profiles.json`, `*.dpapi`, logs, traces, diagnostics, or real VPN host/user data.
- Run a secret scan before the first public push.
- Include `LICENSE` and `THIRD_PARTY_NOTICES.md` in releases.
- If bundling `wintun.dll` in a release, include the exact upstream license files and notices.
- Use neutral wording: MyVpnClient is compatible with some Fortinet/OpenConnect workflows; it is not affiliated with or endorsed by Fortinet, Cisco, WireGuard, OpenConnect, or WiX.
