# Third-Party Notices

MyVpnClient is not affiliated with, endorsed by, or supported by Fortinet,
Cisco, WireGuard, the OpenConnect project, the WiX Toolset project, or their
respective owners. Product and protocol names are used only to describe
interoperability and compatibility context.

## OpenConnect

MyVpnClient bundles OpenConnect for Windows and uses `OpenConnect\openconnect.exe` as the default Fortinet tunnel transport. MyVpnClient performs the Fortinet login/MFA flow, receives the VPN cookie, and passes that cookie to OpenConnect.

The MSI redistributes the OpenConnect for Windows runtime under `OpenConnect\`. MyVpnClient prefers the bundled `OpenConnect\openconnect.exe`, then falls back to a system OpenConnect installation or `openconnect` on PATH.

OpenConnect is released under the GNU Lesser General Public License, version 2.1. The license text is included as `OPENCONNECT-LGPL-2.1.txt`. The bundled Windows runtime also includes OpenConnect runtime dependencies; their upstream license terms remain with those projects.

Project: https://www.infradead.org/openconnect/

Source repository: https://gitlab.com/openconnect/openconnect
## Wintun

The experimental native `myvpn_tunnel` backend can dynamically load `wintun.dll`
when present on the user's system. Wintun is a WireGuard project.

Project: https://www.wintun.net/

Source repository: https://git.zx2c4.com/wintun/

MyVpnClient does not vendor `wintun.dll` in this source repository. If you
redistribute Wintun binaries with a release package, include the license terms
from the Wintun binary distribution you use.

## WiX Toolset

MyVpnClient uses WiX Toolset during local MSI builds. WiX Toolset is licensed
under the Microsoft Reciprocal License.

Project: https://wixtoolset.org/

MyVpnClient does not require WiX at runtime.


