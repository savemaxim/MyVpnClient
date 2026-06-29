using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MyVpnClient;

internal sealed class VpnController(string installDirectory, string appDirectory)
{
    private readonly string _pythonScript = Path.Combine(installDirectory, "myvpnclient_bridge.py");
    private readonly string _installTasksScript = Path.Combine(installDirectory, "install-helper-tasks-admin.ps1");
    private readonly string _uninstallTasksScript = Path.Combine(installDirectory, "uninstall-helper-tasks-admin.ps1");
    private readonly string _configPath = Path.Combine(appDirectory, "config.json");
    private readonly string _logPath = Path.Combine(appDirectory, "state", "myvpn.log");
    private readonly string _legacyLogPath = Path.Combine(appDirectory, "state", "openconnect.log");
    private readonly string _tracePath = Path.Combine(appDirectory, "state", "myvpn_tunnel-current-trace.jsonl");
    private readonly string _routesPath = Path.Combine(appDirectory, "state", "myvpn_tunnel-routes.json");
    private readonly string _ownerPidPath = Path.Combine(appDirectory, "state", "myvpnclient-owner.pid");
    private readonly TimeSpan _healthCacheTtl = TimeSpan.FromSeconds(5);
    private DateTime _healthCacheTime = DateTime.MinValue;
    private string _healthCacheText = "";

    public string LogPath => ActiveLogPath();

    public void WriteOwnerPid()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_ownerPidPath)!);
        File.WriteAllText(_ownerPidPath, Environment.ProcessId.ToString());
    }

    public void ConnectElevated()
    {
        RunPythonDetached("connect-watch");
    }

    public void FullDiagnosticElevated()
    {
        RunPythonDetached("full-diagnostic");
    }

    public async Task<CommandResult> DisconnectAsync()
    {
        TryDeleteOwnerPid();
        var disconnect = await RunPythonAsync("disconnect");
        var cleanup = await CleanupBundledOpenConnectAsync();
        return MergeResults(disconnect, cleanup);
    }

    public async Task<CommandResult> CleanupBundledOpenConnectAsync()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return new CommandResult(0, "", "");
            }

            var installRoot = Path.GetFullPath(installDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var openConnectRoot = Path.Combine(installRoot, "OpenConnect");
            var output = await RunPowerShellTextAsync($@"
$ErrorActionPreference = 'Continue'
$openConnectRoot = '{PowerShellSingleQuoted(openConnectRoot)}'
$installRoot = '{PowerShellSingleQuoted(installRoot)}'
$matches = @(Get-CimInstance Win32_Process -Filter ""Name = 'openconnect.exe'"" -ErrorAction SilentlyContinue | Where-Object {{
    $path = [string]$_.ExecutablePath
    $commandLine = [string]$_.CommandLine
    ($path -and $path.StartsWith($openConnectRoot, [StringComparison]::OrdinalIgnoreCase)) -or
    ($commandLine -and $commandLine.IndexOf($openConnectRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
    ($commandLine -and $commandLine.IndexOf($installRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf('OpenConnect', [StringComparison]::OrdinalIgnoreCase) -ge 0)
}})
foreach ($process in $matches) {{
    try {{
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        Write-Output ""Stopped stale MyVpnClient OpenConnect PID $($process.ProcessId): $($process.ExecutablePath)""
    }} catch {{
        Write-Output ""Failed to stop stale MyVpnClient OpenConnect PID $($process.ProcessId): $($_.Exception.Message)""
    }}
}}
", timeoutSeconds: 12);
            return new CommandResult(0, output, "");
        }
        catch (Exception ex)
        {
            return new CommandResult(0, "", "OpenConnect cleanup skipped: " + ex.Message);
        }
    }
    private static CommandResult MergeResults(CommandResult first, CommandResult second)
    {
        var output = string.Join(Environment.NewLine, new[] { first.Output, second.Output }.Where(value => !string.IsNullOrWhiteSpace(value)));
        var error = string.Join(Environment.NewLine, new[] { first.Error, second.Error }.Where(value => !string.IsNullOrWhiteSpace(value)));
        var exitCode = first.ExitCode != 0 ? first.ExitCode : second.ExitCode;
        return new CommandResult(exitCode, output, error);
    }

    private void TryDeleteOwnerPid()
    {
        try
        {
            File.Delete(_ownerPidPath);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    public async Task<CommandResult> StatusAsync()
    {
        return await RunPythonAsync("status");
    }

    private async Task<CommandResult> StatusJsonAsync()
    {
        return await RunPythonAsync("status-json");
    }

    public async Task<VpnStatusSnapshot> GetStatusSnapshotAsync()
    {
        var status = await StatusJsonAsync();
        var statusSnapshot = TryStatusFromJson(status.CombinedOutput);
        if (statusSnapshot is not null)
        {
            return statusSnapshot;
        }

        return Snapshot(
            VpnConnectionState.Disconnected,
            status.CombinedOutput.Trim(),
            "Idle",
            "VPN is disconnected.",
            "Connect when ready.",
            retryable: true);
    }

    private static async Task<string> GetTapIpv4Async(string tapAlias)
    {
        return await RunPowerShellTextAsync(
            $"Get-NetIPAddress -InterfaceAlias '{PowerShellSingleQuoted(tapAlias)}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.IPAddress -notlike '169.254.*' } | " +
            "Select-Object -First 1 -ExpandProperty IPAddress",
            timeoutSeconds: 8);
    }

    private static VpnStatusSnapshot? TryStatusFromJson(string text)
    {
        var start = text.IndexOf('{');
        if (start < 0)
        {
            return null;
        }

        try
        {
            var jsonText = ExtractFirstJsonObject(text[start..]);
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okElement) && okElement.GetBoolean();
            var detail = root.TryGetProperty("detail", out var detailElement) ? detailElement.GetString() ?? "" : "";
            var tapIp = root.TryGetProperty("tapIp", out var tapIpElement) ? tapIpElement.GetString() ?? "" : "";
            var status = root.TryGetProperty("status", out var statusElement) && statusElement.ValueKind == JsonValueKind.Object
                ? statusElement
                : root;
            var state = status.TryGetProperty("state", out var stateElement) ? stateElement.GetString() ?? "" : "";
            var pidRunning = status.TryGetProperty("pidRunning", out var pidElement) && pidElement.GetBoolean();
            var note = status.TryGetProperty("detail", out var noteElement) ? noteElement.GetString() ?? "" : "";
            var phase = status.TryGetProperty("phase", out var phaseElement) ? phaseElement.GetString() ?? "" : "";
            var userMessage = status.TryGetProperty("userMessage", out var messageElement) ? messageElement.GetString() ?? "" : "";
            var suggestedAction = status.TryGetProperty("suggestedAction", out var actionElement) ? actionElement.GetString() ?? "" : "";
            var networkCheck = status.TryGetProperty("networkCheck", out var networkCheckElement) ? networkCheckElement.GetString() ?? "" : "";
            var mfaStatus = status.TryGetProperty("mfaStatus", out var mfaStatusElement) ? mfaStatusElement.GetString() ?? "" : "";
            var retryable = !status.TryGetProperty("retryable", out var retryableElement) || retryableElement.GetBoolean();
            var connectedAt = status.TryGetProperty("connectedAt", out var connectedAtElement)
                ? ParseStateTimestamp(connectedAtElement.GetString() ?? "")
                : null;
            if (string.IsNullOrWhiteSpace(detail))
            {
                detail = note;
            }

            if (state is "network-ready" && networkCheck.Equals("running", StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot(
                    VpnConnectionState.Connecting,
                    detail,
                    "NetworkCheck",
                    "VPN tunnel is up; waiting for optional network check.",
                    "This is only used by explicit diagnostic flows.",
                    retryable: false,
                    mfaStatus: mfaStatus,
                    connectedAt: connectedAt);
            }

            if (ok || state is "network-ready")
            {
                return Snapshot(
                    VpnConnectionState.Connected,
                    string.IsNullOrWhiteSpace(tapIp) ? detail : $"myvpn_tunnel connected: {tapIp}",
                    phase,
                    userMessage,
                    suggestedAction,
                    retryable,
                    mfaStatus,
                    connectedAt);
            }

            if (state is "auth-failed" or "auth-timeout" or "tunnel-open-failed" or "tunnel-lost" or "negotiation-timeout" or "network-check-failed" or "tunnel-stalled")
            {
                return Snapshot(VpnConnectionState.Disconnected, note, phase, userMessage, suggestedAction, retryable, mfaStatus);
            }

            if (pidRunning || state.StartsWith("ppp-", StringComparison.OrdinalIgnoreCase) || state is "authenticating" or "authenticated" or "tls-tunnel-running" or "dtls-tunnel-running" or "reconnect-wait")
            {
                var shownDetail = !string.IsNullOrWhiteSpace(detail) && detail != note ? detail : note;
                return Snapshot(VpnConnectionState.Connecting, shownDetail, phase, userMessage, suggestedAction, retryable, mfaStatus);
            }

            return Snapshot(VpnConnectionState.Disconnected, note, phase, userMessage, suggestedAction, retryable, mfaStatus);
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? ParseStateTimestamp(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (DateTimeOffset.TryParseExact(
                text.Trim(),
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out var parsed))
        {
            return parsed;
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out parsed)
            ? parsed
            : null;
    }

    private static string ExtractFirstJsonObject(string text)
    {
        var depth = 0;
        var inString = false;
        var escaped = false;
        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (ch == '\\')
                {
                    escaped = true;
                }
                else if (ch == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == '"')
            {
                inString = true;
                continue;
            }
            if (ch == '{')
            {
                depth++;
            }
            else if (ch == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return text[..(i + 1)];
                }
            }
        }

        return text;
    }

    private static VpnStatusSnapshot Snapshot(
        VpnConnectionState state,
        string detail,
        string phase = "",
        string userMessage = "",
        string suggestedAction = "",
        bool retryable = true,
        string mfaStatus = "",
        DateTimeOffset? connectedAt = null)
    {
        var inferred = InferStatusMetadata(state, detail, phase, userMessage, suggestedAction, retryable);
        return new VpnStatusSnapshot(state, detail, inferred.Phase, inferred.UserMessage, inferred.SuggestedAction, inferred.Retryable, mfaStatus, connectedAt);
    }

    private static (string Phase, string UserMessage, string SuggestedAction, bool Retryable) InferStatusMetadata(
        VpnConnectionState state,
        string detail,
        string phase,
        string userMessage,
        string suggestedAction,
        bool retryable)
    {
        if (!string.IsNullOrWhiteSpace(phase) || !string.IsNullOrWhiteSpace(userMessage) || !string.IsNullOrWhiteSpace(suggestedAction))
        {
            return (
                string.IsNullOrWhiteSpace(phase) ? state.ToString() : phase,
                string.IsNullOrWhiteSpace(userMessage) ? state.ToString() : userMessage,
                string.IsNullOrWhiteSpace(suggestedAction) ? "Refresh status or run diagnostics." : suggestedAction,
                retryable);
        }

        if (state == VpnConnectionState.Disconnected && detail.Contains("auth", StringComparison.OrdinalIgnoreCase))
        {
            return ("AuthFailed", "MFA approval was not accepted, expired, or did not produce a VPN cookie.", "Press Connect to try again.", true);
        }

        return state switch
        {
            VpnConnectionState.Connected => ("NetworkReady", "VPN network is ready.", "No action needed.", false),
            VpnConnectionState.Connecting => ("OpeningTunnel", "VPN connection is in progress.", "Wait for the next phase or disconnect.", false),
            _ => ("Idle", "VPN is disconnected.", "Connect when ready.", true)
        };
    }

    private async Task<RouteCheckResult> CheckConnectivityRoutesAsync(VpnProfile profile, string tapAlias)
    {
        var hosts = profile.ConnectivityCheckHosts
            .Where(host => !string.IsNullOrWhiteSpace(host))
            .Select(host => host.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (hosts.Count == 0)
        {
            return new RouteCheckResult(true, "");
        }

        foreach (var host in hosts)
        {
            var result = await RunPowerShellTextAsync($@"
$hostName = '{PowerShellSingleQuoted(host)}'
$tapAlias = '{PowerShellSingleQuoted(tapAlias)}'
$addresses = @(Resolve-DnsName $hostName -Type A -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress }} |
  Select-Object -ExpandProperty IPAddress)
if (-not $addresses -or $addresses.Count -eq 0) {{
  Write-Output ""unresolved|$hostName""
  exit
}}
foreach ($address in $addresses) {{
  $route = Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue |
    Sort-Object {{ $_.RouteMetric + $_.InterfaceMetric }} |
    Select-Object -First 1
  if ($route) {{
    $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object -First 1
    Write-Output ""$address|$($iface.InterfaceAlias)""
  }}
}}
",
                timeoutSeconds: 8);

            var routedThroughTap = result
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Any(line => line.EndsWith("|" + tapAlias, StringComparison.OrdinalIgnoreCase));
            if (!routedThroughTap)
            {
                var routeSummary = string.IsNullOrWhiteSpace(result) ? "no route" : result.Replace(Environment.NewLine, ", ");
                return new RouteCheckResult(false, $"VPN route check pending: {host} via {routeSummary}");
            }
        }

        return new RouteCheckResult(true, "");
    }

    private static string LatestConnectLogBlock(string logTail)
    {
        var openConnectIndex = logTail.LastIndexOf("--- connect ", StringComparison.OrdinalIgnoreCase);
        var myvpnIndex = logTail.LastIndexOf("--- myvpn connect ", StringComparison.OrdinalIgnoreCase);
        var markerIndex = Math.Max(openConnectIndex, myvpnIndex);
        return markerIndex >= 0 ? logTail[markerIndex..] : logTail;
    }

    private static bool IsWaitingForFortiTokenApproval(string latestConnectLog)
    {
        var tokenPromptIndex = latestConnectLog.LastIndexOf("Enter token code", StringComparison.OrdinalIgnoreCase);
        var loginCheckIndex = latestConnectLog.LastIndexOf("remote/logincheck", StringComparison.OrdinalIgnoreCase);
        var authPromptIndex = Math.Max(tokenPromptIndex, loginCheckIndex);
        if (authPromptIndex < 0)
        {
            return false;
        }

        var authFailedIndex = latestConnectLog.LastIndexOf("Failed to complete authentication", StringComparison.OrdinalIgnoreCase);
        if (authFailedIndex > authPromptIndex)
        {
            return false;
        }

        var authSuccessIndex = LastIndexOfAny(
            latestConnectLog,
            [
                "Session authentication will expire",
                "ESP session established",
                "DTLS handshake complete",
                "CSTP connected",
                "Connected as "
            ]);
        return authSuccessIndex < authPromptIndex;
    }

    private static int LastIndexOfAny(string text, IReadOnlyList<string> needles)
    {
        var index = -1;
        foreach (var needle in needles)
        {
            index = Math.Max(index, text.LastIndexOf(needle, StringComparison.OrdinalIgnoreCase));
        }

        return index;
    }

    private static string PowerShellSingleQuoted(string value)
    {
        return value.Replace("'", "''");
    }

    public void RepairNetworkElevated()
    {
        RunPythonDetached("fix-network");
    }

    public void InstallHelperTasksElevated()
    {
        RunPowerShellElevated(_installTasksScript, keepOpen: true);
    }

    public void UninstallHelperTasksElevated()
    {
        RunPowerShellElevated(_uninstallTasksScript, keepOpen: true);
    }

    public bool IsRunningAsAdministrator()
    {
        return IsProcessElevated();
    }

    public void RemoveLegacyHelperTasks()
    {
        foreach (var taskName in new[]
        {
            "MyVpnClient-Connect",
            "MyVpnClient-Disconnect",
            "MyVpnClient-RepairNetwork",
            "MyVpnClient-ResetNetwork",
            "MyVpnClient-FullDiagnostic",
            "MyVpnClient Connect",
            "MyVpnClient Disconnect",
            "MyVpnClient Repair Network",
            "MyVpnClient Reset Network",
            "MyVpnClient Full Diagnostic"
        })
        {
            DeleteScheduledTask(taskName);
        }
    }

    private static void RunPowerShellElevated(string scriptPath, bool keepOpen)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = true,
            Verb = "runas"
        };
        if (keepOpen)
        {
            startInfo.ArgumentList.Add("-NoExit");
        }
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);
        Process.Start(startInfo);
    }

    private static void DeleteScheduledTask(string taskName)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                ArgumentList = { "/Delete", "/TN", taskName, "/F" }
            });
            process?.WaitForExit(3000);
        }
        catch
        {
        }
    }

    private void RunPythonDetached(string command, params string[] arguments)
    {
        if (!File.Exists(_pythonScript))
        {
            throw new FileNotFoundException("MyVpnClient bridge script is missing. Reinstall MyVpnClient.", _pythonScript);
        }

        if (!IsProcessElevated())
        {
            throw new InvalidOperationException("MyVpnClient must run as Administrator to start or repair the VPN tunnel.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "py",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = installDirectory
        };
        startInfo.Environment["MYVPNCLIENT_DATA_DIR"] = appDirectory;
        startInfo.Environment["PYTHONWARNINGS"] = "ignore::SyntaxWarning";
        startInfo.ArgumentList.Add("-B");
        startInfo.ArgumentList.Add(_pythonScript);
        startInfo.ArgumentList.Add("--config");
        startInfo.ArgumentList.Add(_configPath);
        startInfo.ArgumentList.Add(command);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        Process.Start(startInfo);
    }

    private static bool IsProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public string ReadLogTail(int lineCount)
    {
        var path = ActiveLogPath();
        return ReadTextTail(path, lineCount, $"No log file yet: {path}");
    }

    public void ClearLog()
    {
        var path = ActiveLogPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var stream = new FileStream(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete);
        if (File.Exists(_legacyLogPath))
        {
            using var legacyStream = new FileStream(
                _legacyLogPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete);
        }
    }

    private string ActiveLogPath()
    {
        var configured = ConfiguredLogPath();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }
        if (File.Exists(_logPath) || !File.Exists(_legacyLogPath))
        {
            return _logPath;
        }
        return _legacyLogPath;
    }

    private string ConfiguredLogPath()
    {
        try
        {
            var profile = VpnProfile.Load(_configPath);
            var configured = profile.LogPath.Trim();
            if (string.IsNullOrWhiteSpace(configured))
            {
                return "";
            }
            var path = Environment.ExpandEnvironmentVariables(configured);
            if (!Path.IsPathRooted(path))
            {
                path = Path.Combine(appDirectory, path);
            }
            if (Directory.Exists(path) || string.IsNullOrWhiteSpace(Path.GetExtension(path)))
            {
                path = Path.Combine(path, "myvpn.log");
            }
            return path;
        }
        catch
        {
            return "";
        }
    }

    public void ClearSessionTrace()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_tracePath)!);
        using var stream = new FileStream(
            _tracePath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete);
    }

    public string ReadTraceTail(int lineCount)
    {
        return ReadTextTail(_tracePath, lineCount, $"No trace file yet: {_tracePath}");
    }

    public string ReadSessionTail(int lineCount)
    {
        var owner = ReadRouteOwnerSummary();
        var trace = ReadTraceTail(lineCount);
        return string.IsNullOrWhiteSpace(owner)
            ? trace
            : owner + Environment.NewLine + Environment.NewLine + trace;
    }

    private static string ReadTextTail(string path, int lineCount, string missingText)
    {
        if (!File.Exists(path))
        {
            return missingText;
        }

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var lines = new Queue<string>(lineCount);
            while (reader.ReadLine() is { } line)
            {
                if (lines.Count == lineCount)
                {
                    lines.Dequeue();
                }

                lines.Enqueue(line);
            }

            return string.Join(Environment.NewLine, lines);
        }
        catch (IOException ex)
        {
            return $"File is temporarily locked: {ex.Message}";
        }
    }

    public async Task<CommandResult> RunDiagnosticsAsync()
    {
        var builder = new StringBuilder();
        builder.AppendLine("== MyVpnClient diagnostics ==");
        builder.AppendLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        builder.AppendLine();

        var selfTest = await RunPythonAsync("self-test");
        builder.AppendLine("== Self-test ==");
        builder.AppendLine(selfTest.CombinedOutput.Trim());
        builder.AppendLine();

        var preflight = await RunPreflightAsync();
        builder.AppendLine("== Preflight ==");
        builder.AppendLine(preflight.CombinedOutput.Trim());
        builder.AppendLine();

        var sandbox = await RunSandboxCheckAsync();
        builder.AppendLine("== Offline sandbox ==");
        builder.AppendLine(sandbox.CombinedOutput.Trim());
        builder.AppendLine();

        var status = await StatusAsync();
        builder.AppendLine("== Status ==");
        builder.AppendLine(status.CombinedOutput.Trim());
        builder.AppendLine();

        var health = await RunPythonAsync("health");
        builder.AppendLine("== Health ==");
        builder.AppendLine(health.CombinedOutput.Trim());
        builder.AppendLine();

        builder.AppendLine("== TAP adapter ==");
        builder.AppendLine(await RunPowerShellTextAsync(
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.Name -match 'Local Area Connection|VPN' -or $_.InterfaceDescription -match 'TAP|Wintun|Fortinet' } | " +
            "Select-Object Name,Status,InterfaceDescription,ifIndex | Format-Table -AutoSize | Out-String"));

        builder.AppendLine("== VPN IP ==");
        builder.AppendLine(await RunPowerShellTextAsync(
            "Get-NetIPAddress -InterfaceAlias 'Local Area Connection' -ErrorAction SilentlyContinue | " +
            "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily | Format-Table -AutoSize | Out-String"));

        builder.AppendLine("== DNS sample ==");
        builder.AppendLine(await RunPowerShellTextAsync(
            "Resolve-DnsName intranet.example.com -ErrorAction SilentlyContinue | " +
            "Select-Object Name,Type,IPAddress,NameHost | Format-Table -AutoSize | Out-String"));

        builder.AppendLine("== VPN DNS/routes sample ==");
        builder.AppendLine(await RunPowerShellTextAsync(
            "Resolve-DnsName service.example.com -ErrorAction SilentlyContinue | " +
            "Select-Object Name,Type,IPAddress,NameHost | Format-Table -AutoSize | Out-String; " +
            "Get-DnsClientServerAddress -InterfaceAlias 'Local Area Connection' -AddressFamily IPv4 -ErrorAction SilentlyContinue | " +
            "Select-Object InterfaceAlias,ServerAddresses | Format-Table -AutoSize | Out-String; " +
            "Get-NetRoute -DestinationPrefix '10.0.0.0/8' -ErrorAction SilentlyContinue | " +
            "Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | Format-Table -AutoSize | Out-String"));

        builder.AppendLine("== Recent log ==");
        builder.AppendLine(ReadLogTail(80));

        var bundlePath = await SaveDiagnosticBundleAsync(selfTest, status, health, builder.ToString());
        builder.AppendLine();
        builder.AppendLine("== Diagnostic bundle ==");
        builder.AppendLine(bundlePath);

        return new CommandResult(0, builder.ToString(), "");
    }

    public async Task<CommandResult> RunLifecycleProofAsync(Action startConnect, Func<Task> disconnect)
    {
        var builder = new StringBuilder();
        builder.AppendLine("== MyVpnClient tunnel lifecycle proof ==");
        builder.AppendLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        builder.AppendLine();
        builder.AppendLine("Starting connect. Approve UAC/FortiToken if prompted.");
        startConnect();

        var connected = await WaitForStateAsync(VpnConnectionState.Connected, TimeSpan.FromMinutes(4), builder);
        if (!connected)
        {
            builder.AppendLine("Result: failed to reach Connected before timeout.");
            return new CommandResult(1, builder.ToString(), "");
        }

        builder.AppendLine("Connected proof:");
        builder.AppendLine(await HealthTextAsync());
        builder.AppendLine();
        builder.AppendLine("Disconnecting.");
        await disconnect();

        var disconnected = await WaitForStateAsync(VpnConnectionState.Disconnected, TimeSpan.FromSeconds(60), builder);
        builder.AppendLine("Post-disconnect proof:");
        builder.AppendLine(await HealthTextAsync());
        builder.AppendLine();
        builder.AppendLine(disconnected
            ? "Result: lifecycle proof passed; tunnel reached Connected and then Disconnected."
            : "Result: disconnect cleanup did not reach Disconnected before timeout.");
        return new CommandResult(disconnected ? 0 : 1, builder.ToString(), "");
    }

    private async Task<bool> WaitForStateAsync(VpnConnectionState target, TimeSpan timeout, StringBuilder builder)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var snapshot = await GetStatusSnapshotAsync();
            builder.AppendLine($"{DateTime.Now:HH:mm:ss} status={snapshot.State} detail={snapshot.Detail}");
            if (snapshot.State == target)
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromSeconds(5));
        }

        return false;
    }

    public async Task<string> HealthTextAsync()
    {
        if (!string.IsNullOrWhiteSpace(_healthCacheText) && DateTime.UtcNow - _healthCacheTime < _healthCacheTtl)
        {
            return _healthCacheText;
        }

        var text = (await RunPythonAsync("health-json")).CombinedOutput.Trim();
        _healthCacheText = text;
        _healthCacheTime = DateTime.UtcNow;
        return text;
    }

    public async Task<JsonNode> HealthJsonAsync()
    {
        return ParseJsonOrFallback(await HealthTextAsync(), "health");
    }

    public async Task<JsonNode> PreflightJsonAsync()
    {
        var result = await RunPythonAsync("preflight-json");
        return ParseJsonOrFallback(result.CombinedOutput.Trim(), "preflight");
    }

    public async Task<JsonNode> SandboxCheckJsonAsync()
    {
        var result = await RunPythonAsync("sandbox-check-json");
        return ParseJsonOrFallback(result.CombinedOutput.Trim(), "sandbox");
    }

    public async Task<CommandResult> RunPreflightAsync()
    {
        return await RunPythonAsync("preflight-json");
    }

    public async Task<CommandResult> RunSandboxCheckAsync()
    {
        return await RunPythonAsync("sandbox-check-json");
    }

    public async Task<CommandResult> WaitForFullDiagnosticReportAsync(DateTime startedAt, TimeSpan timeout, Action<string>? progress = null)
    {
        var diagnosticsDirs = FullDiagnosticDirectories();
        foreach (var diagnosticsDir in diagnosticsDirs)
        {
            Directory.CreateDirectory(diagnosticsDir);
        }

        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var report = diagnosticsDirs
                .SelectMany(dir => Directory.GetFiles(dir, "full-vpn-diagnostic-*.json"))
                .Select(path => new FileInfo(path))
                .Where(file => file.LastWriteTime >= startedAt.AddSeconds(-3))
                .Select(file => new { File = file, Started = ReadDiagnosticStartedAt(file.FullName) })
                .Where(item => item.Started is not null && item.Started.Value >= startedAt.AddSeconds(-5))
                .OrderByDescending(item => item.Started)
                .ThenByDescending(item => item.File.LastWriteTime)
                .Select(item => item.File)
                .FirstOrDefault();
            if (report is not null)
            {
                var text = await File.ReadAllTextAsync(report.FullName);
                return new CommandResult(0,
                    "== Full VPN diagnostic report ==" + Environment.NewLine
                    + report.FullName + Environment.NewLine + Environment.NewLine
                    + text,
                    "");
            }

            var progressText = FullDiagnosticProgressText(startedAt);
            if (progressText.Contains("Tunnel exited", StringComparison.OrdinalIgnoreCase)
                || progressText.Contains("persistent_connect_exit", StringComparison.OrdinalIgnoreCase)
                || progressText.Contains("network-check-failed", StringComparison.OrdinalIgnoreCase))
            {
                progressText += Environment.NewLine
                    + "Tunnel finished; collecting final diagnostic report..." + Environment.NewLine;
            }

            progress?.Invoke(progressText);
            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        return new CommandResult(1,
            "Full VPN diagnostic did not finish before timeout." + Environment.NewLine + Environment.NewLine
            + "Checked folders:" + Environment.NewLine
            + string.Join(Environment.NewLine, diagnosticsDirs) + Environment.NewLine + Environment.NewLine
            + "Recent session trace:" + Environment.NewLine
            + ReadSessionTail(120),
            "");
    }

    private static DateTime? ReadDiagnosticStartedAt(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (!document.RootElement.TryGetProperty("started", out var started))
            {
                return null;
            }

            return DateTime.TryParse(started.GetString(), out var value) ? value : null;
        }
        catch
        {
            return null;
        }
    }
    public string FullDiagnosticProgressText(DateTime startedAt)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Running full VPN test...");
        builder.AppendLine("Approve UAC and FortiToken/MFA when prompted.");
        builder.AppendLine();
        builder.AppendLine($"Started: {startedAt:yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"Elapsed: {DateTime.Now - startedAt:mm\\:ss}");
        builder.AppendLine();

        var traceLines = ReadRecentTraceEvents(startedAt, 18);
        builder.AppendLine("Live progress:");
        if (traceLines.Count > 0)
        {
            foreach (var line in traceLines)
            {
                builder.AppendLine(line);
            }
        }
        else
        {
            builder.AppendLine("- Waiting for elevated helper to start writing trace events...");
        }

        var status = TryReadMyVpnStatusLine();
        if (!string.IsNullOrWhiteSpace(status))
        {
            builder.AppendLine();
            builder.AppendLine("Current status:");
            builder.AppendLine(status);
        }

        builder.AppendLine();
        builder.AppendLine("Final report will appear here automatically when the test finishes.");
        return builder.ToString();
    }

    private List<string> ReadRecentTraceEvents(DateTime startedAt, int maxLines)
    {
        if (!File.Exists(_tracePath))
        {
            return [];
        }

        var result = new List<string>();
        foreach (var line in File.ReadLines(_tracePath).Reverse().Take(250).Reverse())
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var eventTime = TraceEventTime(root);
                if (eventTime is not null && eventTime.Value < startedAt.AddSeconds(-5))
                {
                    continue;
                }

                var formatted = FormatTraceEvent(root);
                if (!string.IsNullOrWhiteSpace(formatted))
                {
                    result.Add(formatted);
                }
            }
            catch (JsonException)
            {
            }
            catch (IOException)
            {
            }
        }

        return result.TakeLast(maxLines).ToList();
    }

    private static DateTime? TraceEventTime(JsonElement root)
    {
        if (!root.TryGetProperty("time", out var timeElement))
        {
            return null;
        }

        return DateTime.TryParse(timeElement.GetString(), out var time) ? time : null;
    }

    private static string FormatTraceEvent(JsonElement root)
    {
        var time = root.TryGetProperty("time", out var timeElement)
            ? ShortTime(timeElement.GetString())
            : DateTime.Now.ToString("HH:mm:ss");
        var name = root.TryGetProperty("event", out var eventElement) ? eventElement.GetString() ?? "event" : "event";

        return name switch
        {
            "connect_start" => $"- {time} Starting MyVpnClient {StringProp(root, "version")} ({StringProp(root, "backend")})",
            "login_start" => $"- {time} MFA push sent; approve FortiToken on your phone",
            "login_note" => FormatLoginNote(time, root),
            "login_result" => $"- {time} Auth result: {StringProp(root, "status")} cookies={StringProp(root, "cookies")}",
            "state" => $"- {time} {StringProp(root, "status")}: {StringProp(root, "note")}",
            "tls_tunnel_open_start" => $"- {time} Opening TLS tunnel stream",
            "tls_tunnel_opened" => $"- {time} TLS tunnel opened: {StringProp(root, "reason")}",
            "ppp_phase" => $"- {time} PPP {StringProp(root, "phase")}: {StringProp(root, "detail")}",
            "network_check_start" => $"- {time} Network check attempt {StringProp(root, "attempt")}/{StringProp(root, "attempts")}",
            "network_check_dns_probe_start" => $"- {time} DNS probe started: {StringProp(root, "host")} via {StringProp(root, "dns")} timeout={StringProp(root, "timeoutSeconds")}s",
            "network_check_dns_probe" => FormatDnsProbe(time, root),
            "network_check_retry" => $"- {time} Check retry: {StringProp(root, "error")}",
            "dns_packet" => FormatDnsPacket(time, root),
            "tunnel_exit" => $"- {time} Tunnel exited with code {StringProp(root, "exit_code")}",
            "persistent_connect_exit" => $"- {time} Helper finished with code {StringProp(root, "exit_code")}",
            _ => ""
        };
    }


    private static string FormatLoginNote(string time, JsonElement root)
    {
        var message = StringProp(root, "message");
        if (message.Contains("tokeninfo MFA challenge", StringComparison.OrdinalIgnoreCase))
        {
            return $"- {time} MFA push is waiting for approval";
        }

        if (message.Contains("MFA logincheck", StringComparison.OrdinalIgnoreCase))
        {
            return $"- {time} MFA logincheck in progress; waiting for mobile approval";
        }

        return $"- {time} Auth: {message}";
    }

    private static string FormatDnsProbe(string time, JsonElement root)
    {
        var error = StringProp(root, "error");
        if (!string.IsNullOrWhiteSpace(error))
        {
            return $"- {time} DNS probe {StringProp(root, "host")} via {StringProp(root, "dns")}: {error}";
        }

        return $"- {time} DNS probe {StringProp(root, "host")} via {StringProp(root, "dns")}: rcode={StringProp(root, "rcode")} answers={StringProp(root, "answers")} elapsed={StringProp(root, "elapsedSeconds")}s";
    }

    private static string FormatDnsPacket(string time, JsonElement root)
    {
        var qname = StringProp(root, "qname");
        if (string.IsNullOrWhiteSpace(qname))
        {
            return "";
        }

        var direction = StringProp(root, "direction");
        var answer = StringProp(root, "answerA");
        return string.IsNullOrWhiteSpace(answer)
            ? $"- {time} DNS packet {direction}: {qname}"
            : $"- {time} DNS packet {direction}: {qname} -> {answer}";
    }

    private static string ShortTime(string? value)
    {
        return DateTime.TryParse(value, out var time) ? time.ToString("HH:mm:ss") : DateTime.Now.ToString("HH:mm:ss");
    }

    private static string StringProp(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element))
        {
            return "";
        }

        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? "",
            JsonValueKind.Array => string.Join(",", element.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())),
            JsonValueKind.Null => "",
            JsonValueKind.Undefined => "",
            _ => element.ToString()
        };
    }

    private string TryReadMyVpnStatusLine()
    {
        var statePath = Path.Combine(appDirectory, "state", "myvpn_tunnel.json");
        if (!File.Exists(statePath))
        {
            return "";
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(statePath));
            var root = document.RootElement;
            var status = StringProp(root, "status");
            var detail = StringProp(root, "detail");
            var phase = StringProp(root, "phase");
            return string.Join(" | ", new[] { status, phase, detail }.Where(part => !string.IsNullOrWhiteSpace(part)));
        }
        catch
        {
            return "";
        }
    }
    private string[] FullDiagnosticDirectories()
    {
        var dirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MyVpnClient", "state", "diagnostics"),
            Path.Combine(appDirectory, "state", "diagnostics")
        };
        return dirs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public Task<JsonNode> TraceJsonAsync()
    {
        var array = new JsonArray();
        if (File.Exists(_tracePath))
        {
            foreach (var line in ReadTextTail(_tracePath, 200, "").Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    array.Add(JsonNode.Parse(line));
                }
                catch (JsonException)
                {
                    array.Add(new JsonObject { ["raw"] = line });
                }
            }
        }

        var payload = new JsonObject
        {
            ["tracePath"] = _tracePath,
            ["routeOwnerPath"] = _routesPath,
            ["routeOwner"] = ParseJsonFileOrNull(_routesPath),
            ["events"] = array
        };
        return Task.FromResult<JsonNode>(payload);
    }

    public async Task<CommandResult> ResetNetworkAsync()
    {
        return await RunPythonAsync("reset-network");
    }

    private async Task<string> SaveDiagnosticBundleAsync(
        CommandResult selfTest,
        CommandResult status,
        CommandResult health,
        string diagnosticsText)
    {
        var diagnosticsDir = Path.Combine(appDirectory, "state", "diagnostics");
        Directory.CreateDirectory(diagnosticsDir);
        var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var staging = Path.Combine(diagnosticsDir, "bundle-" + timestamp);
        var zipPath = Path.Combine(diagnosticsDir, $"MyVpnClient-diagnostics-{timestamp}.zip");
        Directory.CreateDirectory(staging);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(staging, "diagnostics.txt"), diagnosticsText);
            await File.WriteAllTextAsync(Path.Combine(staging, "self-test.txt"), selfTest.CombinedOutput);
            await File.WriteAllTextAsync(Path.Combine(staging, "status.txt"), status.CombinedOutput);
            await File.WriteAllTextAsync(Path.Combine(staging, "health.txt"), health.CombinedOutput);
            await File.WriteAllTextAsync(Path.Combine(staging, "config.redacted.json"), RedactJsonFile(_configPath));

            CopyIfExists(Path.Combine(appDirectory, "profiles.json"), Path.Combine(staging, "profiles.redacted.json"), redactJson: true);
            CopyIfExists(Path.Combine(appDirectory, "state", "myvpnclient.settings.json"), Path.Combine(staging, "myvpnclient.settings.json"), redactJson: false);
            CopyIfExists(ActiveLogPath(), Path.Combine(staging, "myvpn.log"), redactJson: false);
            CopyIfExists(_legacyLogPath, Path.Combine(staging, "openconnect-legacy.log"), redactJson: false);
            CopyIfExists(Path.Combine(appDirectory, "state", "myvpn_tunnel.json"), Path.Combine(staging, "myvpn_tunnel.json"), redactJson: false);
            CopyIfExists(Path.Combine(appDirectory, "state", "myvpn_tunnel-current-trace.jsonl"), Path.Combine(staging, "myvpn_tunnel-current-trace.jsonl"), redactJson: false);

            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }

            ZipFile.CreateFromDirectory(staging, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            return zipPath;
        }
        finally
        {
            try
            {
                Directory.Delete(staging, recursive: true);
            }
            catch
            {
            }
        }
    }

    private static void CopyIfExists(string source, string destination, bool redactJson)
    {
        if (!File.Exists(source))
        {
            return;
        }

        if (redactJson)
        {
            File.WriteAllText(destination, RedactJsonFile(source));
            return;
        }

        File.Copy(source, destination, overwrite: true);
    }

    private static string RedactJsonFile(string path)
    {
        if (!File.Exists(path))
        {
            return "{}";
        }

        try
        {
            var node = JsonNode.Parse(File.ReadAllText(path));
            RedactNode(node);
            return node?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "{}";
        }
        catch
        {
            return "{}";
        }
    }

    private static void RedactNode(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            foreach (var key in obj.Select(item => item.Key).ToList())
            {
                if (IsSecretKey(key))
                {
                    obj[key] = "(redacted)";
                }
                else
                {
                    RedactNode(obj[key]);
                }
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array)
            {
                RedactNode(child);
            }
        }
    }

    private static bool IsSecretKey(string key)
    {
        return key.Contains("pass", StringComparison.OrdinalIgnoreCase)
            || key.Contains("token", StringComparison.OrdinalIgnoreCase)
            || key.Contains("secret", StringComparison.OrdinalIgnoreCase)
            || key.Contains("credential", StringComparison.OrdinalIgnoreCase)
            || key.Contains("cookie", StringComparison.OrdinalIgnoreCase);
    }

    public void OpenDiagnosticsFolder()
    {
        var diagnosticsDir = Path.Combine(appDirectory, "state", "diagnostics");
        Directory.CreateDirectory(diagnosticsDir);
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            ArgumentList = { diagnosticsDir },
            UseShellExecute = true
        });
    }

    private string ReadRouteOwnerSummary()
    {
        var stats = ReadMyVpnStatsSummary();
        if (!File.Exists(_routesPath))
        {
            return stats;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(_routesPath));
            var root = doc.RootElement;
            var pid = root.TryGetProperty("pid", out var pidElement) ? pidElement.ToString() : "";
            var adapter = root.TryGetProperty("interfaceAlias", out var adapterElement) ? adapterElement.GetString() ?? "" : "";
            var count = root.TryGetProperty("routes", out var routesElement) && routesElement.ValueKind == JsonValueKind.Array
                ? routesElement.GetArrayLength()
                : 0;
            var owner = $"Route owner: pid={pid}, adapter={adapter}, trackedRoutes={count}";
            return string.IsNullOrWhiteSpace(stats) ? owner : owner + Environment.NewLine + stats;
        }
        catch (JsonException ex)
        {
            return $"Route owner file is unreadable: {ex.Message}";
        }
        catch (IOException ex)
        {
            return $"Route owner file is temporarily locked: {ex.Message}";
        }
    }

    private string ReadMyVpnStatsSummary()
    {
        var statePath = Path.Combine(appDirectory, "state", "myvpn_tunnel.json");
        if (!File.Exists(statePath))
        {
            return "";
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(statePath));
            if (!doc.RootElement.TryGetProperty("stats", out var stats) || stats.ValueKind != JsonValueKind.Object)
            {
                return "";
            }

            static bool ZeroOrBlank(string value) => string.IsNullOrWhiteSpace(value) || value == "0";

            var phase = stats.TryGetProperty("phase", out var phaseElement) ? phaseElement.GetString() ?? "" : "";
            var rx = stats.TryGetProperty("rxPackets", out var rxElement) ? rxElement.ToString() : "0";
            var tx = stats.TryGetProperty("txPackets", out var txElement) ? txElement.ToString() : "0";
            var lastRx = stats.TryGetProperty("lastRxSecondsAgo", out var lastRxElement) ? lastRxElement.ToString() : "";
            var lastTx = stats.TryGetProperty("lastTxSecondsAgo", out var lastTxElement) ? lastTxElement.ToString() : "";
            if (string.IsNullOrWhiteSpace(phase) && ZeroOrBlank(rx) && ZeroOrBlank(tx) && string.IsNullOrWhiteSpace(lastRx) && string.IsNullOrWhiteSpace(lastTx))
            {
                return "";
            }

            return $"PPP stats: phase={phase}, rx={rx}, tx={tx}, lastRx={lastRx}s, lastTx={lastTx}s";
        }
        catch
        {
            return "";
        }
    }

    private static JsonNode ParseJsonOrFallback(string text, string propertyName)
    {
        var start = text.IndexOf('{');
        if (start >= 0)
        {
            try
            {
                return JsonNode.Parse(text[start..]) ?? new JsonObject();
            }
            catch (JsonException)
            {
            }
        }

        return new JsonObject { [propertyName] = text };
    }

    private static JsonNode? ParseJsonFileOrNull(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(File.ReadAllText(path));
        }
        catch
        {
            return new JsonObject { ["error"] = "Unable to parse route owner file." };
        }
    }

    private async Task<CommandResult> RunPythonAsync(string command, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "py",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.Environment["MYVPNCLIENT_DATA_DIR"] = appDirectory;
        startInfo.Environment["PYTHONWARNINGS"] = "ignore::SyntaxWarning";
        startInfo.ArgumentList.Add("-B");
        startInfo.ArgumentList.Add(_pythonScript);
        startInfo.ArgumentList.Add("--config");
        startInfo.ArgumentList.Add(_configPath);
        startInfo.ArgumentList.Add(command);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start Python.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        var timeout = PythonCommandTimeout(command);
        var waitTask = process.WaitForExitAsync();
        if (await Task.WhenAny(waitTask, Task.Delay(timeout)) != waitTask)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            return new CommandResult(124, await outputTask, "Python command timed out after " + timeout.TotalSeconds + "s: " + command + Environment.NewLine + await errorTask);
        }

        return new CommandResult(process.ExitCode, await outputTask, await errorTask);
    }

    private static TimeSpan PythonCommandTimeout(string command)
    {
        return command switch
        {
            "status" or "status-json" or "health-json" => TimeSpan.FromSeconds(6),
            "preflight-json" or "sandbox-check-json" => TimeSpan.FromSeconds(20),
            "diagnostics-json" => TimeSpan.FromSeconds(90),
            _ => TimeSpan.FromMinutes(5),
        };
    }

    private static async Task<string> RunPowerShellTextAsync(string command, int timeoutSeconds = 30)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(command);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        var waitTask = process.WaitForExitAsync();
        var exited = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(timeoutSeconds)));
        if (exited != waitTask)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            return "PowerShell command timed out.";
        }

        return ((await outputTask) + (await errorTask)).Trim();
    }
}

internal sealed record RouteCheckResult(bool Ok, string Detail);

internal sealed record CommandResult(int ExitCode, string Output, string Error)
{
    public string CombinedOutput => string.IsNullOrWhiteSpace(Error)
        ? Output
        : Output + Environment.NewLine + Error;
}

internal enum VpnConnectionState
{
    Disconnected,
    Connecting,
    Connected
}

internal sealed record VpnStatusSnapshot(
    VpnConnectionState State,
    string Detail,
    string Phase = "",
    string UserMessage = "",
    string SuggestedAction = "",
    bool Retryable = true,
    string MfaStatus = "",
    DateTimeOffset? ConnectedAt = null);
