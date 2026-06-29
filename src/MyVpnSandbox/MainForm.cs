using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace MyVpnSandbox;

public sealed class MainForm : Form
{
    private readonly ComboBox backendBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
    private readonly ComboBox commandBox = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox prerequisitesBox = new() { ReadOnly = true, BackColor = SystemColors.Control, BorderStyle = BorderStyle.FixedSingle };
    private readonly ToolTip tips = new() { AutoPopDelay = 20000, InitialDelay = 350, ReshowDelay = 100, ShowAlways = true };
    private readonly TextBox configBox = new() { Text = @"C:\ProgramData\MyVpnClient\config.json" };
    private readonly NumericUpDown durationBox = new() { Minimum = 5, Maximum = 3600, Value = 140 };
    private readonly TextBox myVpnSourceBox = new() { Text = AppContext.BaseDirectory };
    private readonly TextBox openConnectSourceBox = new() { Text = "" };
    private readonly TextBox openFortiVpnSourceBox = new() { Text = "" };
    private readonly TextBox openConnectExeBox = new() { Text = "openconnect" };
    private readonly TextBox openFortiVpnExeBox = new() { Text = "openfortivpn" };
    private readonly TextBox extraArgsBox = new();
    private readonly TextBox logBox = new()
    {
        Multiline = true,
        ScrollBars = ScrollBars.Vertical,
        WordWrap = true,
        ReadOnly = true,
        Dock = DockStyle.Fill,
        Font = new Font("Consolas", 9F),
        BackColor = Color.White
    };
    private readonly TabControl logTabs = new() { Dock = DockStyle.Fill };
    private readonly TextBox myVpnLogBox = CreateLogTextBox();
    private readonly TextBox openConnectLogBox = CreateLogTextBox();
    private readonly TextBox openFortiVpnLogBox = CreateLogTextBox();
    private readonly TextBox otherLogBox = CreateLogTextBox();
    private readonly TextBox snapshotLogBox = CreateLogTextBox();
    private readonly Button clearLogButton = new() { Text = "Clear", AutoSize = false, Width = 90, Height = 28 };
    private readonly Button copyLogButton = new() { Text = "Copy", AutoSize = false, Width = 90, Height = 28 };
    private readonly Button loadLogButton = new() { Text = "Load log", Enabled = false, AutoSize = false, Width = 100, Height = 28 };
    private readonly Button refreshLogsButton = new() { Text = "Refresh logs", Enabled = false, AutoSize = false, Width = 110, Height = 28 };
    private readonly ComboBox logFileBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Enabled = false, Width = 420 };
    private readonly CheckBox wordWrapBox = new() { Text = "Word wrap", Checked = true, AutoSize = true, Padding = new Padding(10, 5, 0, 0) };
    private readonly CheckBox preferDtlsBox = new() { Text = "Try DTLS", AutoSize = true };
    private readonly CheckBox forceOnlinkJiraBox = new() { Text = "On-link target", AutoSize = true };
    private readonly CheckBox windowsResolverBox = new() { Text = "Windows DNS", AutoSize = true };
    private readonly CheckBox disableNetworkFixBox = new() { Text = "No repair", AutoSize = true };
    private readonly CheckBox keepAliveBox = new() { Text = "Keep alive", AutoSize = true };
    private readonly CheckBox nativeDnsProbeBox = new() { Text = "DNS probe", AutoSize = true };
    private readonly CheckBox liveAdapterCheckBox = new() { Text = "Check adapter", AutoSize = true };
    private readonly CheckBox liveRouteCheckBox = new() { Text = "Check route", AutoSize = true };
    private readonly CheckBox nativeTcpProbeBox = new() { Text = "Check TCP", AutoSize = true };
    private readonly CheckBox nativeLiveHoldBox = new() { Text = "Keep connected", Checked = true, AutoSize = true };
    private readonly CheckBox nativeHttpsProbeBox = new() { Text = "Check HTTPS", AutoSize = true };
    private readonly CheckBox appSourceBox = new() { Text = "Source app", AutoSize = true };
    private readonly CheckBox appBypassCheckBox = new() { Text = "Bypass check", AutoSize = true };
    private readonly Button runButton = new() { Text = "Run", AutoSize = false, Width = 110, Height = 30 };
    private readonly Button stopButton = new() { Text = "Stop", Enabled = false, AutoSize = false, Width = 110, Height = 30 };
    private readonly Button openRunButton = new() { Text = "Open run folder", Enabled = false, AutoSize = false, Width = 140, Height = 30 };
    private readonly Button openLatestButton = new() { Text = "Open latest tool run", Enabled = false, AutoSize = false, Width = 160, Height = 30 };
    private readonly Label statusLabel = new() { Text = "Ready", AutoSize = true, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 7, 0, 0) };
    private readonly Label versionLabel = new() { AutoSize = true, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 7, 0, 0) };

    private readonly System.Windows.Forms.Timer heartbeatTimer = new() { Interval = 1000 };
    private Process? process;
    private StreamWriter? runLog;
    private string? currentRunFolder;
    private string? latestToolRunFolder;
    private DateTime runStartedAt;

    private sealed record CommandChoice(string Command, string Description, string Stage, string Prerequisites, string? Label = null)
    {
        public override string ToString() => Label ?? $"{Stage} / {Command}";
    }

    private static readonly Dictionary<string, CommandChoice[]> Commands = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MyVpn"] = new[]
        {
            new CommandChoice("preflight", "check config, Python, adapter and helper prerequisites", "1 Baseline", "None. Start here before changing routes or launching tunnels.", "1 Baseline / preflight"),
            new CommandChoice("collect", "save route, DNS, adapter and trace snapshots only", "1 Baseline", "Optional. Useful before and after any tunnel run.", "1 Baseline / collect"),
            new CommandChoice("compare-sources", "compare installed/source/openconnect/openfortivpn files", "1 Baseline", "Optional. Run when installed behavior differs from source/sandbox behavior.", "1 Baseline / compare-sources"),
            new CommandChoice("probe", "test current network without starting VPN", "1 Baseline", "Optional. Run after FortiClient/MyVpn/OpenConnect is already connected.", "2 Current network / probe"),
            new CommandChoice("native-ppp", "native tunnel test; keep connected quickly by default, enable checkboxes only for extra diagnostics", "3 Native tunnel", "Run preflight first. MFA is triggered by POST remote/logincheck when Fortinet returns tokeninfo; approve the mobile push when shown.", "3 Native tunnel / native"),
            new CommandChoice("myvpn-full", "run full native diagnostic and stop after report", "4 Full report", "Run after the smaller native test if you need one collected report.", "4 Full report / myvpn-full"),
            new CommandChoice("app-parity", "test installed app-like launch path; use checkboxes for source/bypass variants", "5 App parity", "Run native live hold first if comparing installed app behavior against the sandbox.", "5 App parity / app")
        },
        ["OpenConnect"] = new[]
        {
            new CommandChoice("preflight", "check OpenConnect executable and environment", "1 Baseline", "None. Start here for OpenConnect comparison."),
            new CommandChoice("collect", "save OpenConnect-related snapshots", "1 Baseline", "Optional. Useful before and after OpenConnect tunnel runs."),
            new CommandChoice("compare-sources", "collect source/config comparison evidence", "1 Baseline", "Optional. Run when comparing OpenConnect scripts/source with MyVpn."),
            new CommandChoice("probe", "probe current network without starting OpenConnect", "2 Current network", "Run after any VPN is already connected."),
            new CommandChoice("auth", "authenticate and stop after cookie/session proof", "3 OpenConnect auth", "Run OpenConnect preflight first. MFA is triggered by Fortinet logincheck/tokeninfo; approve the mobile push when shown."),
            new CommandChoice("connect", "connect with OpenConnect and probe target", "4 OpenConnect tunnel", "Run OpenConnect auth first if MFA/auth behavior is uncertain.")
        },
        ["openfortivpn"] = new[]
        {
            new CommandChoice("preflight", "check openfortivpn executable and environment", "1 Baseline", "None. Start here for openfortivpn comparison."),
            new CommandChoice("compare-sources", "collect source/config comparison evidence", "1 Baseline", "Optional. Run when comparing openfortivpn source with MyVpn."),
            new CommandChoice("probe", "probe current network without starting openfortivpn", "2 Current network", "Run after any VPN is already connected."),
            new CommandChoice("cookie", "test Fortinet cookie/auth flow only", "3 openfortivpn auth", "Run openfortivpn preflight first. MFA is triggered by Fortinet logincheck/tokeninfo; approve the mobile push when shown."),
            new CommandChoice("connect-cookie", "try openfortivpn-style cookie connect and probe", "4 openfortivpn tunnel", "Run cookie first if auth behavior is uncertain.")
        }
    };

    public MainForm()
    {
        Text = "MyVpn Sandbox Lab " + AppVersion;
        versionLabel.Text = AppVersion;
        Width = 1180;
        Height = 820;
        MinimumSize = new Size(960, 650);

        backendBox.Items.AddRange(Commands.Keys.Cast<object>().ToArray());
        backendBox.SelectedIndex = 0;
        backendBox.SelectedIndexChanged += (_, _) =>
        {
            PopulateCommands();
            UpdateVpnOptionAvailability();
        };
        commandBox.SelectedIndexChanged += (_, _) =>
        {
            UpdateCommandPrerequisites();
            UpdateVpnOptionAvailability();
        };
        foreach (var box in MyVpnOptionBoxes())
        {
            box.CheckedChanged += (_, _) => UpdateCommandPrerequisites();
        }
        PopulateCommands();
        UpdateVpnOptionAvailability();

        runButton.Click += async (_, _) => await RunAsync();
        stopButton.Click += (_, _) => StopProcess();
        clearLogButton.Click += (_, _) => ActiveLogBox().Clear();
        copyLogButton.Click += (_, _) =>
        {
            var box = ActiveLogBox();
            if (!string.IsNullOrEmpty(box.Text))
            {
                Clipboard.SetText(box.Text);
            }
        };
        wordWrapBox.CheckedChanged += (_, _) => ApplyWordWrapToLogs();
        loadLogButton.Click += (_, _) => LoadSelectedToolLog();
        refreshLogsButton.Click += (_, _) => RefreshToolLogList();
        logFileBox.SelectedIndexChanged += (_, _) => loadLogButton.Enabled = logFileBox.SelectedItem is LogFileChoice;
        openRunButton.Click += (_, _) => OpenFolder(currentRunFolder);
        openLatestButton.Click += (_, _) => OpenFolder(latestToolRunFolder);
        heartbeatTimer.Tick += (_, _) => UpdateHeartbeat();

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(12)
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        root.Controls.Add(BuildMainGrid(), 0, 0);
        root.Controls.Add(BuildAdvancedGrid(), 0, 1);
        root.Controls.Add(BuildLogPanel(), 0, 2);
        root.Controls.Add(BuildButtonRow(), 0, 3);
        InstallTooltips();

        AppendLog("MyVpn Sandbox Lab " + AppVersion + " ready.");
        AppendLog("Launch this exe as administrator once, then run comparable VPN lab modes without reinstalling MyVpnClient.");
    }

    private void PopulateCommands()
    {
        commandBox.Items.Clear();
        if (backendBox.SelectedItem is string backend && Commands.TryGetValue(backend, out var commands))
        {
            commandBox.Items.AddRange(commands.Cast<object>().ToArray());
            commandBox.DropDownWidth = 620;
            commandBox.SelectedIndex = 0;
        }
        UpdateCommandPrerequisites();
    }

    private void UpdateCommandPrerequisites()
    {
        if (commandBox.SelectedItem is CommandChoice choice)
        {
            var actual = string.Equals(backendBox.SelectedItem?.ToString(), "MyVpn", StringComparison.OrdinalIgnoreCase)
                ? ResolveMyVpnCommand(choice.Command)
                : choice.Command;
            var suffix = actual != choice.Command ? $" Runs: {actual}." : "";
            prerequisitesBox.Text = $"{choice.Stage} / {choice.Command}: {choice.Description}. {choice.Prerequisites}{suffix}";
        }
        else
        {
            prerequisitesBox.Text = "";
        }
    }

    private Control BuildMainGrid()
    {
        var grid = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 6 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));

        AddLabeled(grid, "VPN app", backendBox, 0, 0);
        AddLabeled(grid, "Config", configBox, 2, 0);
        AddLabeled(grid, "Seconds", durationBox, 4, 0);
        AddLabeled(grid, "Command", commandBox, 0, 1, span: 5);
        AddLabeled(grid, "Prerequisites", prerequisitesBox, 0, 2, span: 5);
        AddLabeled(grid, "Options", BuildVpnOptionsRow(), 0, 3, span: 5);
        return grid;
    }

    private Control BuildVpnOptionsRow()
    {
        var row = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true, Margin = new Padding(0, 2, 0, 2) };
        row.Controls.Add(preferDtlsBox);
        row.Controls.Add(windowsResolverBox);
        row.Controls.Add(disableNetworkFixBox);
        row.Controls.Add(keepAliveBox);
        row.Controls.Add(nativeDnsProbeBox);
        row.Controls.Add(liveAdapterCheckBox);
        row.Controls.Add(liveRouteCheckBox);
        row.Controls.Add(nativeTcpProbeBox);
        row.Controls.Add(nativeLiveHoldBox);
        row.Controls.Add(nativeHttpsProbeBox);
        row.Controls.Add(forceOnlinkJiraBox);
        row.Controls.Add(appSourceBox);
        row.Controls.Add(appBypassCheckBox);
        return row;
    }

    private Control BuildAdvancedGrid()
    {
        var box = new GroupBox { Text = "Paths and extra args", Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(10) };
        var grid = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 4 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        box.Controls.Add(grid);

        AddLabeled(grid, "MyVpn source", myVpnSourceBox, 0, 0);
        AddLabeled(grid, "OpenConnect src", openConnectSourceBox, 2, 0);
        AddLabeled(grid, "openfortivpn src", openFortiVpnSourceBox, 0, 1);
        AddLabeled(grid, "OpenConnect exe", openConnectExeBox, 2, 1);
        AddLabeled(grid, "openfortivpn exe", openFortiVpnExeBox, 0, 2);
        AddLabeled(grid, "Extra args", extraArgsBox, 2, 2);
        return box;
    }


    private Control BuildLogPanel()
    {
        var box = new GroupBox { Text = "Live log", Dock = DockStyle.Fill, Padding = new Padding(10) };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
        toolbar.Controls.Add(clearLogButton);
        toolbar.Controls.Add(copyLogButton);
        toolbar.Controls.Add(refreshLogsButton);
        toolbar.Controls.Add(logFileBox);
        toolbar.Controls.Add(loadLogButton);
        toolbar.Controls.Add(wordWrapBox);

        layout.Controls.Add(toolbar, 0, 0);
        AddLogTab("Live", logBox);
        AddLogTab("MyVpn", myVpnLogBox);
        AddLogTab("OpenConnect", openConnectLogBox);
        AddLogTab("openfortivpn", openFortiVpnLogBox);
        AddLogTab("Other", otherLogBox);
        AddLogTab("Adapters", snapshotLogBox);
        ApplyWordWrapToLogs();
        layout.Controls.Add(logTabs, 0, 1);
        box.Controls.Add(layout);
        return box;
    }

    private Control BuildButtonRow()
    {
        var row = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(0, 8, 0, 0), WrapContents = false };
        row.Controls.Add(runButton);
        row.Controls.Add(stopButton);
        row.Controls.Add(openRunButton);
        row.Controls.Add(openLatestButton);
        row.Controls.Add(statusLabel);
        row.Controls.Add(versionLabel);
        return row;
    }

    private void InstallTooltips()
    {
        tips.SetToolTip(backendBox, "The one VPN app family to use for this run. The command list changes so MyVpn, OpenConnect, and openfortivpn tests stay separated.");
        tips.SetToolTip(commandBox, "Specific lab command grouped by investigation stage. For MyVpn native/app variants, checkboxes below choose the exact sub-test.");
        tips.SetToolTip(prerequisitesBox, "Suggested earlier commands for a careful step-by-step run. It is guidance, not an automatic blocker.");
        tips.SetToolTip(configBox, "Path to the MyVpnClient JSON config with server, profile, adapter and saved credential references.");
        tips.SetToolTip(durationBox, "Maximum seconds the selected lab command may run before the script times out or stops probing.");
        tips.SetToolTip(myVpnSourceBox, "Root folder of the MyVpnClient source tree. GUI run logs are written under this folder's sandbox/gui-runs.");
        tips.SetToolTip(openConnectSourceBox, "Root folder of the openconnect checkout used by OpenConnect comparison scripts.");
        tips.SetToolTip(openFortiVpnSourceBox, "Root folder of the openfortivpn checkout used by openfortivpn comparison scripts.");
        tips.SetToolTip(openConnectExeBox, "OpenConnect executable name or full path. Use openconnect if it is on PATH.");
        tips.SetToolTip(openFortiVpnExeBox, "openfortivpn executable name or full path. Use openfortivpn if it is on PATH.");
        tips.SetToolTip(extraArgsBox, "Advanced: raw extra arguments appended to the PowerShell sandbox launcher.");
        tips.SetToolTip(preferDtlsBox, "MyVpn only: try experimental DTLS for this sandbox run. Leave off for baseline TLS tests; use only when comparing DTLS behavior.");
        tips.SetToolTip(forceOnlinkJiraBox, "Native command only: run the on-link target route variant with NextHop 0.0.0.0.");
        tips.SetToolTip(windowsResolverBox, "MyVpn only: allow built-in network check to retry DNS through Resolve-DnsName/Windows resolver when direct UDP DNS fails.");
        tips.SetToolTip(disableNetworkFixBox, "MyVpn only: disable postConnectNetworkFix in the temporary run config to compare behavior without the repair thread.");
        tips.SetToolTip(keepAliveBox, "MyVpn only: set keepTunnelAliveWhileAppRunning for this sandbox config copy.");
        tips.SetToolTip(nativeDnsProbeBox, "Native command only: short DNS-stage probe when Keep connected is off.");
        tips.SetToolTip(liveAdapterCheckBox, "Keep connected mode: verify the VPN adapter has an IPv4 address. Leave off for fastest connect.");
        tips.SetToolTip(liveRouteCheckBox, "Keep connected mode: verify the selected target route uses the VPN adapter. Leave off for fastest connect.");
        tips.SetToolTip(nativeTcpProbeBox, "Keep connected mode: run target TCP reachability checks. Leave off for fastest connect.");
        tips.SetToolTip(nativeLiveHoldBox, "Native command only: keep the tunnel open for manual/browser checks. Uncheck for short PPP/IP stage proof only.");
        tips.SetToolTip(nativeHttpsProbeBox, "Keep connected mode: run target HTTPS/curl checks. This is the slowest check; leave off for fastest connect.");
        tips.SetToolTip(appSourceBox, "App parity command only: use the source bridge path instead of installed app path.");
        tips.SetToolTip(appBypassCheckBox, "App parity command only: run the source live/bypass variant when network check may kill the tunnel.");
        tips.SetToolTip(logTabs, "Logs split by source: live launcher output, MyVpn native files, OpenConnect files, openfortivpn files, and network snapshots.");
        tips.SetToolTip(logBox, "Live stdout/stderr from the sandbox command. A copy is saved in gui-live.log inside the run folder.");
        tips.SetToolTip(myVpnLogBox, "MyVpn native sandbox logs and reports from the latest tool run.");
        tips.SetToolTip(openConnectLogBox, "OpenConnect comparison logs from the latest tool run.");
        tips.SetToolTip(openFortiVpnLogBox, "openfortivpn comparison logs from the latest tool run.");
        tips.SetToolTip(otherLogBox, "Tooling and generic sandbox output that is not specific to MyVpn, OpenConnect, or openfortivpn.");
        tips.SetToolTip(snapshotLogBox, "Captured adapter, DNS and route snapshots from the latest tool run.");
        tips.SetToolTip(clearLogButton, "Clear only the active visible log tab. Saved files in the run folder are not deleted.");
        tips.SetToolTip(copyLogButton, "Copy the active visible log tab to clipboard.");
        tips.SetToolTip(refreshLogsButton, "Scan the latest tool run folder for text/json/log files and group them into tabs.");
        tips.SetToolTip(logFileBox, "Choose a log/report file from the latest tool run folder to view inside this window.");
        tips.SetToolTip(loadLogButton, "Load the selected run log/report file into the live log window.");
        tips.SetToolTip(wordWrapBox, "Wrap long log lines inside the window. Turn off to get horizontal scrolling.");
        tips.SetToolTip(runButton, "Start the selected sandbox command.");
        tips.SetToolTip(stopButton, "Kill the currently running sandbox process tree.");
        tips.SetToolTip(openRunButton, "Open the GUI run folder with command.txt and gui-live.log.");
        tips.SetToolTip(openLatestButton, "Open the latest tool-generated run folder printed by the sandbox script.");
        tips.SetToolTip(statusLabel, "Current launcher state and exit code.");
        tips.SetToolTip(versionLabel, "Sandbox app version. This changes when the lab UI/launcher changes.");
    }

    private static void AddLabeled(TableLayoutPanel grid, string label, Control control, int col, int row, int span = 1)
    {
        var lbl = new Label { Text = label, AutoSize = true, TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill };
        control.Dock = DockStyle.Fill;
        grid.Controls.Add(lbl, col, row);
        grid.Controls.Add(control, col + 1, row);
        if (span > 1)
        {
            grid.SetColumnSpan(control, span);
        }
    }

    private async Task RunAsync()
    {
        if (process is not null && !process.HasExited)
        {
            AppendLog("A run is already active.");
            return;
        }

        latestToolRunFolder = null;
        openLatestButton.Enabled = false;
        logBox.Clear();
        ClearGroupedLogTabs();

        var backend = backendBox.SelectedItem?.ToString() ?? "";
        var command = SelectedCommand();
        AppendLog("VPN app selected for this run: " + backend);
        var runRoot = Path.Combine(myVpnSourceBox.Text, "sandbox", "gui-runs");
        Directory.CreateDirectory(runRoot);
        currentRunFolder = Path.Combine(runRoot, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + SafeName(backend) + "-" + SafeName(command));
        Directory.CreateDirectory(currentRunFolder);
        openRunButton.Enabled = true;

        var psi = BuildProcessStartInfo(backend, command);
        File.WriteAllText(Path.Combine(currentRunFolder, "command.txt"), $"MyVpnSandbox={AppVersion}{Environment.NewLine}Backend={backend}{Environment.NewLine}Command={command}{Environment.NewLine}{psi.FileName} {psi.Arguments}{Environment.NewLine}", Encoding.UTF8);
        runLog = new StreamWriter(Path.Combine(currentRunFolder, "gui-live.log"), append: false, Encoding.UTF8) { AutoFlush = true };

        AppendLog("Run folder: " + currentRunFolder);
        AppendLog("$ " + psi.FileName + " " + psi.Arguments);

        process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => OnProcessLine(e.Data);
        process.ErrorDataReceived += (_, e) => OnProcessLine(e.Data);
        process.Exited += (_, _) => BeginInvoke(new Action(OnProcessExited));

        try
        {
            runButton.Enabled = false;
            stopButton.Enabled = true;
            runStartedAt = DateTime.Now;
            statusLabel.Text = "Running 00:00";
            heartbeatTimer.Start();
            AppendLog("Started. Waiting for sandbox output...");
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await Task.Run(() => process.WaitForExit());
        }
        catch (Exception ex)
        {
            AppendLog("Launch failed: " + ex);
                heartbeatTimer.Stop();
            statusLabel.Text = "Launch failed";
            runButton.Enabled = true;
            stopButton.Enabled = false;
            runLog?.Dispose();
            runLog = null;
        }
    }

    private string SelectedBaseCommand()
    {
        return commandBox.SelectedItem is CommandChoice choice ? choice.Command : commandBox.SelectedItem?.ToString() ?? "";
    }

    private string SelectedCommand()
    {
        var command = SelectedBaseCommand();
        if (string.Equals(backendBox.SelectedItem?.ToString(), "MyVpn", StringComparison.OrdinalIgnoreCase))
        {
            return ResolveMyVpnCommand(command);
        }
        return command;
    }

    private string ResolveMyVpnCommand(string command)
    {
        if (command == "native-ppp")
        {
            if (nativeHttpsProbeBox.Checked) return "native-https";
            if (forceOnlinkJiraBox.Checked) return "native-tcp-onlink";
            if (nativeLiveHoldBox.Checked) return "native-tcp-live";
            if (nativeTcpProbeBox.Checked) return "native-tcp";
            if (nativeDnsProbeBox.Checked) return "native-dns";
        }
        if (command == "app-parity")
        {
            if (appBypassCheckBox.Checked) return "source-app-live";
            if (appSourceBox.Checked) return "source-app-parity";
        }
        return command;
    }

    private ProcessStartInfo BuildProcessStartInfo(string backend, string command)
    {
        string script;
        var args = new List<string>();
        if (backend.Equals("MyVpn", StringComparison.OrdinalIgnoreCase))
        {
            script = Path.Combine(myVpnSourceBox.Text, "sandbox", "run-vpn-lab.ps1");
            args.AddRange(new[] { command, "-DurationSeconds", durationBox.Value.ToString(), "-Config", Quote(configBox.Text), "-OpenConnectSource", Quote(openConnectSourceBox.Text) });
            AddMyVpnOptionArgs(args);
        }
        else if (backend.Equals("OpenConnect", StringComparison.OrdinalIgnoreCase))
        {
            script = Path.Combine(openConnectSourceBox.Text, "sandbox", "run-openconnect-lab.ps1");
            args.AddRange(new[] { command, "-DurationSeconds", durationBox.Value.ToString(), "-Config", Quote(configBox.Text), "-MyVpnClientSource", Quote(myVpnSourceBox.Text), "-OpenConnectExe", Quote(openConnectExeBox.Text) });
        }
        else
        {
            script = Path.Combine(openFortiVpnSourceBox.Text, "sandbox", "run-openfortivpn-lab.ps1");
            args.AddRange(new[] { command, "-DurationSeconds", durationBox.Value.ToString(), "-Config", Quote(configBox.Text), "-MyVpnClientSource", Quote(myVpnSourceBox.Text), "-OpenFortiVpnExe", Quote(openFortiVpnExeBox.Text) });
        }

        if (!File.Exists(script))
        {
            AppendLog("Warning: script does not exist: " + script);
        }

        var extra = extraArgsBox.Text.Trim();
        var allArgs = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(script) + " " + string.Join(" ", args);
        if (!string.IsNullOrWhiteSpace(extra))
        {
            allArgs += " " + extra;
        }

        return new ProcessStartInfo("powershell.exe", allArgs)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = currentRunFolder ?? Environment.CurrentDirectory
        };
    }

    private void AddMyVpnOptionArgs(List<string> args)
    {
        if (preferDtlsBox.Checked) args.Add("-PreferDtls");
        if (forceOnlinkJiraBox.Enabled && forceOnlinkJiraBox.Checked) args.Add("-ForceOnlinkJira");
        if (windowsResolverBox.Checked) args.Add("-WindowsResolver");
        if (disableNetworkFixBox.Checked) args.Add("-DisablePostConnectNetworkFix");
        if (keepAliveBox.Checked) args.Add("-KeepAlive");
        if (nativeLiveHoldBox.Enabled && nativeLiveHoldBox.Checked)
        {
            if (!liveAdapterCheckBox.Checked) args.Add("-SkipLiveAdapterCheck");
            if (!liveRouteCheckBox.Checked) args.Add("-SkipLiveRouteCheck");
            if (!nativeTcpProbeBox.Checked) args.Add("-SkipLiveTcpCheck");
            if (!nativeHttpsProbeBox.Checked) args.Add("-SkipLiveHttpsCheck");
        }
    }

    private CheckBox[] MyVpnOptionBoxes() => new[]
    {
        preferDtlsBox, windowsResolverBox, disableNetworkFixBox, keepAliveBox,
        nativeDnsProbeBox, liveAdapterCheckBox, liveRouteCheckBox, nativeTcpProbeBox, nativeLiveHoldBox, nativeHttpsProbeBox, forceOnlinkJiraBox,
        appSourceBox, appBypassCheckBox
    };

    private void UpdateVpnOptionAvailability()
    {
        var isMyVpn = string.Equals(backendBox.SelectedItem?.ToString(), "MyVpn", StringComparison.OrdinalIgnoreCase);
        var baseCommand = SelectedBaseCommand();
        foreach (var box in new[] { preferDtlsBox, windowsResolverBox, disableNetworkFixBox, keepAliveBox })
        {
            box.Enabled = isMyVpn;
        }
        var nativeEnabled = isMyVpn && baseCommand == "native-ppp";
        foreach (var box in new[] { nativeDnsProbeBox, liveAdapterCheckBox, liveRouteCheckBox, nativeTcpProbeBox, nativeLiveHoldBox, nativeHttpsProbeBox, forceOnlinkJiraBox })
        {
            box.Enabled = nativeEnabled;
        }
        var appEnabled = isMyVpn && baseCommand == "app-parity";
        foreach (var box in new[] { appSourceBox, appBypassCheckBox })
        {
            box.Enabled = appEnabled;
        }
    }

    private void OnProcessLine(string? line)
    {
        if (line is null)
        {
            return;
        }
        BeginInvoke(new Action(() =>
        {
            AppendLog(line);
            if (Directory.Exists(line.Trim()))
            {
                latestToolRunFolder = line.Trim();
                openLatestButton.Enabled = true;
                File.WriteAllText(Path.Combine(currentRunFolder!, "latest-tool-run.txt"), latestToolRunFolder + Environment.NewLine, Encoding.UTF8);
                AppendLog("Tool run folder detected: " + latestToolRunFolder);
                RefreshToolLogList();
                AppendResultPreview(latestToolRunFolder);
            }
        }));
    }

    private void OnProcessExited()
    {
        var exitCode = process?.ExitCode;
        heartbeatTimer.Stop();
        AppendLog("Process exited: " + exitCode);
        if (!string.IsNullOrWhiteSpace(latestToolRunFolder))
        {
            AppendResultPreview(latestToolRunFolder);
        }
        statusLabel.Text = "Exited " + exitCode;
        runButton.Enabled = true;
        stopButton.Enabled = false;
        runLog?.Dispose();
        runLog = null;
    }

    private void UpdateHeartbeat()
    {
        if (process is null || process.HasExited)
        {
            heartbeatTimer.Stop();
            return;
        }

        var elapsed = DateTime.Now - runStartedAt;
        statusLabel.Text = $"Running {elapsed:mm\\:ss}";
        if (Math.Abs(elapsed.TotalSeconds % 10) < 0.5)
        {
            AppendLog($"Still running after {elapsed:mm\\:ss}...");
        }
    }

    private sealed record LogFileChoice(string Path, string DisplayName)
    {
        public override string ToString() => DisplayName;
    }

    private void RefreshToolLogList()
    {
        logFileBox.Items.Clear();
        logFileBox.Enabled = false;
        loadLogButton.Enabled = false;
        refreshLogsButton.Enabled = !string.IsNullOrWhiteSpace(latestToolRunFolder) && Directory.Exists(latestToolRunFolder);

        if (!refreshLogsButton.Enabled || latestToolRunFolder is null)
        {
            return;
        }

        var root = latestToolRunFolder;
        var files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(file => file.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                || file.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                || file.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            .OrderBy(file => PriorityFileName(Path.GetFileName(file)))
            .ThenBy(file => file, StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .Select(file =>
            {
                var relative = Path.GetRelativePath(root, file);
                return new LogFileChoice(file, relative);
            })
            .Cast<object>()
            .ToArray();

        if (files.Length == 0)
        {
            AppendLog("No text/json/log files found in latest tool run folder.");
            return;
        }

        logFileBox.Items.AddRange(files);
        logFileBox.Enabled = true;
        logFileBox.SelectedIndex = 0;
        loadLogButton.Enabled = true;
        PopulateGroupedLogTabs(root, files.OfType<LogFileChoice>().Select(x => x.Path).ToArray());
        AppendLog($"Found {files.Length} log/report files. Choose one and click Load log.");
    }

    private static int PriorityFileName(string name)
    {
        return name.ToLowerInvariant() switch
        {
            "preflight.txt" => 0,
            "summary.txt" => 1,
            "summary.json" => 2,
            "app-parity-report.json" => 3,
            "myvpn.log" => 4,
            "openconnect.log" => 5,
            "openfortivpn.log" => 6,
            _ => 50
        };
    }

    private void LoadSelectedToolLog()
    {
        if (logFileBox.SelectedItem is not LogFileChoice selected || !File.Exists(selected.Path))
        {
            return;
        }

        try
        {
            var content = File.ReadAllText(selected.Path, Encoding.UTF8);
            if (Path.GetFileName(selected.Path).Equals("preflight.txt", StringComparison.OrdinalIgnoreCase))
            {
                SplitPreflightIntoTabs(selected.DisplayName, selected.Path, content, clearExisting: true);
                logTabs.SelectedTab = myVpnLogBox.Parent as TabPage;
                return;
            }

            var target = LogBoxForFile(selected.Path, content);
            target.Clear();
            AppendToBox(target, "Viewing: " + selected.DisplayName);
            AppendToBox(target, "Full path: " + selected.Path);
            AppendToBox(target, "");
            AppendContentToBox(target, content);
            logTabs.SelectedTab = target.Parent as TabPage;
        }
        catch (Exception ex)
        {
            AppendLog("Could not load selected log: " + ex.Message);
        }
    }

    private void AppendResultPreview(string folder)
    {
        if (!Directory.Exists(folder))
        {
            return;
        }

        foreach (var name in new[] { "preflight.txt", "summary.txt", "summary.json", "app-parity-report.json", "myvpn.log", "openconnect.log", "openfortivpn.log" })
        {
            var file = Path.Combine(folder, name);
            if (!File.Exists(file))
            {
                continue;
            }

            try
            {
                var content = File.ReadAllText(file, Encoding.UTF8);
                if (content.Length > 12000)
                {
                    content = content[..12000] + Environment.NewLine + "... truncated in GUI preview; open run folder for full file ...";
                }
                AppendLog("");
                AppendLog("== " + name + " ==");
                foreach (var line in content.Replace("\r\n", "\n").Split('\n'))
                {
                    AppendLog(line);
                }
            }
            catch (Exception ex)
            {
                AppendLog("Could not preview " + name + ": " + ex.Message);
            }
            return;
        }
    }

    private void StopProcess()
    {
        try
        {
            if (process is null || process.HasExited)
            {
                AppendLog("No active process to stop.");
                runButton.Enabled = true;
                stopButton.Enabled = false;
                statusLabel.Text = "Stopped";
                return;
            }

            var pid = process.Id;
            AppendLog($"Stopping process tree for PID {pid}...");
            heartbeatTimer.Stop();
            statusLabel.Text = "Stopping";
            stopButton.Enabled = false;

            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception killEx)
            {
                AppendLog(".NET process-tree kill failed: " + killEx.Message);
            }

            try
            {
                var taskkill = Process.Start(new ProcessStartInfo("taskkill.exe", $"/PID {pid} /T /F")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                });
                if (taskkill is not null)
                {
                    var output = taskkill.StandardOutput.ReadToEnd() + taskkill.StandardError.ReadToEnd();
                    taskkill.WaitForExit(5000);
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        AppendLog("taskkill: " + output.Trim().Replace("\r\n", " | ").Replace("\n", " | "));
                    }
                }
            }
            catch (Exception taskkillEx)
            {
                AppendLog("taskkill fallback failed: " + taskkillEx.Message);
            }

            runButton.Enabled = true;
            statusLabel.Text = "Stopped";
        }
        catch (Exception ex)
        {
            AppendLog("Stop failed: " + ex.Message);
            runButton.Enabled = true;
            stopButton.Enabled = false;
        }
    }

    private void AppendLog(string text)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {text}";
        logBox.AppendText(line + Environment.NewLine);
        runLog?.WriteLine(line);
    }


    private static TextBox CreateLogTextBox()
    {
        return new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            WordWrap = true,
            ReadOnly = true,
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9F),
            BackColor = Color.White
        };
    }

    private void AddLogTab(string title, TextBox textBox)
    {
        var page = new TabPage(title);
        page.Controls.Add(textBox);
        logTabs.TabPages.Add(page);
    }

    private TextBox ActiveLogBox()
    {
        return logTabs.SelectedTab?.Controls.OfType<TextBox>().FirstOrDefault() ?? logBox;
    }

    private IEnumerable<TextBox> AllLogBoxes()
    {
        yield return logBox;
        yield return myVpnLogBox;
        yield return openConnectLogBox;
        yield return openFortiVpnLogBox;
        yield return otherLogBox;
        yield return snapshotLogBox;
    }

    private void ApplyWordWrapToLogs()
    {
        foreach (var box in AllLogBoxes())
        {
            box.WordWrap = wordWrapBox.Checked;
            box.ScrollBars = wordWrapBox.Checked ? ScrollBars.Vertical : ScrollBars.Both;
        }
    }

    private void ClearGroupedLogTabs()
    {
        myVpnLogBox.Clear();
        openConnectLogBox.Clear();
        openFortiVpnLogBox.Clear();
        otherLogBox.Clear();
        snapshotLogBox.Clear();
    }

    private TextBox LogBoxForFile(string path, string? content = null)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        var normalized = path.ToLowerInvariant();
        var sample = (content ?? "").ToLowerInvariant();
        if (normalized.Contains(@"\snapshot\") || name.StartsWith("dns-") || name.Contains("route") || name.Contains("adapter"))
        {
            return snapshotLogBox;
        }
        if (name.Equals("myvpn.log", StringComparison.OrdinalIgnoreCase) || sample.Contains("myvpn_tunnel") || sample.Contains("myvpnclient") || sample.Contains("integrated myvpn"))
        {
            return myVpnLogBox;
        }
        if (sample.Contains("openfortivpn") || name.Contains("openfortivpn") || normalized.Contains("openfortivpn"))
        {
            return openFortiVpnLogBox;
        }
        if (sample.Contains("openconnect") || name.Contains("openconnect") || normalized.Contains("openconnect"))
        {
            return openConnectLogBox;
        }
        if (name.Contains("python") || name.Contains("dotnet") || name.Contains("summary"))
        {
            return otherLogBox;
        }
        return myVpnLogBox;
    }

    private void PopulateGroupedLogTabs(string root, string[] files)
    {
        ClearGroupedLogTabs();
        foreach (var file in files.OrderBy(file => PriorityFileName(Path.GetFileName(file))).ThenBy(file => file, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var relative = Path.GetRelativePath(root, file);
                var content = File.ReadAllText(file, Encoding.UTF8);
                if (Path.GetFileName(file).Equals("preflight.txt", StringComparison.OrdinalIgnoreCase))
                {
                    SplitPreflightIntoTabs(relative, file, content, clearExisting: false);
                    continue;
                }

                var target = LogBoxForFile(file, content);
                AppendToBox(target, "== " + relative + " ==");
                if (content.Length > 20000)
                {
                    content = content[..20000] + Environment.NewLine + "... truncated in grouped tab; use Load log/open folder for full file ...";
                }
                AppendContentToBox(target, content);
                AppendToBox(target, "");
            }
            catch (Exception ex)
            {
                AppendToBox(myVpnLogBox, "Could not read " + file + ": " + ex.Message);
            }
        }
    }


    private void SplitPreflightIntoTabs(string displayName, string path, string content, bool clearExisting)
    {
        if (clearExisting)
        {
            myVpnLogBox.Clear();
            openConnectLogBox.Clear();
            otherLogBox.Clear();
        }

        AppendToBox(myVpnLogBox, "== " + displayName + " / MyVpn config ==");
        AppendToBox(myVpnLogBox, "Full path: " + path);
        AppendToBox(myVpnLogBox, "");

        AppendToBox(openConnectLogBox, "== " + displayName + " / openconnect --version ==");
        AppendToBox(openConnectLogBox, "Full path: " + path);
        AppendToBox(openConnectLogBox, "");

        AppendToBox(otherLogBox, "== " + displayName + " / tools ==");
        AppendToBox(otherLogBox, "Full path: " + path);
        AppendToBox(otherLogBox, "");

        var current = myVpnLogBox;
        foreach (var rawLine in content.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.StartsWith("openconnect_source=", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("$ openconnect --version", StringComparison.OrdinalIgnoreCase))
            {
                current = openConnectLogBox;
            }
            else if (line.StartsWith("$ ", StringComparison.Ordinal)
                && (line.Contains("python", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("dotnet", StringComparison.OrdinalIgnoreCase)))
            {
                current = otherLogBox;
            }

            AppendToBox(current, line);
        }

        AppendToBox(myVpnLogBox, "");
        AppendToBox(openConnectLogBox, "");
        AppendToBox(otherLogBox, "");
    }

    private static void AppendToBox(TextBox box, string text)
    {
        box.AppendText(text + Environment.NewLine);
    }

    private static void AppendContentToBox(TextBox box, string content)
    {
        foreach (var line in content.Replace("\r\n", "\n").Split('\n'))
        {
            AppendToBox(box, line);
        }
    }

    private static void OpenFolder(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            return;
        }
        Process.Start(new ProcessStartInfo("explorer.exe", Quote(folder)) { UseShellExecute = true });
    }

    private static string AppVersion
    {
        get
        {
            var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            return "v" + (string.IsNullOrWhiteSpace(version) ? "0.0.0" : version);
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private static string SafeName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.Select(ch => invalid.Contains(ch) || char.IsWhiteSpace(ch) ? '-' : ch).ToArray();
        return new string(chars).Trim('-').ToLowerInvariant();
    }
}
