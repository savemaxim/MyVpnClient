using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

namespace MyVpnClient;

internal sealed class MainForm : Form
{
    private static readonly string AppVersion =
        typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private readonly string _appDirectory;
    private readonly string _installDirectory;
    private readonly string _configPath;
    private readonly string _settingsPath;
    private readonly string _profilesPath;
    private readonly SecretStore _secretStore;
    private readonly VpnController _controller;
    private readonly VpnProfileStore _profileStore;
    private readonly AppSettings _appSettings;
    private readonly NotifyIcon _trayIcon;
    private readonly Icon _connectedTrayIcon;
    private readonly Icon _connectingTrayIcon;
    private readonly Icon _disconnectedTrayIcon;
    private readonly System.Windows.Forms.Timer _statusTimer;
    private ApiServer? _apiServer;

    private readonly Label _statusLabel = new();
    private readonly Label _uptimeLabel = new();
    private readonly Label _statusDetailLabel = new();
    private readonly ComboBox _profileBox = new();
    private readonly Button _connectButton = new();
    private readonly Button _disconnectButton = new();
    private readonly Button _refreshButton = new();
    private readonly Button _settingsButton = new();
    private readonly TextBox _logBox = new();
    private readonly Button _clearLogsButton = new();
    private readonly Button _scrollToEndButton = new();
    private readonly Button _sessionScrollToEndButton = new();
    private readonly TextBox _logSearchBox = new();
    private readonly Label _logSearchCountLabel = new();
    private readonly Button _logSearchPreviousButton = new();
    private readonly Button _logSearchNextButton = new();
    private readonly TextBox _sessionSearchBox = new();
    private readonly Label _sessionSearchCountLabel = new();
    private readonly Button _sessionSearchPreviousButton = new();
    private readonly Button _sessionSearchNextButton = new();
    private readonly TextBox _diagnosticsBox = new();
    private readonly TableLayoutPanel _fullDiagnosticChecklistPanel = new();
    private readonly Dictionary<string, CheckBox> _fullDiagnosticCheckBoxes = [];
    private readonly Label _authGauge = new();
    private readonly Label _mfaGauge = new();
    private readonly Label _tunnelGauge = new();
    private readonly Label _networkGauge = new();
    private readonly Button _preflightButton = new();
    private readonly Button _sandboxCheckButton = new();
    private readonly Button _diagnosticsButton = new();
    private readonly Button _fullDiagnosticButton = new();
    private readonly Button _lifecycleProofButton = new();
    private readonly Button _repairNetworkButton = new();
    private readonly Button _resetNetworkButton = new();
    private readonly TextBox _traceBox = new();
    private readonly ToolTip _toolTip = new();
    private readonly ContextMenuStrip _trayMenu = new();
    private readonly ToolStripMenuItem _trayOpenItem = new("Open Console");
    private readonly ToolStripMenuItem _trayAboutItem = new("About");
    private readonly ToolStripMenuItem _trayConnectItem = new("Connect");
    private readonly ToolStripMenuItem _trayDisconnectItem = new("Disconnect");
    private readonly ToolStripMenuItem _trayShutdownItem = new("Shutdown");
    private TabControl? _mainTabs;
    private bool _allowExit;
    private bool _loadingProfiles;
    private bool _userDisconnectRequested;
    private bool _fullDiagnosticRunning;
    private bool _connectLaunchInProgress;
    private bool _wasEverConnected;
    private DateTimeOffset? _connectedSessionStartedAt;
    private bool _logFollowTail = true;
    private bool _sessionFollowTail = true;
    private bool _logPageActivated;
    private DateTime _connectLaunchStartedAt;
    private int _connectLaunchProgress;
    private int _logSearchIndex = -1;
    private int _sessionSearchIndex = -1;
    private TrayIconState _trayIconState = TrayIconState.Unknown;
    private DiagnosticCheckState _mfaGaugeState = DiagnosticCheckState.Pending;
    private VpnConnectionState _currentState = VpnConnectionState.Disconnected;
    private readonly List<LogSearchMatch> _logSearchMatches = [];
    private readonly List<LogSearchMatch> _sessionSearchMatches = [];
    private List<VpnProfile> _profiles = [];

    private const int EmGetFirstVisibleLine = 0x00CE;
    private const int EmLineScroll = 0x00B6;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, int message, uint action, IntPtr changeInfo);

    private const uint MsgfltAllow = 1;

    public MainForm()
    {
        _installDirectory = LocateInstallDirectory();
        _appDirectory = PrepareAppDirectory(_installDirectory);
        _configPath = Path.Combine(_appDirectory, "config.json");
        _settingsPath = Path.Combine(_appDirectory, "state", "myvpnclient.settings.json");
        _profilesPath = Path.Combine(_appDirectory, "profiles.json");
        _secretStore = new SecretStore(_appDirectory);
        _controller = new VpnController(_installDirectory, _appDirectory);
        _controller.ClearSessionTrace();
        _controller.WriteOwnerPid();
        _controller.RemoveLegacyHelperTasks();
        _profileStore = new VpnProfileStore(_profilesPath, _configPath);
        _appSettings = AppSettings.Load(_settingsPath);
        MigrateConfigPasswordToSecretStore();

        Text = $"MyVpnClient {AppVersion}";
        Icon = LoadApplicationIcon();
        DoubleBuffered = true;
        BackColor = Color.FromArgb(236, 246, 253);
        MinimumSize = new Size(960, 560);
        StartPosition = FormStartPosition.Manual;
        Font = new Font("Segoe UI", 9F);
        _toolTip.AutoPopDelay = 18000;
        _toolTip.InitialDelay = 350;
        _toolTip.ReshowDelay = 100;
        _toolTip.ShowAlways = true;
        ApplySavedWindowBounds();

        BuildLayout();
        LoadProfiles();

        _connectedTrayIcon = BuildIcon(Color.ForestGreen);
        _connectingTrayIcon = BuildIcon(Color.DarkOrange);
        _disconnectedTrayIcon = BuildIcon(Color.FromArgb(180, 35, 24));
        _trayIcon = BuildTrayIcon();
        _statusTimer = new System.Windows.Forms.Timer { Interval = 1_000 };
        _statusTimer.Tick += async (_, _) =>
        {
            if (!_fullDiagnosticRunning)
            {
                await RefreshStatusAsync();
            }
        };
        _statusTimer.Start();
        RestartApiServer();

        Load += (_, _) => BeginInvoke((Action)EnsureVisibleAfterStartup);
        Shown += async (_, _) => await OnShownAsync();
        FormClosing += OnFormClosing;
        Move += (_, _) => SaveWindowBounds();
        ResizeEnd += (_, _) => SaveWindowBounds();
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        Resize += (_, _) =>
        {
            if (WindowState == FormWindowState.Minimized)
            {
                Hide();
            }
        };
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        AllowExternalLaunchMessage();
    }

    protected override void WndProc(ref Message m)
    {
        if (SingleInstanceSignal.ShowWindowMessage != 0 && m.Msg == SingleInstanceSignal.ShowWindowMessage)
        {
            ShowFromExternalLaunch();
            return;
        }

        base.WndProc(ref m);
    }

    private void AllowExternalLaunchMessage()
    {
        if (!OperatingSystem.IsWindows() || SingleInstanceSignal.ShowWindowMessage == 0)
        {
            return;
        }

        try
        {
            _ = ChangeWindowMessageFilterEx(Handle, SingleInstanceSignal.ShowWindowMessage, MsgfltAllow, IntPtr.Zero);
        }
        catch
        {
        }
    }

    private void MigrateConfigPasswordToSecretStore()
    {
        try
        {
            var profile = VpnProfile.Load(_configPath);
            if (string.IsNullOrEmpty(profile.Password))
            {
                return;
            }

            _secretStore.SavePassword(profile.Password);
            profile.Password = "";
            profile.Save(_configPath);
        }
        catch
        {
        }
    }

    private async Task OnShownAsync()
    {
        try
        {
            await PromptForExistingVpnAfterInstallAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Startup cleanup skipped: " + ex.Message);
        }

        await RefreshStatusAsync();
    }

    private async Task PromptForExistingVpnAfterInstallAsync()
    {
        if (_appSettings.LastRunVersion == AppVersion)
        {
            return;
        }

        _appSettings.LastRunVersion = AppVersion;
        _appSettings.Save(_settingsPath);

        var status = await _controller.StatusAsync();
        if (status.ExitCode == 0)
        {
            var answer = MessageBox.Show(
                this,
                "An existing MyVpnClient VPN session is already running from before this app version started.\n\nDisconnect it now so the new install starts cleanly?",
                "Existing VPN session",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1);
            if (answer != DialogResult.Yes)
            {
                return;
            }

            var result = await _controller.DisconnectAsync();
            AppendLog(result.CombinedOutput);
            return;
        }

        var cleanup = await _controller.CleanupBundledOpenConnectAsync();
        AppendLog(cleanup.CombinedOutput);
    }

    private static string PrepareAppDirectory(string installDirectory)
    {
        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "MyVpnClient");
        Directory.CreateDirectory(dataDirectory);
        Directory.CreateDirectory(Path.Combine(dataDirectory, "state"));

        if (!string.IsNullOrWhiteSpace(installDirectory))
        {
            CopyRuntimeFile(installDirectory, dataDirectory, "config.example.json", overwrite: true);
            CopyRuntimeFile(installDirectory, dataDirectory, "profiles.example.json", overwrite: true);
            CopyRuntimeFile(installDirectory, dataDirectory, "config.example.json", "config.json", overwrite: false);
            CopyRuntimeFile(installDirectory, dataDirectory, "profiles.example.json", "profiles.json", overwrite: false);
        }
        DeleteLegacyProgramDataCodeCopies(dataDirectory);

        return dataDirectory;
    }

    private static void DeleteLegacyProgramDataCodeCopies(string dataDirectory)
    {
        foreach (var name in new[]
        {
            "myvpnclient_bridge.py",
            "connect-admin.ps1",
            "install-helper-tasks-admin.ps1",
            "uninstall-helper-tasks-admin.ps1",
            "run-helper-task.ps1",
            "task-connect.ps1",
            "task-disconnect.ps1",
            "task-repair-network.ps1",
            "task-reset-network.ps1"
        })
        {
            TryDeleteFile(Path.Combine(dataDirectory, name));
        }

        TryDeleteDirectory(Path.Combine(dataDirectory, "backend"));
        TryDeleteDirectory(Path.Combine(dataDirectory, "myvpn_tunnel"));
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string LocateInstallDirectory()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "myvpnclient_bridge.py")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return "";
    }

    private static void CopyRuntimeFile(string sourceDirectory, string targetDirectory, string name, bool overwrite)
    {
        CopyRuntimeFile(sourceDirectory, targetDirectory, name, name, overwrite);
    }

    private static void CopyRuntimeFile(string sourceDirectory, string targetDirectory, string sourceName, string targetName, bool overwrite)
    {
        var source = Path.Combine(sourceDirectory, sourceName);
        var target = Path.Combine(targetDirectory, targetName);
        if (!File.Exists(source) || (!overwrite && File.Exists(target)))
        {
            return;
        }

        try
        {
            File.Copy(source, target, overwrite);
        }
        catch (IOException) when (overwrite && File.Exists(target))
        {
        }
        catch (UnauthorizedAccessException) when (overwrite && File.Exists(target))
        {
        }
    }

    private static void CopyRuntimeDirectory(string sourceDirectory, string targetDirectory, string name)
    {
        var source = Path.Combine(sourceDirectory, name);
        var target = Path.Combine(targetDirectory, name);
        if (!Directory.Exists(source))
        {
            return;
        }

        Directory.CreateDirectory(target);
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            var targetFile = Path.Combine(target, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(targetFile)!);
            File.Copy(file, targetFile, overwrite: true);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _trayIcon.Icon = null;
            _trayIcon.Dispose();
            _connectedTrayIcon.Dispose();
            _connectingTrayIcon.Dispose();
            _disconnectedTrayIcon.Dispose();
            _statusTimer.Dispose();
            _apiServer?.Dispose();
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        }

        base.Dispose(disposing);
    }

    private void BuildLayout()
    {
        var root = new GradientTableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(16)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 176));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Color.Transparent
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));

        _statusLabel.Text = "Checking...";
        _statusLabel.Dock = DockStyle.Fill;
        _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        _statusLabel.Font = new Font(Font.FontFamily, 12F, FontStyle.Bold);
        _statusLabel.BackColor = Color.Transparent;

        _uptimeLabel.Text = "";
        _uptimeLabel.Dock = DockStyle.Fill;
        _uptimeLabel.TextAlign = ContentAlignment.MiddleLeft;
        _uptimeLabel.Font = new Font(Font.FontFamily, 10F, FontStyle.Bold);
        _uptimeLabel.ForeColor = Color.ForestGreen;
        _uptimeLabel.BackColor = Color.Transparent;
        _uptimeLabel.Margin = new Padding(8, 0, 0, 0);
        _uptimeLabel.MinimumSize = new Size(96, 0);
        _uptimeLabel.AutoEllipsis = false;

        _statusDetailLabel.Dock = DockStyle.Fill;
        _statusDetailLabel.TextAlign = ContentAlignment.TopLeft;
        _statusDetailLabel.Font = new Font(Font.FontFamily, 8.5F, FontStyle.Regular);
        _statusDetailLabel.ForeColor = Color.FromArgb(68, 78, 88);
        _statusDetailLabel.BackColor = Color.Transparent;
        _statusDetailLabel.Margin = new Padding(0, 2, 0, 0);

        var statusPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            BackColor = Color.Transparent,
            Margin = new Padding(0)
        };
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 128));
        statusPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        statusPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusPanel.Controls.Add(_statusLabel, 0, 0);
        statusPanel.Controls.Add(_uptimeLabel, 1, 0);
        statusPanel.Controls.Add(_statusDetailLabel, 0, 1);
        statusPanel.SetColumnSpan(_statusDetailLabel, 2);
        header.Controls.Add(statusPanel, 0, 0);

        var profileLabel = new Label
        {
            Text = "VPN profile",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Color.Transparent
        };
        header.Controls.Add(profileLabel, 0, 1);

        var actionRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 0, 0, 0),
            Margin = new Padding(0)
        };
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        actionRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _profileBox.Dock = DockStyle.Fill;
        _profileBox.MinimumSize = new Size(260, 0);
        _profileBox.DropDownStyle = ComboBoxStyle.DropDownList;
        _profileBox.Margin = new Padding(0, 4, 8, 0);
        _profileBox.SelectedIndexChanged += (_, _) => WriteSelectedProfileToConfig();
        actionRow.Controls.Add(_profileBox, 0, 0);

        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(0),
            Margin = new Padding(0),
            BackColor = Color.Transparent
        };
        ConfigureCommandButton(_connectButton, "Connect", trailingMargin: true);
        ConfigureCommandButton(_disconnectButton, "Disconnect", trailingMargin: true);
        ConfigureCommandButton(_refreshButton, "Refresh", trailingMargin: true);
        ConfigureCommandButton(_settingsButton, "Settings", trailingMargin: false);
        _connectButton.Click += (_, _) => Connect();
        _disconnectButton.Click += async (_, _) => await DisconnectAsync();
        _refreshButton.Click += async (_, _) => await RefreshStatusAsync();
        _settingsButton.Click += (_, _) => OpenSettings();
        _disconnectButton.Visible = false;
        buttonPanel.Controls.AddRange([_connectButton, _disconnectButton, _refreshButton, _settingsButton]);
        actionRow.Controls.Add(buttonPanel, 1, 0);
        header.Controls.Add(actionRow, 0, 2);
        header.Controls.Add(BuildConnectionGaugeRow(), 0, 3);

        var tabs = CreateStableTabs();
        tabs.TabPages.Add(MakeTracePage());
        tabs.TabPages.Add(MakeLogPage());
        tabs.TabPages.Add(MakeDiagnosticsPage());
        tabs.SelectedIndexChanged += (_, _) =>
        {
            if (tabs.SelectedTab?.Text == "Logs")
            {
                var firstLogActivation = !_logPageActivated;
                _logPageActivated = true;
                RefreshLogBox(scrollToBottom: firstLogActivation || _logFollowTail, detectManualScroll: !firstLogActivation);
            }
        };
        _mainTabs = tabs;

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(tabs, 0, 1);
        Controls.Add(root);
    }

    private static void ConfigureCommandButton(Button button, string text, bool trailingMargin)
    {
        button.Text = text;
        button.AutoSize = true;
        button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        button.MinimumSize = new Size(Math.Max(96, TextRenderer.MeasureText(text, button.Font).Width + 36), 30);
        button.Margin = new Padding(0, 4, trailingMargin ? 8 : 0, 0);
        button.Padding = new Padding(8, 0, 8, 0);
    }

    private Control BuildConnectionGaugeRow()
    {
        var row = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 2, 0, 0),
            Margin = Padding.Empty
        };
        ConfigureGauge(_authGauge, "Auth");
        ConfigureGauge(_mfaGauge, "MFA");
        ConfigureGauge(_tunnelGauge, "Tunnel");
        ConfigureGauge(_networkGauge, "Network");
        row.Controls.AddRange([_authGauge, _mfaGauge, _tunnelGauge, _networkGauge]);
        UpdateConnectionGauges(null);
        return row;
    }

    private static void ConfigureGauge(Label gauge, string text)
    {
        gauge.AutoSize = false;
        gauge.Font = new Font("Segoe UI", 8.25F, FontStyle.Bold);
        gauge.MinimumSize = new Size(106, 24);
        gauge.Size = new Size(Math.Max(106, TextRenderer.MeasureText(text, gauge.Font).Width + 34), 24);
        gauge.Margin = new Padding(0, 0, 8, 0);
        gauge.TextAlign = ContentAlignment.MiddleCenter;
        gauge.Text = text;
    }

    private void UpdateConnectionGauges(VpnStatusSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            SetGauge(_authGauge, "Auth", DiagnosticCheckState.Pending);
            SetMfaGauge(DiagnosticCheckState.Pending);
            SetGauge(_tunnelGauge, "Tunnel", DiagnosticCheckState.Pending);
            SetGauge(_networkGauge, "Network", DiagnosticCheckState.Pending);
            return;
        }

        var detail = (snapshot.Phase + " " + snapshot.UserMessage + " " + snapshot.SuggestedAction).ToLowerInvariant();
        var rawDetail = snapshot.Detail.ToLowerInvariant();
        var combined = detail + " " + rawDetail;
        if (snapshot.State == VpnConnectionState.Connected)
        {
            SetGauge(_authGauge, "Auth", DiagnosticCheckState.Passed);
            SetMfaGauge(DiagnosticCheckState.Passed);
            SetGauge(_tunnelGauge, "Tunnel", DiagnosticCheckState.Passed);
            SetGauge(_networkGauge, "Network", DiagnosticCheckState.Passed);
            return;
        }

        if (snapshot.State == VpnConnectionState.Disconnected && snapshot.Phase.Equals("AuthFailed", StringComparison.OrdinalIgnoreCase))
        {
            SetGauge(_authGauge, "Auth", DiagnosticCheckState.Failed);
            SetMfaGauge(DiagnosticCheckState.Failed);
            SetGauge(_tunnelGauge, "Tunnel", DiagnosticCheckState.Pending);
            SetGauge(_networkGauge, "Network", DiagnosticCheckState.Pending);
            return;
        }

        if (snapshot.State == VpnConnectionState.Disconnected && snapshot.Phase.Equals("FailedNetwork", StringComparison.OrdinalIgnoreCase))
        {
            SetGauge(_authGauge, "Auth", DiagnosticCheckState.Passed);
            SetMfaGauge(snapshot.MfaStatus.Equals("accepted", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticCheckState.Passed
                : snapshot.MfaStatus.Equals("failed", StringComparison.OrdinalIgnoreCase)
                    ? DiagnosticCheckState.Failed
                    : DiagnosticCheckState.Pending);
            SetGauge(_tunnelGauge, "Tunnel", DiagnosticCheckState.Passed);
            SetGauge(_networkGauge, "Network", DiagnosticCheckState.Failed);
            return;
        }

        if (snapshot.State == VpnConnectionState.Connecting || _connectLaunchInProgress)
        {
            var authPassed = combined.Contains("vpn cookie") || combined.Contains("svpncookie") || combined.Contains("tls tunnel") || combined.Contains("ppp");
            var mfaState = snapshot.MfaStatus.ToLowerInvariant();
            var mfaPassed = mfaState == "accepted";
            var mfaFailed = mfaState == "failed";
            var mfaRequested = mfaState == "requested"
                || (string.IsNullOrWhiteSpace(mfaState) && (combined.Contains("mfa") || combined.Contains("fortitoken")))
                || (_mfaGaugeState == DiagnosticCheckState.Running && !mfaFailed && !mfaPassed);
            var nextMfaState = mfaFailed
                ? DiagnosticCheckState.Failed
                : mfaPassed
                    ? DiagnosticCheckState.Passed
                    : mfaRequested
                        ? DiagnosticCheckState.Running
                        : DiagnosticCheckState.Pending;
            SetGauge(_authGauge, "Auth", authPassed ? DiagnosticCheckState.Passed : combined.Contains("authenticat") || _connectLaunchInProgress ? DiagnosticCheckState.Running : DiagnosticCheckState.Pending);
            SetMfaGauge(nextMfaState);
            SetGauge(_tunnelGauge, "Tunnel", combined.Contains("tls") || combined.Contains("tunnel") ? DiagnosticCheckState.Running : DiagnosticCheckState.Pending);
            SetGauge(_networkGauge, "Network", combined.Contains("ppp") || combined.Contains("network") || combined.Contains("dns") ? DiagnosticCheckState.Running : DiagnosticCheckState.Pending);
            return;
        }

        SetGauge(_authGauge, "Auth", DiagnosticCheckState.Pending);
        SetMfaGauge(DiagnosticCheckState.Pending);
        SetGauge(_tunnelGauge, "Tunnel", DiagnosticCheckState.Pending);
        SetGauge(_networkGauge, "Network", DiagnosticCheckState.Pending);
    }

    private void SetMfaGauge(DiagnosticCheckState state)
    {
        _mfaGaugeState = state;
        SetGauge(_mfaGauge, "MFA", state);
    }

    private static void SetGauge(Label gauge, string text, DiagnosticCheckState state)
    {
        gauge.Text = text;
        gauge.BackColor = state switch
        {
            DiagnosticCheckState.Running => Color.FromArgb(255, 224, 128),
            DiagnosticCheckState.Passed => Color.FromArgb(220, 244, 226),
            DiagnosticCheckState.Failed => Color.FromArgb(255, 224, 224),
            _ => Color.FromArgb(230, 236, 242)
        };
        gauge.ForeColor = state switch
        {
            DiagnosticCheckState.Running => Color.FromArgb(92, 55, 0),
            DiagnosticCheckState.Passed => Color.FromArgb(20, 95, 45),
            DiagnosticCheckState.Failed => Color.FromArgb(150, 22, 22),
            _ => Color.FromArgb(72, 82, 92)
        };
        gauge.BorderStyle = BorderStyle.FixedSingle;
    }

    private TabPage MakeLogPage()
    {
        var page = new TabPage("Logs");
        page.BackColor = Color.FromArgb(248, 251, 254);
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var toolbar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            BackColor = Color.Transparent,
            Padding = new Padding(8, 5, 8, 5)
        };
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var searchPanel = BuildSearchPanel(
            _logSearchBox,
            _logSearchPreviousButton,
            _logSearchNextButton,
            _logSearchCountLabel,
            (_, _) => RefreshLogSearchMatches(selectFirst: true),
            MoveLogSearch);

        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Transparent,
            Margin = Padding.Empty
        };
        ConfigureToolbarButton(_clearLogsButton, "Clear logs");
        _clearLogsButton.Click += (_, _) => ClearLogs();
        ConfigureToolbarButton(_scrollToEndButton, "Scroll to End");
        _scrollToEndButton.Click += (_, _) => EnableLogTailFollow();
        buttonPanel.Controls.Add(_clearLogsButton);
        buttonPanel.Controls.Add(_scrollToEndButton);

        _logBox.Dock = DockStyle.Fill;
        _logBox.Multiline = true;
        _logBox.ReadOnly = true;
        _logBox.ScrollBars = ScrollBars.Both;
        _logBox.WordWrap = false;
        _logBox.HideSelection = false;
        _logBox.Font = new Font("Consolas", 9F);
        _logBox.BackColor = Color.FromArgb(252, 254, 255);
        _logBox.MouseWheel += (_, _) => BeginInvoke((Action)DetectLogScrollPosition);
        _logBox.MouseUp += (_, _) => BeginInvoke((Action)DetectLogScrollPosition);
        _logBox.KeyUp += (_, e) =>
        {
            if (IsLogNavigationKey(e.KeyCode))
            {
                BeginInvoke((Action)DetectLogScrollPosition);
            }
        };
        SetTip(_logSearchBox, "Search visible log lines. Press Enter for next match and Shift+Enter for previous match.");
        SetTip(_logSearchPreviousButton, "Previous matching log line.");
        SetTip(_logSearchNextButton, "Next matching log line.");
        SetTip(_scrollToEndButton, "Scroll to the newest log line and keep following new logs.");
        SetTip(_clearLogsButton, "Clear the MyVpnClient log file.");
        UpdateLogSearchUi();
        UpdateLogFollowButton();

        toolbar.Controls.Add(searchPanel, 0, 0);
        toolbar.Controls.Add(buttonPanel, 1, 0);
        panel.Controls.Add(toolbar, 0, 0);
        panel.Controls.Add(_logBox, 0, 1);
        page.Controls.Add(panel);
        return page;
    }

    private FlowLayoutPanel BuildSearchPanel(
        TextBox searchBox,
        Button previousButton,
        Button nextButton,
        Label countLabel,
        EventHandler searchChanged,
        Action<int> moveSearch)
    {
        var searchPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
            Margin = Padding.Empty
        };
        var searchLabel = new Label
        {
            Text = "Search",
            AutoSize = false,
            Size = new Size(76, 30),
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(0, 0, 8, 0)
        };
        searchBox.Width = 260;
        searchBox.Height = 30;
        searchBox.Margin = new Padding(0, 0, 8, 0);
        searchBox.TextChanged += searchChanged;
        searchBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Enter)
            {
                return;
            }

            moveSearch(e.Shift ? -1 : 1);
            e.SuppressKeyPress = true;
        };
        ConfigureSearchArrowButton(previousButton, "\u25B2");
        previousButton.Margin = new Padding(0, 0, 4, 0);
        previousButton.Click += (_, _) => moveSearch(-1);
        ConfigureSearchArrowButton(nextButton, "\u25BC");
        nextButton.Margin = new Padding(0, 0, 8, 0);
        nextButton.Click += (_, _) => moveSearch(1);
        countLabel.Text = "0 / 0";
        countLabel.AutoSize = false;
        countLabel.Size = new Size(82, 30);
        countLabel.TextAlign = ContentAlignment.MiddleLeft;
        countLabel.Margin = Padding.Empty;
        searchPanel.Controls.AddRange([searchLabel, searchBox, previousButton, nextButton, countLabel]);
        return searchPanel;
    }

    private static void ConfigureSearchArrowButton(Button button, string text)
    {
        button.Text = text;
        button.AutoSize = false;
        button.Size = new Size(34, 30);
        button.Padding = Padding.Empty;
    }

    private static void ConfigureToolbarButton(Button button, string text)
    {
        button.Text = text;
        button.AutoSize = true;
        button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        button.MinimumSize = new Size(Math.Max(104, TextRenderer.MeasureText(text, button.Font).Width + 34), 30);
        button.Margin = new Padding(0, 0, 8, 0);
        button.Padding = new Padding(8, 0, 8, 0);
    }

    private TabPage MakeDiagnosticsPage()
    {
        var page = new TabPage("Diagnostics");
        page.BackColor = Color.FromArgb(248, 251, 254);
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3 };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 112));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var buttonPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 2,
            BackColor = Color.Transparent,
            Padding = new Padding(8, 8, 8, 6),
            Margin = Padding.Empty
        };
        for (var column = 0; column < 4; column++)
        {
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        }
        buttonPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        buttonPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        ConfigureDiagnosticButton(_preflightButton, "Preflight check");
        _preflightButton.Click += async (_, _) => await RunPreflightAsync();
        SetTip(_preflightButton, "Check config, credentials availability, helper files, adapter readiness, and DNS before connecting.");
        ConfigureDiagnosticButton(_sandboxCheckButton, "Offline sandbox");
        _sandboxCheckButton.Click += async (_, _) => await RunSandboxCheckAsync();
        SetTip(_sandboxCheckButton, "Run a no-network/no-adapter state model check for connection phases.");
        ConfigureDiagnosticButton(_diagnosticsButton, "Run diagnostics");
        _diagnosticsButton.Click += async (_, _) => await RunDiagnosticsAsync();
        SetTip(_diagnosticsButton, "Collect status, health, routes, logs, and a redacted diagnostics bundle.");
        ConfigureDiagnosticButton(_fullDiagnosticButton, "Full VPN test");
        _fullDiagnosticButton.Click += async (_, _) => await RunFullDiagnosticAsync();
        SetTip(_fullDiagnosticButton, "Run one elevated connect attempt, wait for MFA, verify the tunnel reaches VPN-ready state, collect route evidence, then disconnect.");
        ConfigureDiagnosticButton(_lifecycleProofButton, "Test lifecycle");
        _lifecycleProofButton.Click += async (_, _) => await RunLifecycleProofAsync();
        SetTip(_lifecycleProofButton, "Run a connect/disconnect ownership test to confirm MyVpnClient stops its tunnel cleanly.");
        ConfigureDiagnosticButton(_repairNetworkButton, "Set adapter DNS/metric");
        _repairNetworkButton.Click += (_, _) => RepairNetwork();
        SetTip(_repairNetworkButton, "Reapply VPN adapter DNS servers, adapter metric, and DNS cache flush without reconnecting. This does not test named hosts.");
        ConfigureDiagnosticButton(_resetNetworkButton, "Reset network");
        _resetNetworkButton.Click += async (_, _) => await ResetNetworkAsync();
        SetTip(_resetNetworkButton, "Remove tracked VPN routes and restore adapter DNS state after a stale or failed session.");
        buttonPanel.Controls.Add(_preflightButton, 0, 0);
        buttonPanel.Controls.Add(_sandboxCheckButton, 1, 0);
        buttonPanel.Controls.Add(_diagnosticsButton, 2, 0);
        buttonPanel.Controls.Add(_fullDiagnosticButton, 3, 0);
        buttonPanel.Controls.Add(_lifecycleProofButton, 0, 1);
        buttonPanel.Controls.Add(_repairNetworkButton, 1, 1);
        buttonPanel.Controls.Add(_resetNetworkButton, 2, 1);
        _diagnosticsBox.Dock = DockStyle.Fill;
        _diagnosticsBox.Multiline = true;
        _diagnosticsBox.ReadOnly = true;
        _diagnosticsBox.ScrollBars = ScrollBars.Both;
        _diagnosticsBox.Font = new Font("Consolas", 9F);
        _diagnosticsBox.BackColor = Color.FromArgb(252, 254, 255);
        panel.Controls.Add(buttonPanel, 0, 0);
        panel.Controls.Add(BuildFullDiagnosticChecklist(), 0, 1);
        panel.Controls.Add(_diagnosticsBox, 0, 2);
        page.Controls.Add(panel);
        return page;
    }

    private static void ConfigureDiagnosticButton(Button button, string text)
    {
        button.Text = text;
        button.Dock = DockStyle.Fill;
        button.AutoSize = false;
        button.MinimumSize = new Size(112, 32);
        button.Margin = new Padding(0, 0, 8, 8);
        button.Padding = new Padding(8, 0, 8, 0);
    }

    private Control BuildFullDiagnosticChecklist()
    {
        var container = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 2,
            BackColor = Color.Transparent,
            Padding = new Padding(8, 8, 8, 6)
        };
        container.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        container.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var title = new Label
        {
            Dock = DockStyle.Fill,
            Text = "Full VPN test checklist",
            Font = new Font(Font, FontStyle.Bold),
            ForeColor = Color.FromArgb(25, 45, 62),
            TextAlign = ContentAlignment.MiddleLeft
        };

        _fullDiagnosticChecklistPanel.Dock = DockStyle.Fill;
        _fullDiagnosticChecklistPanel.BackColor = Color.Transparent;
        _fullDiagnosticChecklistPanel.ColumnCount = 4;
        _fullDiagnosticChecklistPanel.RowCount = 2;
        _fullDiagnosticChecklistPanel.Margin = Padding.Empty;
        _fullDiagnosticChecklistPanel.Padding = Padding.Empty;
        _fullDiagnosticChecklistPanel.ColumnStyles.Clear();
        _fullDiagnosticChecklistPanel.RowStyles.Clear();
        for (var column = 0; column < 4; column++)
        {
            _fullDiagnosticChecklistPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        }
        _fullDiagnosticChecklistPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        _fullDiagnosticChecklistPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        AddFullDiagnosticCheck("helper", "Helper launched", "Elevated helper/task started and began writing trace events.", 0, 0);
        AddFullDiagnosticCheck("auth", "Fortinet MFA", "Login and FortiToken/MFA challenge completed.", 1, 0);
        AddFullDiagnosticCheck("tls", "TLS tunnel", "SSL VPN tunnel stream opened.", 2, 0);
        AddFullDiagnosticCheck("ppp", "PPP/IP", "PPP negotiation completed and VPN IPv4 address was assigned.", 3, 0);
        AddFullDiagnosticCheck("dns", "Adapter DNS", "VPN DNS settings were collected from the tunnel/config.", 0, 1);
        AddFullDiagnosticCheck("routes", "VPN routes", "VPN route table evidence was collected.", 1, 1);
        AddFullDiagnosticCheck("jira", "Host checks off", "MyVpnClient does not test named hosts during connect.", 2, 1);
        AddFullDiagnosticCheck("report", "Final report", "Diagnostic JSON was collected and summarized.", 3, 1);
        ResetFullDiagnosticChecklist();

        container.Controls.Add(title, 0, 0);
        container.Controls.Add(_fullDiagnosticChecklistPanel, 0, 1);
        return container;
    }

    private void AddFullDiagnosticCheck(string key, string text, string tooltip, int column, int row)
    {
        var box = new CheckBox
        {
            Dock = DockStyle.Fill,
            AutoCheck = false,
            ThreeState = true,
            FlatStyle = FlatStyle.Standard,
            Text = text,
            Tag = text,
            Margin = new Padding(2),
            Padding = new Padding(6, 0, 4, 0),
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Color.FromArgb(238, 242, 246)
        };
        SetTip(box, tooltip);
        _fullDiagnosticCheckBoxes[key] = box;
        _fullDiagnosticChecklistPanel.Controls.Add(box, column, row);
    }

    private void ResetFullDiagnosticChecklist()
    {
        foreach (var key in _fullDiagnosticCheckBoxes.Keys)
        {
            SetFullDiagnosticCheck(key, DiagnosticCheckState.Pending);
        }
    }

    private void UpdateFullDiagnosticChecklist(string text)
    {
        ResetFullDiagnosticChecklist();
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var lower = text.ToLowerInvariant();
        var finalPassed = lower.Contains("\"ok\": true") || lower.Contains("full vpn diagnostic passed");
        var finalFailed = lower.Contains("\"ok\": false") || lower.Contains("full vpn diagnostic failed") || lower.Contains("did not finish before timeout");

        if (ContainsAny(lower, "starting myvpnclient", "connect_start", "live progress:", "running full vpn test")) SetFullDiagnosticCheck("helper", DiagnosticCheckState.Running);
        if (ContainsAny(lower, "login started", "waiting for mfa", "received tokeninfo mfa challenge", "fortinet login started")) { SetFullDiagnosticCheck("helper", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("auth", DiagnosticCheckState.Running); }
        if (ContainsAny(lower, "auth result: authenticated", "\"status\": \"authenticated\"", "authenticated cookies")) { SetFullDiagnosticCheck("helper", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("auth", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("tls", DiagnosticCheckState.Running); }
        if (ContainsAny(lower, "opening tls tunnel", "tls_tunnel_open_start")) SetFullDiagnosticCheck("tls", DiagnosticCheckState.Running);
        if (ContainsAny(lower, "tls tunnel opened", "tls-tunnel-running")) { SetFullDiagnosticCheck("tls", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("ppp", DiagnosticCheckState.Running); }
        if (ContainsAny(lower, "ppp lcp", "ppp ipcp", "lcp is open", "ipcp")) SetFullDiagnosticCheck("ppp", DiagnosticCheckState.Running);
        if (ContainsAny(lower, "ppp-network-ready", "network-ready", "ppp negotiation complete", "vpn tunnel is up")) { SetFullDiagnosticCheck("ppp", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("dns", DiagnosticCheckState.Passed); SetFullDiagnosticCheck("routes", DiagnosticCheckState.Running); SetFullDiagnosticCheck("jira", DiagnosticCheckState.Passed); }
        if (ContainsAny(lower, "network_routes_tracked", "routes tracked")) SetFullDiagnosticCheck("routes", DiagnosticCheckState.Passed);
        if (ContainsAny(lower, "network_check_skipped", "host checks disabled", "host checks removed")) SetFullDiagnosticCheck("jira", DiagnosticCheckState.Passed);
        if (finalPassed) foreach (var key in _fullDiagnosticCheckBoxes.Keys) SetFullDiagnosticCheck(key, DiagnosticCheckState.Passed);

        if (ContainsAny(lower, "authentication failed", "login failed")) SetFullDiagnosticCheck("auth", DiagnosticCheckState.Failed);
        if (ContainsAny(lower, "tls tunnel open failed", "tunnel-open-failed")) SetFullDiagnosticCheck("tls", DiagnosticCheckState.Failed);
        if (ContainsAny(lower, "ppp negotiation timed out", "negotiation-timeout")) SetFullDiagnosticCheck("ppp", DiagnosticCheckState.Failed);
        if (finalFailed) SetFullDiagnosticCheck("report", DiagnosticCheckState.Failed);
        else if (ContainsAny(lower, "full vpn diagnostic report", "final report will appear", "collecting final diagnostic report")) SetFullDiagnosticCheck("report", finalPassed ? DiagnosticCheckState.Passed : DiagnosticCheckState.Running);
    }

    private static bool ContainsAny(string text, params string[] needles)
    {
        return needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private void SetFullDiagnosticCheck(string key, DiagnosticCheckState state)
    {
        if (!_fullDiagnosticCheckBoxes.TryGetValue(key, out var box)) return;
        var label = box.Tag as string ?? box.Text;
        box.Text = state switch
        {
            DiagnosticCheckState.Running => label + " - testing",
            DiagnosticCheckState.Passed => label + " - ok",
            DiagnosticCheckState.Failed => label + " - failed",
            _ => label
        };
        box.CheckState = state switch
        {
            DiagnosticCheckState.Running => CheckState.Indeterminate,
            DiagnosticCheckState.Passed => CheckState.Checked,
            _ => CheckState.Unchecked
        };
        box.BackColor = state switch
        {
            DiagnosticCheckState.Running => Color.FromArgb(255, 224, 128),
            DiagnosticCheckState.Passed => Color.FromArgb(220, 244, 226),
            DiagnosticCheckState.Failed => Color.FromArgb(255, 224, 224),
            _ => Color.FromArgb(238, 242, 246)
        };
        box.ForeColor = state switch
        {
            DiagnosticCheckState.Running => Color.FromArgb(92, 55, 0),
            DiagnosticCheckState.Passed => Color.FromArgb(20, 95, 45),
            DiagnosticCheckState.Failed => Color.FromArgb(150, 22, 22),
            _ => Color.FromArgb(52, 62, 72)
        };
    }

    private readonly record struct LogSearchMatch(int LineIndex, int Start, int Length);

    private enum TrayIconState
    {
        Unknown,
        Connected,
        Connecting,
        Disconnected
    }

    private enum DiagnosticCheckState
    {
        Pending,
        Running,
        Passed,
        Failed
    }

    private TabPage MakeTracePage()
    {
        var page = new TabPage("Session");
        page.BackColor = Color.FromArgb(248, 251, 254);

        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var toolbar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            BackColor = Color.Transparent,
            Padding = new Padding(8, 5, 8, 5)
        };
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var searchPanel = BuildSearchPanel(
            _sessionSearchBox,
            _sessionSearchPreviousButton,
            _sessionSearchNextButton,
            _sessionSearchCountLabel,
            (_, _) => RefreshSessionSearchMatches(selectFirst: true),
            MoveSessionSearch);

        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Transparent,
            Margin = Padding.Empty
        };
        ConfigureToolbarButton(_sessionScrollToEndButton, "Scroll to End");
        _sessionScrollToEndButton.Click += (_, _) => EnableSessionTailFollow();
        buttonPanel.Controls.Add(_sessionScrollToEndButton);

        _traceBox.Dock = DockStyle.Fill;
        _traceBox.Multiline = true;
        _traceBox.ReadOnly = true;
        _traceBox.ScrollBars = ScrollBars.Both;
        _traceBox.WordWrap = false;
        _traceBox.HideSelection = false;
        _traceBox.Font = new Font("Consolas", 9F);
        _traceBox.BackColor = Color.FromArgb(252, 254, 255);
        _traceBox.MouseWheel += (_, _) => BeginInvoke((Action)DetectSessionScrollPosition);
        _traceBox.MouseUp += (_, _) => BeginInvoke((Action)DetectSessionScrollPosition);
        _traceBox.KeyUp += (_, e) =>
        {
            if (IsLogNavigationKey(e.KeyCode))
            {
                BeginInvoke((Action)DetectSessionScrollPosition);
            }
        };

        SetTip(_sessionSearchBox, "Search visible session lines. Press Enter for next match and Shift+Enter for previous match.");
        SetTip(_sessionSearchPreviousButton, "Previous matching session line.");
        SetTip(_sessionSearchNextButton, "Next matching session line.");
        SetTip(_sessionScrollToEndButton, "Scroll to the newest session line and keep following new session output.");
        UpdateSessionSearchUi();
        UpdateSessionFollowButton();

        toolbar.Controls.Add(searchPanel, 0, 0);
        toolbar.Controls.Add(buttonPanel, 1, 0);
        panel.Controls.Add(toolbar, 0, 0);
        panel.Controls.Add(_traceBox, 0, 1);
        page.Controls.Add(panel);
        return page;
    }

    private static TabControl CreateStableTabs()
    {
        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            DrawMode = TabDrawMode.OwnerDrawFixed,
            SizeMode = TabSizeMode.Fixed,
            ItemSize = new Size(132, 30)
        };
        tabs.DrawItem += (_, e) =>
        {
            var selected = e.Index == tabs.SelectedIndex;
            var bounds = e.Bounds;
            var backColor = selected ? Color.FromArgb(248, 251, 254) : Color.FromArgb(235, 242, 248);
            using var background = new SolidBrush(backColor);
            e.Graphics.FillRectangle(background, bounds);
            using var border = new Pen(Color.FromArgb(196, 206, 216));
            e.Graphics.DrawRectangle(border, bounds.X, bounds.Y, bounds.Width - 1, bounds.Height - 1);
            var textColor = selected ? Color.Black : Color.FromArgb(36, 44, 52);
            TextRenderer.DrawText(
                e.Graphics,
                tabs.TabPages[e.Index].Text,
                tabs.Font,
                bounds,
                textColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        };
        return tabs;
    }

    private NotifyIcon BuildTrayIcon()
    {
        var icon = new NotifyIcon
        {
            Text = $"MyVpnClient {AppVersion}",
            Icon = _disconnectedTrayIcon,
            Visible = true,
            ContextMenuStrip = _trayMenu
        };

        _trayMenu.ShowImageMargin = false;
        _trayMenu.ShowCheckMargin = false;
        _trayMenu.Padding = new Padding(2);
        _trayOpenItem.Click += (_, _) => ShowFromTray();
        _trayAboutItem.Click += (_, _) => ShowAboutDialog();
        _trayConnectItem.Click += (_, _) => Connect();
        _trayDisconnectItem.Click += async (_, _) => await DisconnectAsync();
        _trayShutdownItem.Click += async (_, _) => await ShutdownAsync();
        _trayMenu.Items.Add(_trayOpenItem);
        _trayMenu.Items.Add(_trayAboutItem);
        _trayMenu.Items.Add(new ToolStripSeparator());
        _trayMenu.Items.Add(_trayConnectItem);
        _trayMenu.Items.Add(_trayDisconnectItem);
        _trayMenu.Items.Add(new ToolStripSeparator());
        _trayMenu.Items.Add(_trayShutdownItem);
        _trayMenu.Opening += (_, _) => UpdateTrayMenuItems();
        _trayMenu.Opened += (_, _) => OffsetTrayMenu();
        icon.DoubleClick += (_, _) => ShowFromTray();
        icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowTrayMenu();
            }
        };
        return icon;
    }

    private void ShowTrayMenu()
    {
        UpdateTrayMenuItems();
        var position = Cursor.Position;
        _trayMenu.Show(position.X - 18, position.Y - Math.Max(_trayMenu.Height + 24, 32));
    }

    private void OffsetTrayMenu()
    {
        _trayMenu.Location = new Point(_trayMenu.Left - 18, _trayMenu.Top - 18);
    }

    private void UpdateTrayMenuItems()
    {
        var connectedOrConnecting = _currentState is VpnConnectionState.Connected or VpnConnectionState.Connecting;
        var profileName = CurrentTrayProfileName();
        _trayConnectItem.Text = $"Connect \"{profileName}\"";
        _trayDisconnectItem.Text = $"Disconnect \"{profileName}\"";
        _trayConnectItem.Visible = !connectedOrConnecting;
        _trayDisconnectItem.Visible = connectedOrConnecting;
    }

    private string CurrentTrayProfileName()
    {
        var profile = SelectedProfile();
        return CompactTrayProfileName(profile is null ? "VPN" : ProfileBaseName(profile));
    }

    private static string CompactTrayProfileName(string name)
    {
        var compact = name.Trim();
        var parenthesis = compact.IndexOf(" (", StringComparison.Ordinal);
        if (parenthesis > 0)
        {
            compact = compact[..parenthesis].Trim();
        }

        return compact.Length <= 24 ? compact : compact[..21] + "...";
    }

    private void SetTrayIcon(TrayIconState state)
    {
        if (_trayIconState == state)
        {
            return;
        }

        _trayIcon.Icon = state switch
        {
            TrayIconState.Connected => _connectedTrayIcon,
            TrayIconState.Connecting => _connectingTrayIcon,
            _ => _disconnectedTrayIcon
        };
        _trayIconState = state;
    }

    private static Icon BuildIcon(Color color)
    {
        using var bitmap = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bitmap);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        using var bg = new LinearGradientBrush(
            new Rectangle(2, 2, 28, 28),
            ControlPaint.Light(color, 0.18F),
            ControlPaint.Dark(color, 0.12F),
            LinearGradientMode.ForwardDiagonal);
        using var tile = RoundedRect(new Rectangle(2, 2, 28, 28), 8);
        g.FillPath(bg, tile);
        using var border = new Pen(Color.FromArgb(75, Color.White), 1F);
        g.DrawPath(border, tile);

        using var shield = new SolidBrush(Color.FromArgb(245, Color.White));
        var points = new[]
        {
            new PointF(16F, 6F),
            new PointF(24F, 9F),
            new PointF(22F, 20F),
            new PointF(16F, 27F),
            new PointF(10F, 20F),
            new PointF(8F, 9F)
        };
        g.FillPolygon(shield, points);

        using var lockBrush = new SolidBrush(ControlPaint.Dark(color, 0.05F));
        g.FillEllipse(lockBrush, 13F, 13F, 6F, 6F);
        g.FillRectangle(lockBrush, 14.4F, 17F, 3.2F, 6F);
        var hIcon = bitmap.GetHicon();
        try
        {
            using var icon = Icon.FromHandle(hIcon);
            return (Icon)icon.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    private static GraphicsPath RoundedRect(Rectangle bounds, int radius)
    {
        var path = new GraphicsPath();
        var diameter = radius * 2;
        path.AddArc(bounds.X, bounds.Y, diameter, diameter, 180, 90);
        path.AddArc(bounds.Right - diameter, bounds.Y, diameter, diameter, 270, 90);
        path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(bounds.X, bounds.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }

    private static Icon LoadApplicationIcon()
    {
        return Icon.ExtractAssociatedIcon(Application.ExecutablePath)
            ?? SystemIcons.Application;
    }

    private void LoadProfiles(string? preferredProfileName = null)
    {
        _loadingProfiles = true;
        try
        {
            var selectedName = string.IsNullOrWhiteSpace(preferredProfileName) ? SelectedProfile()?.Name : preferredProfileName;
            _profiles = _profileStore.Load();
            _profileBox.Items.Clear();
            foreach (var profile in _profiles)
            {
                _profileBox.Items.Add(ProfileDisplayName(profile));
            }

            if (_profiles.Count == 0)
            {
                return;
            }

            var selectedIndex = string.IsNullOrWhiteSpace(selectedName)
                ? 0
                : Math.Max(0, _profiles.FindIndex(profile => profile.Name == selectedName));
            _profileBox.SelectedIndex = selectedIndex;
        }
        finally
        {
            _loadingProfiles = false;
        }
    }

    private static string ProfileDisplayName(VpnProfile profile)
    {
        return ProfileBaseName(profile);
    }

    private static string ProfileBaseName(VpnProfile profile)
    {
        return !string.IsNullOrWhiteSpace(profile.Name)
            ? profile.Name
            : string.IsNullOrWhiteSpace(profile.Server) ? "VPN profile" : profile.Server;
    }

    private VpnProfile? SelectedProfile()
    {
        var index = _profileBox.SelectedIndex;
        return index >= 0 && index < _profiles.Count ? _profiles[index] : null;
    }

    private void WriteSelectedProfileToConfig()
    {
        if (_loadingProfiles)
        {
            return;
        }

        var profile = SelectedProfile();
        if (profile is null)
        {
            return;
        }

        var password = profile.Password;
        profile.Password = "";
        profile.Save(_configPath);
        profile.Password = password;
    }

    private void SaveSelectedProfileFromConfig()
    {
        var index = _profileBox.SelectedIndex;
        if (index < 0 || index >= _profiles.Count)
        {
            return;
        }

        var updated = VpnProfile.Load(_configPath);
        if (string.IsNullOrWhiteSpace(updated.Name))
        {
            updated.Name = ProfileBaseName(_profiles[index]);
        }

        _profiles[index] = updated;
        _profileStore.Save(_profiles);
        LoadProfiles();
    }


    private static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void OpenSettings()
    {
        WriteSelectedProfileToConfig();
        using var dialog = new SettingsForm(_configPath, _secretStore, _appDirectory, _settingsPath);
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            LoadProfiles(dialog.SelectedProfileName);
            WriteSelectedProfileToConfig();
            ReloadAppSettings();
            RestartApiServer();
            AppendLog("Settings saved.");
        }
    }

    private void ShowAboutDialog()
    {
        MessageBox.Show(
            this,
            $"MyVpnClient {AppVersion}\n{OpenConnectVersionText()}\n\nFortinet/OpenConnect VPN client.\nProfile: {CurrentTrayProfileName()}",
            "About MyVpnClient",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private string OpenConnectVersionText()
    {
        var openConnectPath = Path.Combine(_installDirectory, "OpenConnect", "openconnect.exe");
        if (!File.Exists(openConnectPath))
        {
            return "OpenConnect: not bundled";
        }

        try
        {
            using var process = new Process
            {
                StartInfo =
                {
                    FileName = openConnectPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.StartInfo.ArgumentList.Add("--version");
            process.Start();
            if (!process.WaitForExit(1500))
            {
                process.Kill(entireProcessTree: true);
                return "OpenConnect: version check timed out";
            }

            var output = process.StandardOutput.ReadToEnd() + Environment.NewLine + process.StandardError.ReadToEnd();
            var line = output
                .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(value => value.Contains("OpenConnect", StringComparison.OrdinalIgnoreCase))
                ?? output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(line))
            {
                return "OpenConnect: version unavailable";
            }

            if (line.StartsWith("OpenConnect ", StringComparison.OrdinalIgnoreCase))
            {
                line = line["OpenConnect ".Length..].Trim();
            }

            return $"OpenConnect: {line}";
        }
        catch (Exception ex)
        {
            return $"OpenConnect: version unavailable ({ex.Message})";
        }
    }

    private async void Connect()
    {
        try
        {
            _userDisconnectRequested = false;
            _mfaGaugeState = DiagnosticCheckState.Pending;
            ShowConnectingFeedback();
            WriteSelectedProfileToConfig();
            AppendLog("Connect requested. Running preflight check...");
            _statusDetailLabel.Text = "Running preflight check...";
            var preflight = await _controller.RunPreflightAsync();
            if (PreflightBlocksConnect(preflight.CombinedOutput, out var preflightMessage))
            {
                _connectButton.Text = "Connect";
                _connectButton.Enabled = true;
                _connectButton.Visible = true;
                _disconnectButton.Visible = false;
                _statusLabel.Text = "Preflight failed";
                ClearUptimeLabel();
                _statusLabel.ForeColor = Color.DarkOrange;
                _statusDetailLabel.Text = ShortenStatusDetail(preflightMessage);
                _diagnosticsBox.Text = "== Preflight check ==" + Environment.NewLine + preflight.CombinedOutput.Trim();
                MessageBox.Show(this, preflightMessage, "Connect preflight failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _statusDetailLabel.Text = "Starting VPN...";
            AppendLog("Preflight passed. Starting VPN from MyVpnClient...");
            _controller.WriteOwnerPid();
            _controller.ConnectElevated();
            AppendLog("VPN start requested. Approve FortiToken push if prompted.");
        }
        catch (Exception ex)
        {
            _connectLaunchInProgress = false;
            _connectButton.Text = "Connect";
            _connectButton.Enabled = true;
            _connectButton.Visible = true;
            _disconnectButton.Visible = false;
            _statusLabel.Text = "Connect failed";
            ClearUptimeLabel();
            _statusLabel.ForeColor = Color.Firebrick;
            _statusDetailLabel.Text = ShortenStatusDetail(ex.Message);
            AppendLog("Connect failed: " + ex.Message);
            MessageBox.Show(this, ex.Message, "Connect failed");
        }
    }

    private async Task DisconnectAsync()
    {
        _userDisconnectRequested = true;
        _wasEverConnected = false;
        _mfaGaugeState = DiagnosticCheckState.Pending;
        var result = await _controller.DisconnectAsync();
        AppendLog(result.CombinedOutput);
        await RefreshStatusAsync();
    }

    private async Task ShutdownAsync()
    {
        _allowExit = true;
        _connectButton.Enabled = false;
        _disconnectButton.Enabled = false;
        _trayConnectItem.Enabled = false;
        _trayDisconnectItem.Enabled = false;
        _trayShutdownItem.Enabled = false;
        _statusLabel.Text = "Shutting down";
        ClearUptimeLabel();
        _statusLabel.ForeColor = Color.DarkOrange;
        _statusDetailLabel.Text = "Disconnecting VPN before exit.";
        AppendLog("Shutdown requested. Disconnecting VPN before closing MyVpnClient.");

        try
        {
            await DisconnectAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Disconnect before shutdown failed: " + ex.Message);
        }
        finally
        {
            _trayIcon.Visible = false;
            Application.Exit();
        }
    }


    private void SelectProfileForApi(string? profileName)
    {
        if (string.IsNullOrWhiteSpace(profileName))
        {
            return;
        }

        for (var index = 0; index < _profileBox.Items.Count; index++)
        {
            var item = _profileBox.Items[index]?.ToString() ?? "";
            if (item.Equals(profileName, StringComparison.OrdinalIgnoreCase))
            {
                _profileBox.SelectedIndex = index;
                WriteSelectedProfileToConfig();
                return;
            }
        }
    }

    private async Task<ApiStatus> GetApiStatusAsync()
    {
        var snapshot = await _controller.GetStatusSnapshotAsync();
        return new ApiStatus(
            _appSettings.ApiEnabled,
            snapshot.State.ToString(),
            snapshot.Detail,
            _profileBox.SelectedItem?.ToString(),
            _appSettings.ApiPort,
            _appSettings.ApiBindAddress,
            snapshot.Phase,
            snapshot.UserMessage,
            snapshot.SuggestedAction,
            snapshot.Retryable);
    }

    private IReadOnlyList<ApiProfile> GetApiProfiles()
    {
        var selected = _profileBox.SelectedItem?.ToString() ?? "";
        return _profiles
            .Select(profile => new ApiProfile(profile.Name, profile.Server, profile.Protocol, profile.Backend, profile.Name.Equals(selected, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }
    private Task<string> ConnectFromApiAsync(string? profileName)
    {
        return RunOnUiThreadAsync(() =>
        {
            SelectProfileForApi(profileName);
            Connect();
            return Task.FromResult("Connect requested.");
        });
    }

    private Task<string> DisconnectFromApiAsync()
    {
        return RunOnUiThreadAsync(async () =>
        {
            await DisconnectAsync();
            return "Disconnect requested.";
        });
    }

    private Task<string> ResetNetworkFromApiAsync()
    {
        return RunOnUiThreadAsync(async () =>
        {
            await ResetNetworkAsync();
            return "Reset network requested.";
        });
    }

    private async Task RefreshStatusAsync()
    {
        try
        {
            var snapshot = await _controller.GetStatusSnapshotAsync();
            _currentState = snapshot.State;
            var connected = snapshot.State == VpnConnectionState.Connected;
            var connecting = snapshot.State == VpnConnectionState.Connecting;
            var failed = snapshot.Phase.StartsWith("Failed", StringComparison.OrdinalIgnoreCase)
                || snapshot.Phase.Equals("AuthFailed", StringComparison.OrdinalIgnoreCase);
            TrackSessionUptime(snapshot, connected);
            if (connected)
            {
                _wasEverConnected = true;
            }
            // Once connected, keep showing Connected until user disconnects or terminal failure
            var terminalFailure = failed || snapshot.State == VpnConnectionState.Disconnected && !_wasEverConnected;
            if (_wasEverConnected && !_userDisconnectRequested && !terminalFailure && !connected)
            {
                // Treat transient non-Connected, non-Disconnected states as still Connected
                connected = !snapshot.Phase.Equals("AuthFailed", StringComparison.OrdinalIgnoreCase)
                    && snapshot.State != VpnConnectionState.Disconnected;
                if (!connected && snapshot.State == VpnConnectionState.Disconnected && !failed)
                {
                    // Tunnel exited cleanly without user request — treat as disconnected
                    _wasEverConnected = false;
                }
            }
            var launchGraceActive = _connectLaunchInProgress
                && !connected
                && !connecting
                && !failed
                && DateTime.Now - _connectLaunchStartedAt < TimeSpan.FromSeconds(25);
            if (_connectLaunchInProgress && (connected || connecting || failed || !launchGraceActive))
            {
                _connectLaunchInProgress = false;
            }
            if (!_connectLaunchInProgress)
            {
                _connectButton.Text = "Connect";
                _connectButton.Enabled = true;
            }
            var statusText = _connectLaunchInProgress || connecting
                ? "Connecting"
                : connected
                    ? "Connected"
                    : "Disconnected";
            SetLabelText(_statusLabel, statusText);
            UpdateUptimeLabel(connected, snapshot.ConnectedAt);
            _statusLabel.ForeColor = connected
                ? Color.ForestGreen
                : (_connectLaunchInProgress || connecting) ? Color.DarkOrange : Color.Firebrick;
            _connectButton.Visible = !connected && !connecting;
            _disconnectButton.Visible = connected || connecting || _connectLaunchInProgress;
            if (_connectLaunchInProgress && !connected && !connecting)
            {
                _connectButton.Visible = true;
                _connectButton.Enabled = false;
                _disconnectButton.Visible = false;
            }
            UpdateTrayMenuItems();
            _trayIcon.Text = $"MyVpnClient {AppVersion} - {_statusLabel.Text.ToLowerInvariant()}";
            SetTrayIcon(connected
                ? TrayIconState.Connected
                : (_connectLaunchInProgress || connecting) ? TrayIconState.Connecting : TrayIconState.Disconnected);
            SetLabelText(_statusDetailLabel, ShortenStatusDetail(FormatStatusDetail(snapshot)));
            UpdateConnectionGauges(snapshot);
            if (_mainTabs?.SelectedTab?.Text == "Logs")
            {
                RefreshLogBox(scrollToBottom: _logFollowTail);
            }
            RefreshSessionBox(scrollToBottom: _sessionFollowTail);
        }
        catch (Exception ex)
        {
            _statusLabel.Text = "Status error";
            ClearUptimeLabel();
            _statusDetailLabel.Text = ex.Message;
            _statusLabel.ForeColor = Color.DarkOrange;
            AppendLog(ex.Message);
            UpdateConnectionGauges(null);
        }
    }

    private void TrackSessionUptime(VpnStatusSnapshot snapshot, bool connected)
    {
        if (connected)
        {
            _connectedSessionStartedAt ??= snapshot.ConnectedAt ?? DateTimeOffset.Now;
            return;
        }

        if (_connectedSessionStartedAt is not { } startedAt || snapshot.State != VpnConnectionState.Disconnected)
        {
            return;
        }

        var duration = DateTimeOffset.Now - startedAt;
        AppendLog($"VPN session ended; connected uptime was {FormatConnectionDuration(duration)}.");
        _connectedSessionStartedAt = null;
    }

    private static string ShortenStatusDetail(string detail)
    {
        if (string.IsNullOrWhiteSpace(detail))
        {
            return "";
        }

        var firstLine = detail.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line => !string.IsNullOrWhiteSpace(line) && line.Trim() is not "{" and not "}" and not "[]")
            ?? detail.Trim();
        return firstLine.Length <= 140 ? firstLine : firstLine[..137] + "...";
    }

    private static void SetLabelText(Label label, string text)
    {
        if (!string.Equals(label.Text, text, StringComparison.Ordinal))
        {
            label.Text = text;
        }
    }
    private void UpdateUptimeLabel(bool connected, DateTimeOffset? connectedAt)
    {
        if (!connected || connectedAt is not { } startedAt)
        {
            ClearUptimeLabel();
            return;
        }

        SetLabelText(_uptimeLabel, FormatConnectionDuration(DateTimeOffset.Now - startedAt));
        _uptimeLabel.ForeColor = Color.ForestGreen;
    }

    private void ClearUptimeLabel()
    {
        if (_uptimeLabel.Text.Length > 0)
        {
            _uptimeLabel.Text = "";
        }
    }

    private static string FormatConnectionDuration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            duration = TimeSpan.Zero;
        }

        return duration.TotalDays >= 1
            ? $"{(int)duration.TotalDays}d {duration.Hours:00}:{duration.Minutes:00}:{duration.Seconds:00}"
            : duration.ToString(@"hh\:mm\:ss");
    }

    private static string FormatStatusDetail(VpnStatusSnapshot snapshot)
    {
        var pieces = new List<string>();
        if (!string.IsNullOrWhiteSpace(snapshot.Phase))
        {
            pieces.Add(snapshot.Phase);
        }
        if (!string.IsNullOrWhiteSpace(snapshot.UserMessage))
        {
            pieces.Add(snapshot.UserMessage);
        }
        else if (!string.IsNullOrWhiteSpace(snapshot.Detail))
        {
            pieces.Add(snapshot.Detail);
        }
        if (!string.IsNullOrWhiteSpace(snapshot.SuggestedAction))
        {
            pieces.Add(snapshot.SuggestedAction);
        }
        return string.Join(" | ", pieces.Where(piece => !string.IsNullOrWhiteSpace(piece) && piece.Trim() is not "{" and not "}" and not "[]"));
    }

    private static bool LooksRetryable(string detail)
    {
        if (string.IsNullOrWhiteSpace(detail))
        {
            return true;
        }

        return detail.Contains("MFA", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("auth", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("failed", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("timeout", StringComparison.OrdinalIgnoreCase);
    }

    private void ShowConnectingFeedback()
    {
        _statusLabel.Text = "Connecting";
        ClearUptimeLabel();
        _statusLabel.ForeColor = Color.DarkOrange;
        _statusDetailLabel.Text = "Starting tunnel...";
        _connectLaunchInProgress = true;
        _connectLaunchStartedAt = DateTime.Now;
        _connectLaunchProgress = (_connectLaunchProgress + 1) % 4;
        _connectButton.Text = "Connecting" + new string('.', _connectLaunchProgress);
        _connectButton.Enabled = false;
        _connectButton.Visible = true;
        _disconnectButton.Visible = false;
        UpdateConnectionGauges(new VpnStatusSnapshot(VpnConnectionState.Connecting, "Starting tunnel..."));
    }

    private void ClearLogs()
    {
        _controller.ClearLog();
        _logBox.Clear();
        _logSearchMatches.Clear();
        _logSearchIndex = -1;
        _logFollowTail = true;
        UpdateLogSearchUi();
        UpdateLogFollowButton();
        _statusDetailLabel.Text = "";
    }

    private void RefreshLogBox(bool scrollToBottom, bool detectManualScroll = true)
    {
        if (detectManualScroll)
        {
            DetectLogScrollPosition();
        }

        var firstVisibleLine = GetFirstVisibleLine(_logBox);
        var selectionStart = _logBox.SelectionStart;
        var selectionLength = _logBox.SelectionLength;
        var preserveSelection = selectionLength > 0 && string.IsNullOrWhiteSpace(_logSearchBox.Text);
        var text = _controller.ReadLogTail(220);
        if (string.Equals(_logBox.Text, text, StringComparison.Ordinal))
        {
            RefreshLogSearchMatches(selectFirst: false);
            UpdateLogFollowButton();
            return;
        }

        _logBox.Text = text;
        RefreshLogSearchMatches(selectFirst: false);
        if (preserveSelection)
        {
            BeginInvoke((Action)(() => RestoreTextSelection(_logBox, selectionStart, selectionLength)));
            return;
        }

        if (scrollToBottom && _logFollowTail)
        {
            BeginInvoke((Action)ScrollLogToEnd);
            return;
        }

        BeginInvoke((Action)(() => RestoreLogFirstVisibleLine(firstVisibleLine)));
    }

    private void EnableLogTailFollow()
    {
        _logFollowTail = true;
        UpdateLogFollowButton();
        ScrollLogToEnd();
    }

    private void ScrollLogToEnd()
    {
        if (!_logBox.IsHandleCreated)
        {
            return;
        }

        _logBox.SelectionStart = _logBox.TextLength;
        _logBox.SelectionLength = 0;
        _logBox.ScrollToCaret();
        UpdateLogFollowButton();
    }

    private void RestoreLogFirstVisibleLine(int firstVisibleLine)
    {
        RestoreFirstVisibleLine(_logBox, firstVisibleLine);
    }

    private void RefreshSessionBox(bool scrollToBottom, bool detectManualScroll = true)
    {
        if (detectManualScroll)
        {
            DetectSessionScrollPosition();
        }

        var firstVisibleLine = GetFirstVisibleLine(_traceBox);
        var selectionStart = _traceBox.SelectionStart;
        var selectionLength = _traceBox.SelectionLength;
        var preserveSelection = selectionLength > 0 && string.IsNullOrWhiteSpace(_sessionSearchBox.Text);
        var text = _controller.ReadSessionTail(160);
        if (string.Equals(_traceBox.Text, text, StringComparison.Ordinal))
        {
            RefreshSessionSearchMatches(selectFirst: false);
            UpdateSessionFollowButton();
            return;
        }

        _traceBox.Text = text;
        RefreshSessionSearchMatches(selectFirst: false);
        if (preserveSelection)
        {
            BeginInvoke((Action)(() => RestoreTextSelection(_traceBox, selectionStart, selectionLength)));
            return;
        }

        if (scrollToBottom && _sessionFollowTail)
        {
            BeginInvoke((Action)ScrollSessionToEnd);
            return;
        }

        BeginInvoke((Action)(() => RestoreFirstVisibleLine(_traceBox, firstVisibleLine)));
    }

    private void EnableSessionTailFollow()
    {
        _sessionFollowTail = true;
        UpdateSessionFollowButton();
        ScrollSessionToEnd();
    }

    private void ScrollSessionToEnd()
    {
        if (!_traceBox.IsHandleCreated)
        {
            return;
        }

        _traceBox.SelectionStart = _traceBox.TextLength;
        _traceBox.SelectionLength = 0;
        _traceBox.ScrollToCaret();
        UpdateSessionFollowButton();
    }

    private static void RestoreTextSelection(TextBox textBox, int selectionStart, int selectionLength)
    {
        if (!textBox.IsHandleCreated)
        {
            return;
        }

        var start = Math.Clamp(selectionStart, 0, textBox.TextLength);
        var length = Math.Clamp(selectionLength, 0, Math.Max(0, textBox.TextLength - start));
        textBox.SelectionStart = start;
        textBox.SelectionLength = length;
    }

    private void RestoreFirstVisibleLine(TextBox textBox, int firstVisibleLine)
    {
        if (!textBox.IsHandleCreated || textBox.TextLength == 0)
        {
            return;
        }

        var maxLine = Math.Max(0, textBox.Lines.Length - 1);
        var targetLine = Math.Clamp(firstVisibleLine, 0, maxLine);
        textBox.SelectionStart = 0;
        textBox.SelectionLength = 0;
        SendMessage(textBox.Handle, EmLineScroll, IntPtr.Zero, (IntPtr)targetLine);
    }

    private int GetFirstVisibleLine(TextBox textBox)
    {
        if (!textBox.IsHandleCreated || textBox.TextLength == 0)
        {
            return 0;
        }

        return (int)SendMessage(textBox.Handle, EmGetFirstVisibleLine, IntPtr.Zero, IntPtr.Zero);
    }

    private void DetectLogScrollPosition()
    {
        if (!_logFollowTail || _mainTabs?.SelectedTab?.Text != "Logs" || _logBox.TextLength == 0)
        {
            return;
        }

        if (IsLogScrolledNearBottom())
        {
            return;
        }

        _logFollowTail = false;
        UpdateLogFollowButton();
    }

    private bool IsLogScrolledNearBottom()
    {
        if (!_logBox.IsHandleCreated || _logBox.TextLength == 0)
        {
            return true;
        }

        var lineCount = _logBox.Lines.Length;
        var visibleLines = Math.Max(1, _logBox.ClientSize.Height / Math.Max(1, _logBox.Font.Height));
        var firstVisibleLine = GetFirstVisibleLine(_logBox);
        return firstVisibleLine + visibleLines >= Math.Max(0, lineCount - 2);
    }

    private void DetectSessionScrollPosition()
    {
        if (!_sessionFollowTail || _mainTabs?.SelectedTab?.Text != "Session" || _traceBox.TextLength == 0)
        {
            return;
        }

        if (IsSessionScrolledNearBottom())
        {
            return;
        }

        _sessionFollowTail = false;
        UpdateSessionFollowButton();
    }

    private bool IsSessionScrolledNearBottom()
    {
        if (!_traceBox.IsHandleCreated || _traceBox.TextLength == 0)
        {
            return true;
        }

        var lineCount = _traceBox.Lines.Length;
        var visibleLines = Math.Max(1, _traceBox.ClientSize.Height / Math.Max(1, _traceBox.Font.Height));
        var firstVisibleLine = GetFirstVisibleLine(_traceBox);
        return firstVisibleLine + visibleLines >= Math.Max(0, lineCount - 2);
    }

    private static bool IsLogNavigationKey(Keys keyCode)
    {
        return keyCode is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End;
    }

    private void UpdateLogFollowButton()
    {
        _scrollToEndButton.Text = "Scroll to End";
        _scrollToEndButton.BackColor = _logFollowTail ? Color.FromArgb(220, 244, 226) : SystemColors.Control;
        _scrollToEndButton.ForeColor = _logFollowTail ? Color.FromArgb(20, 95, 45) : SystemColors.ControlText;
    }

    private void UpdateSessionFollowButton()
    {
        _sessionScrollToEndButton.Text = "Scroll to End";
        _sessionScrollToEndButton.BackColor = _sessionFollowTail ? Color.FromArgb(220, 244, 226) : SystemColors.Control;
        _sessionScrollToEndButton.ForeColor = _sessionFollowTail ? Color.FromArgb(20, 95, 45) : SystemColors.ControlText;
    }

    private void RefreshLogSearchMatches(bool selectFirst)
    {
        _logSearchMatches.Clear();
        var query = _logSearchBox.Text;
        if (string.IsNullOrWhiteSpace(query))
        {
            _logSearchIndex = -1;
            UpdateLogSearchUi();
            return;
        }

        var text = _logBox.Text;
        var lineStart = 0;
        var lineIndex = 0;
        while (lineStart <= text.Length)
        {
            var lineEnd = text.IndexOf('\n', lineStart);
            if (lineEnd < 0)
            {
                lineEnd = text.Length;
            }

            var searchEnd = lineEnd > lineStart && text[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
            var lineLength = Math.Max(0, searchEnd - lineStart);
            if (lineLength > 0)
            {
                var matchStart = text.IndexOf(query, lineStart, lineLength, StringComparison.OrdinalIgnoreCase);
                if (matchStart >= 0)
                {
                    _logSearchMatches.Add(new LogSearchMatch(lineIndex, matchStart, query.Length));
                }
            }

            if (lineEnd == text.Length)
            {
                break;
            }

            lineStart = lineEnd + 1;
            lineIndex++;
        }

        if (_logSearchMatches.Count == 0)
        {
            _logSearchIndex = -1;
            UpdateLogSearchUi();
            return;
        }

        if (selectFirst || _logSearchIndex < 0)
        {
            _logSearchIndex = 0;
            SelectLogSearchMatch(focusLogBox: false);
            return;
        }

        _logSearchIndex = Math.Min(_logSearchIndex, _logSearchMatches.Count - 1);
        UpdateLogSearchUi();
    }

    private void MoveLogSearch(int direction)
    {
        if (_logSearchMatches.Count == 0)
        {
            RefreshLogSearchMatches(selectFirst: true);
            if (_logSearchMatches.Count == 0)
            {
                return;
            }
        }

        var count = _logSearchMatches.Count;
        _logSearchIndex = _logSearchIndex < 0
            ? 0
            : (_logSearchIndex + direction + count) % count;
        SelectLogSearchMatch(focusLogBox: false);
    }

    private void SelectLogSearchMatch(bool focusLogBox)
    {
        if (_logSearchIndex < 0 || _logSearchIndex >= _logSearchMatches.Count)
        {
            UpdateLogSearchUi();
            return;
        }

        var match = _logSearchMatches[_logSearchIndex];
        _logFollowTail = false;
        UpdateLogFollowButton();
        _logBox.SelectionStart = Math.Min(match.Start, _logBox.TextLength);
        _logBox.SelectionLength = Math.Min(match.Length, Math.Max(0, _logBox.TextLength - _logBox.SelectionStart));
        _logBox.ScrollToCaret();
        UpdateLogSearchUi();
        if (focusLogBox && _logBox.CanFocus)
        {
            _logBox.Focus();
        }
        else if (_logSearchBox.CanFocus)
        {
            _logSearchBox.Focus();
        }
    }

    private void UpdateLogSearchUi()
    {
        var total = _logSearchMatches.Count;
        var current = _logSearchIndex >= 0 && total > 0 ? _logSearchIndex + 1 : 0;
        _logSearchCountLabel.Text = $"{current} / {total}";
        _logSearchPreviousButton.Enabled = total > 0;
        _logSearchNextButton.Enabled = total > 0;
    }

    private void RefreshSessionSearchMatches(bool selectFirst)
    {
        _sessionSearchMatches.Clear();
        var query = _sessionSearchBox.Text;
        if (string.IsNullOrWhiteSpace(query))
        {
            _sessionSearchIndex = -1;
            UpdateSessionSearchUi();
            return;
        }

        var text = _traceBox.Text;
        var lineStart = 0;
        var lineIndex = 0;
        while (lineStart <= text.Length)
        {
            var lineEnd = text.IndexOf('\n', lineStart);
            if (lineEnd < 0)
            {
                lineEnd = text.Length;
            }

            var searchEnd = lineEnd > lineStart && text[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
            var lineLength = Math.Max(0, searchEnd - lineStart);
            if (lineLength > 0)
            {
                var matchStart = text.IndexOf(query, lineStart, lineLength, StringComparison.OrdinalIgnoreCase);
                if (matchStart >= 0)
                {
                    _sessionSearchMatches.Add(new LogSearchMatch(lineIndex, matchStart, query.Length));
                }
            }

            if (lineEnd == text.Length)
            {
                break;
            }

            lineStart = lineEnd + 1;
            lineIndex++;
        }

        if (_sessionSearchMatches.Count == 0)
        {
            _sessionSearchIndex = -1;
            UpdateSessionSearchUi();
            return;
        }

        if (selectFirst || _sessionSearchIndex < 0)
        {
            _sessionSearchIndex = 0;
            SelectSessionSearchMatch(focusTraceBox: false);
            return;
        }

        _sessionSearchIndex = Math.Min(_sessionSearchIndex, _sessionSearchMatches.Count - 1);
        UpdateSessionSearchUi();
    }

    private void MoveSessionSearch(int direction)
    {
        if (_sessionSearchMatches.Count == 0)
        {
            RefreshSessionSearchMatches(selectFirst: true);
            if (_sessionSearchMatches.Count == 0)
            {
                return;
            }
        }

        var count = _sessionSearchMatches.Count;
        _sessionSearchIndex = _sessionSearchIndex < 0
            ? 0
            : (_sessionSearchIndex + direction + count) % count;
        SelectSessionSearchMatch(focusTraceBox: false);
    }

    private void SelectSessionSearchMatch(bool focusTraceBox)
    {
        if (_sessionSearchIndex < 0 || _sessionSearchIndex >= _sessionSearchMatches.Count)
        {
            UpdateSessionSearchUi();
            return;
        }

        var match = _sessionSearchMatches[_sessionSearchIndex];
        _traceBox.SelectionStart = Math.Min(match.Start, _traceBox.TextLength);
        _traceBox.SelectionLength = Math.Min(match.Length, Math.Max(0, _traceBox.TextLength - _traceBox.SelectionStart));
        _traceBox.ScrollToCaret();
        UpdateSessionSearchUi();
        if (focusTraceBox && _traceBox.CanFocus)
        {
            _traceBox.Focus();
        }
        else if (_sessionSearchBox.CanFocus)
        {
            _sessionSearchBox.Focus();
        }
    }

    private void UpdateSessionSearchUi()
    {
        var total = _sessionSearchMatches.Count;
        var current = _sessionSearchIndex >= 0 && total > 0 ? _sessionSearchIndex + 1 : 0;
        _sessionSearchCountLabel.Text = $"{current} / {total}";
        _sessionSearchPreviousButton.Enabled = total > 0;
        _sessionSearchNextButton.Enabled = total > 0;
    }

    private void SetTip(Control control, string text)
    {
        _toolTip.SetToolTip(control, text);
    }

    private async Task RunDiagnosticsAsync()
    {
        _diagnosticsBox.Text = "Running diagnostics...";
        var result = await _controller.RunDiagnosticsAsync();
        var adminState = _controller.IsRunningAsAdministrator()
            ? "Admin mode: yes"
            : "Admin mode: no";
        _diagnosticsBox.Text = adminState + Environment.NewLine + Environment.NewLine + result.CombinedOutput;
        try
        {
            _controller.OpenDiagnosticsFolder();
        }
        catch (Exception ex)
        {
            AppendLog($"Unable to open diagnostics folder: {ex.Message}");
        }
    }

    private static bool PreflightBlocksConnect(string text, out string message)
    {
        message = "Preflight found issues before connect.";
        var start = text.IndexOf('{');
        if (start < 0)
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(text[start..]);
            var root = doc.RootElement;
            if (root.TryGetProperty("ok", out var okElement) && okElement.GetBoolean())
            {
                return false;
            }

            var lines = new List<string>();
            if (root.TryGetProperty("checks", out var checksElement) && checksElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var check in checksElement.EnumerateArray())
                {
                    if (check.TryGetProperty("ok", out var checkOk) && checkOk.GetBoolean())
                    {
                        continue;
                    }

                    var name = check.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "check" : "check";
                    if (name.Equals("elevation", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var action = check.TryGetProperty("action", out var actionElement) ? actionElement.GetString() ?? "" : "";
                    var detail = check.TryGetProperty("detail", out var detailElement) ? detailElement.GetString() ?? "" : "";
                    lines.Add(string.IsNullOrWhiteSpace(action)
                        ? $"{name}: {detail}"
                        : $"{name}: {action}");
                }
            }

            var actionableLines = lines.Where(line => !string.IsNullOrWhiteSpace(line)).ToList();
            if (actionableLines.Count == 0)
            {
                return false;
            }

            if (root.TryGetProperty("summary", out var summaryElement))
            {
                actionableLines.Insert(0, summaryElement.GetString() ?? message);
            }
            message = string.Join(Environment.NewLine, actionableLines.Take(8));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task RunPreflightAsync()
    {
        WriteSelectedProfileToConfig();
        _diagnosticsBox.Text = "Running preflight check...";
        _preflightButton.Enabled = false;
        try
        {
            var result = await _controller.RunPreflightAsync();
            _diagnosticsBox.Text = "== Preflight check ==" + Environment.NewLine + result.CombinedOutput.Trim();
        }
        finally
        {
            _preflightButton.Enabled = true;
        }
    }

    private async Task RunSandboxCheckAsync()
    {
        WriteSelectedProfileToConfig();
        _diagnosticsBox.Text = "Running offline sandbox check...";
        _sandboxCheckButton.Enabled = false;
        try
        {
            var result = await _controller.RunSandboxCheckAsync();
            _diagnosticsBox.Text = "== Offline sandbox check ==" + Environment.NewLine + result.CombinedOutput.Trim();
        }
        finally
        {
            _sandboxCheckButton.Enabled = true;
        }
    }

    private async Task RunFullDiagnosticAsync()
    {
        WriteSelectedProfileToConfig();
        _userDisconnectRequested = false;
        var startedAt = DateTime.Now;
        var initialProgressText = _controller.FullDiagnosticProgressText(startedAt);
        _diagnosticsBox.Text = initialProgressText;
        UpdateFullDiagnosticChecklist(initialProgressText);
        _fullDiagnosticRunning = true;
        _statusTimer.Stop();
        _fullDiagnosticButton.Enabled = false;
        var originalText = _fullDiagnosticButton.Text;
        var progress = 0;
        using var progressTimer = new System.Windows.Forms.Timer { Interval = 700 };
        progressTimer.Tick += (_, _) =>
        {
            progress = (progress + 1) % 4;
            _fullDiagnosticButton.Text = "Running" + new string('.', progress);
        };
        progressTimer.Start();
        try
        {
            _controller.WriteOwnerPid();
            _controller.FullDiagnosticElevated();
            var result = await _controller.WaitForFullDiagnosticReportAsync(
                startedAt,
                TimeSpan.FromMinutes(6),
                text =>
                {
                    if (!IsDisposed && IsHandleCreated)
                    {
                        BeginInvoke(() =>
                        {
                            _diagnosticsBox.Text = text;
                            UpdateFullDiagnosticChecklist(text);
                        });
                    }
                });
            _diagnosticsBox.Text = result.CombinedOutput;
            UpdateFullDiagnosticChecklist(result.CombinedOutput);
            await RefreshStatusAsync();
        }
        finally
        {
            progressTimer.Stop();
            _fullDiagnosticButton.Text = originalText;
            _fullDiagnosticButton.Enabled = true;
            _fullDiagnosticRunning = false;
            _statusTimer.Start();
        }
    }
    private async Task RunLifecycleProofAsync()
    {
        _diagnosticsBox.Text = "Running lifecycle proof. Approve UAC/FortiToken when prompted...";
        _lifecycleProofButton.Enabled = false;
        try
        {
            _userDisconnectRequested = false;
            var result = await _controller.RunLifecycleProofAsync(
                Connect,
                async () => await DisconnectAsync());
            _diagnosticsBox.Text = result.CombinedOutput;
            await RefreshStatusAsync();
        }
        finally
        {
            _lifecycleProofButton.Enabled = true;
        }
    }

    private void RepairNetwork()
    {
        WriteSelectedProfileToConfig();
        _controller.RepairNetworkElevated();
        AppendLog("Started elevated DNS/route repair.");
    }

    private async Task ResetNetworkAsync()
    {
        _diagnosticsBox.Text = "Resetting VPN network state...";
        var result = await _controller.ResetNetworkAsync();
        _diagnosticsBox.Text = result.CombinedOutput;
        await RefreshStatusAsync();
    }

    private void AppendLog(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        DetectLogScrollPosition();
        var firstVisibleLine = GetFirstVisibleLine(_logBox);
        var selectionStart = _logBox.SelectionStart;
        var selectionLength = _logBox.SelectionLength;
        var preserveSelection = selectionLength > 0 && string.IsNullOrWhiteSpace(_logSearchBox.Text);
        var currentText = _logBox.Text;
        var separator = string.IsNullOrEmpty(currentText) ? "" : Environment.NewLine;
        _logBox.Text = currentText + separator + text.Trim() + Environment.NewLine;
        RefreshLogSearchMatches(selectFirst: false);
        if (!IsHandleCreated || !_logBox.IsHandleCreated)
        {
            return;
        }

        if (preserveSelection)
        {
            BeginInvoke((Action)(() => RestoreTextSelection(_logBox, selectionStart, selectionLength)));
            return;
        }

        if (_logFollowTail)
        {
            BeginInvoke((Action)ScrollLogToEnd);
            return;
        }

        BeginInvoke((Action)(() => RestoreLogFirstVisibleLine(firstVisibleLine)));
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode != PowerModes.Resume)
        {
            return;
        }

        BeginInvoke(async () =>
        {
            AppendLog("Windows resumed from sleep; refreshing VPN status.");
            await RefreshStatusAsync();
            var profile = SelectedProfile();
            if (profile?.KeepTunnelAliveWhileAppRunning == true && !_userDisconnectRequested)
            {
                var snapshot = await _controller.GetStatusSnapshotAsync();
                if (snapshot.State == VpnConnectionState.Disconnected)
                {
                    AppendLog("Persistent tunnel is enabled; reconnecting after resume.");
                    Connect();
                }
            }
        });
    }

    public void ShowFromExternalLaunch()
    {
        if (InvokeRequired)
        {
            BeginInvoke(ShowFromExternalLaunch);
            return;
        }

        ShowFromTray();
    }

    private void EnsureVisibleAfterStartup()
    {
        if (!Visible || WindowState == FormWindowState.Minimized)
        {
            ShowFromTray();
        }
    }

    private void ShowFromTray()
    {
        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }
        Show();
        ShowInTaskbar = true;
        BringToFront();
        Activate();
        TopMost = true;
        TopMost = false;
    }

    private void ApplySavedWindowBounds()
    {
        var settings = _appSettings;
        var size = ClampWindowSize(settings.Width, settings.Height);
        if (!settings.HasBounds)
        {
            Size = size;
            CenterToScreen();
            return;
        }

        var bounds = new Rectangle(settings.X, settings.Y, size.Width, size.Height);
        var visible = Screen.AllScreens.Any(screen => screen.WorkingArea.IntersectsWith(bounds));
        if (!visible)
        {
            Size = size;
            CenterToScreen();
            return;
        }

        Bounds = bounds;
        if (settings.Maximized)
        {
            WindowState = FormWindowState.Maximized;
        }
    }

    private Size ClampWindowSize(int width, int height)
    {
        var min = MinimumSize;
        return new Size(Math.Max(width, min.Width), Math.Max(height, min.Height));
    }

    private void SaveWindowBounds()
    {
        if (WindowState == FormWindowState.Minimized)
        {
            return;
        }

        var bounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
        _appSettings.X = bounds.X;
        _appSettings.Y = bounds.Y;
        _appSettings.Width = Math.Max(bounds.Width, MinimumSize.Width);
        _appSettings.Height = Math.Max(bounds.Height, MinimumSize.Height);
        _appSettings.HasBounds = true;
        _appSettings.Maximized = WindowState == FormWindowState.Maximized;
        _appSettings.Save(_settingsPath);
    }

    private void ReloadAppSettings()
    {
        var latest = AppSettings.Load(_settingsPath);
        _appSettings.ApiEnabled = latest.ApiEnabled;
        _appSettings.ApiPort = latest.ApiPort;
        _appSettings.ApiAllowExternalConnections = latest.ApiAllowExternalConnections
            || string.Equals(latest.ApiBindAddress?.Trim(), "0.0.0.0", StringComparison.OrdinalIgnoreCase)
            || string.Equals(latest.ApiBindAddress?.Trim(), "*", StringComparison.OrdinalIgnoreCase);
        _appSettings.ApiBindAddress = _appSettings.ApiAllowExternalConnections ? "0.0.0.0" : "127.0.0.1";
    }

    private void RestartApiServer()
    {
        _apiServer?.Dispose();
        _apiServer = null;

        if (!_appSettings.ApiEnabled)
        {
            return;
        }

        try
        {
            _apiServer = new ApiServer(
                _appSettings.ApiBindAddress,
                _appSettings.ApiPort,
                GetApiStatusAsync,
                () => _controller.HealthJsonAsync(),
                () => _controller.TraceJsonAsync(),
                () => _controller.PreflightJsonAsync(),
                () => _controller.SandboxCheckJsonAsync(),
                GetApiProfiles,
                ConnectFromApiAsync,
                DisconnectFromApiAsync,
                ResetNetworkFromApiAsync);
            _apiServer.Start();
            var apiScope = _appSettings.ApiAllowExternalConnections ? "external" : "local";
            AppendLog($"{apiScope} API enabled at http://{_appSettings.ApiBindAddress}:{_appSettings.ApiPort}/");
        }
        catch (Exception ex)
        {
            AppendLog($"Unable to start local API: {ex.Message}");
        }
    }

    private Task<T> RunOnUiThreadAsync<T>(Func<Task<T>> action)
    {
        if (!InvokeRequired)
        {
            return action();
        }

        var tcs = new TaskCompletionSource<T>();
        BeginInvoke(async () =>
        {
            try
            {
                tcs.SetResult(await action());
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        return tcs.Task;
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        SaveWindowBounds();
        if (_allowExit)
        {
            return;
        }

        // MSI upgrades send WM_CLOSE to the hidden tray window. Let that exit
        // instead of turning the upgrade close request into another tray hide.
        if (e.CloseReason == CloseReason.UserClosing && !Visible)
        {
            return;
        }

        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip(1500, "MyVpnClient", "Still running in the tray.", ToolTipIcon.Info);
        }
    }
}

internal sealed class GradientTableLayoutPanel : TableLayoutPanel
{
    public GradientTableLayoutPanel()
    {
        BackColor = Color.FromArgb(236, 246, 253);
        SetStyle(
            ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer |
            ControlStyles.ResizeRedraw |
            ControlStyles.UserPaint,
            true);
        UpdateStyles();
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (ClientRectangle.Width <= 0 || ClientRectangle.Height <= 0)
        {
            return;
        }

        using var brush = new LinearGradientBrush(
            ClientRectangle,
            Color.FromArgb(246, 251, 255),
            Color.FromArgb(226, 239, 249),
            LinearGradientMode.ForwardDiagonal);
        e.Graphics.FillRectangle(brush, ClientRectangle);

        using var glow = new SolidBrush(Color.FromArgb(95, 255, 255, 255));
        e.Graphics.FillEllipse(glow, -Width / 5, -Height / 3, Width / 2, Height / 2);

        using var accent = new LinearGradientBrush(
            new Rectangle(0, 0, Math.Max(1, Width), 86),
            Color.FromArgb(64, 0, 122, 204),
            Color.FromArgb(0, 0, 122, 204),
            LinearGradientMode.Vertical);
        e.Graphics.FillRectangle(accent, 0, 0, Width, 86);
    }
}
