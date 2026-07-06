using System.Text.Json;



namespace MyVpnClient;

internal sealed class SettingsForm : Form
{
    private readonly string _configPath;
    private readonly SecretStore _secretStore;
    private readonly string _appDirectory;
    private readonly string _settingsPath;
    private readonly AppSettings _appSettings;
    private readonly VpnProfileStore _profileStore;
    private List<VpnProfile> _profiles = [];
    private int _selectedProfileIndex;
    private bool _loadingProfileSelection;

    private readonly ComboBox _profileSelector = new FocusWheelComboBox();
    private readonly Button _addProfileButton = new();
    private readonly Button _duplicateProfileButton = new();
    private readonly Button _deleteProfileButton = new();
    private readonly TextBox _serverBox = new();
    private readonly TextBox _nameBox = new();
    private readonly TextBox _usernameBox = new();
    private readonly TextBox _passwordBox = new();
    private readonly ComboBox _protocolBox = new FocusWheelComboBox();
    private readonly TextBox _authGroupBox = new();
    private readonly TextBox _serverCertBox = new();
    private readonly CheckBox _autoPushMfaBox = new();
    private readonly NumericUpDown _mfaBlankResponsesBox = new FocusWheelNumericUpDown();
    private readonly TextBox _mfaResponseBox = new();
    private readonly CheckBox _networkFixBox = new();
    private readonly TextBox _tapAliasBox = new();
    private readonly TextBox _openconnectAliasBox = new();
    private readonly NumericUpDown _openconnectDpdSecondsBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _openconnectReconnectTimeoutBox = new FocusWheelNumericUpDown();
    private readonly TextBox _vpnDnsBox = new();
    private readonly NumericUpDown _tapMetricBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _networkFixWaitBox = new FocusWheelNumericUpDown();
    private readonly ComboBox _adapterKindBox = new FocusWheelComboBox();
    private readonly CheckBox _preferDtlsBox = new();
    private readonly CheckBox _useOpenconnectBackendBox = new();
    private readonly NumericUpDown _authRetryCountBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _pppTimeoutBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _idleTimeoutBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _terminateGraceBox = new FocusWheelNumericUpDown();
    private readonly CheckBox _keepTunnelAliveBox = new();
    private readonly NumericUpDown _sessionExpiryWarningMinutesBox = new FocusWheelNumericUpDown();
    private readonly TextBox _logPathBox = new();
    private readonly NumericUpDown _keepTunnelAliveDelayBox = new FocusWheelNumericUpDown();
    private readonly NumericUpDown _keepTunnelAliveMaxBox = new FocusWheelNumericUpDown();
    private readonly CheckBox _apiEnabledBox = new();
    private readonly NumericUpDown _apiPortBox = new FocusWheelNumericUpDown();
    private readonly CheckBox _apiAllowExternalConnectionsBox = new();
    private readonly TextBox _backendCapabilitiesBox = new();
    private readonly ToolTip _toolTip = new();

    public string SelectedProfileName { get; private set; } = "";

    public SettingsForm(string configPath, SecretStore secretStore, string appDirectory, string settingsPath)
    {
        _configPath = configPath;
        _secretStore = secretStore;
        _appDirectory = appDirectory;
        _settingsPath = settingsPath;
        _appSettings = AppSettings.Load(_settingsPath);
        _profileStore = new VpnProfileStore(Path.Combine(_appDirectory, "profiles.json"), _configPath);

        Text = "MyVpnClient Settings";
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        ClientSize = new Size(720, 600);
        Font = new Font("Segoe UI", 9F);
        _toolTip.AutoPopDelay = 20000;
        _toolTip.InitialDelay = 350;
        _toolTip.ReshowDelay = 100;
        _toolTip.ShowAlways = true;

        BuildLayout();
        LoadProfile();
    }

    private void BuildLayout()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(12)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));

        var tabs = CreateStableTabs();
        tabs.TabPages.Add(MakeProfilePage());
        tabs.TabPages.Add(MakeAuthenticationPage());
        tabs.TabPages.Add(MakeNetworkPage());
        tabs.TabPages.Add(MakeTunnelPage());
        tabs.TabPages.Add(MakeAdvancedPage());

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(0, 8, 0, 0)
        };
        var save = new Button { Text = "Save", Width = 90 };
        var cancel = new Button { Text = "Cancel", Width = 90 };
        save.Click += (_, _) => SaveAndClose();
        cancel.Click += (_, _) => DialogResult = DialogResult.Cancel;
        buttons.Controls.AddRange([save, cancel]);
        AcceptButton = save;
        CancelButton = cancel;

        root.Controls.Add(tabs, 0, 0);
        root.Controls.Add(buttons, 0, 1);
        Controls.Add(root);
    }

    private static TabControl CreateStableTabs()
    {
        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            DrawMode = TabDrawMode.OwnerDrawFixed,
            SizeMode = TabSizeMode.Fixed,
            ItemSize = new Size(112, 24)
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
            TextRenderer.DrawText(
                e.Graphics,
                tabs.TabPages[e.Index].Text,
                tabs.Font,
                bounds,
                selected ? Color.Black : Color.FromArgb(36, 44, 52),
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        };
        return tabs;
    }

    private TabPage MakeProfilePage()
    {
        var page = new TabPage("Profile");
        var root = MakeSettingsGrid(8);
        AddRow(root, 0, "Profiles", BuildProfileManagerControl(), "Create, copy, delete, or choose the profile to edit.");
        AddRow(root, 1, "Profile name", _nameBox, "Friendly name shown in the main VPN dropdown.");
        AddRow(root, 2, "Server", _serverBox, "VPN gateway host and port, for example vpn.example.com:8443.");
        AddRow(root, 3, "Username", _usernameBox, "Your VPN username.");
        AddRow(root, 4, "Password", _passwordBox, "Optional saved VPN password. It is stored with Windows DPAPI for the current user; config.json keeps password empty.");
        _passwordBox.UseSystemPasswordChar = true;
        _passwordBox.PlaceholderText = _secretStore.HasSavedPassword ? "Saved password available" : "Leave empty to keep unset";

        _protocolBox.DropDownStyle = ComboBoxStyle.DropDownList;
        _protocolBox.Items.AddRange(["fortinet"]);
        _protocolBox.Enabled = false;
        AddRow(root, 5, "VPN protocol", _protocolBox, "Fortinet only for now. OpenConnect supports more protocols, but MyVpnClient currently implements Fortinet login/MFA and cookie handoff only.");
        AddRow(root, 6, "Auth group", _authGroupBox, "Optional FortiGate realm/auth group. Leave empty when the server chooses the default group.");
        AddRow(root, 7, "Server cert", _serverCertBox, "Reserved for future certificate pinning. Current tunnel mode uses normal TLS validation settings.");
        page.Controls.Add(root);
        return page;
    }

    private Control BuildProfileManagerControl()
    {
        var row = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 1,
            Margin = Padding.Empty,
            Padding = Padding.Empty
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 78));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 86));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 78));
        row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _profileSelector.DropDownStyle = ComboBoxStyle.DropDownList;
        _profileSelector.Dock = DockStyle.Fill;
        _profileSelector.Margin = new Padding(0, 5, 8, 0);
        _profileSelector.SelectedIndexChanged += (_, _) => SelectProfileFromSelector();

        ConfigureSmallProfileButton(_addProfileButton, "Add");
        ConfigureSmallProfileButton(_duplicateProfileButton, "Copy");
        ConfigureSmallProfileButton(_deleteProfileButton, "Delete");
        _addProfileButton.Click += (_, _) => AddProfile();
        _duplicateProfileButton.Click += (_, _) => DuplicateProfile();
        _deleteProfileButton.Click += (_, _) => DeleteProfile();

        row.Controls.Add(_profileSelector, 0, 0);
        row.Controls.Add(_addProfileButton, 1, 0);
        row.Controls.Add(_duplicateProfileButton, 2, 0);
        row.Controls.Add(_deleteProfileButton, 3, 0);
        SetTip(_profileSelector, "Profile selected here is edited by the fields below.");
        SetTip(_addProfileButton, "Add a new empty VPN profile.");
        SetTip(_duplicateProfileButton, "Copy the selected profile into a new profile.");
        SetTip(_deleteProfileButton, "Delete the selected profile. At least one profile is always kept.");
        return row;
    }

    private static void ConfigureSmallProfileButton(Button button, string text)
    {
        button.Text = text;
        button.Width = 70;
        button.Height = 26;
        button.Margin = new Padding(0, 4, 8, 0);
    }

    private TabPage MakeAuthenticationPage()
    {
        var page = new TabPage("Authentication");
        var root = MakeSettingsGrid(3);
        _autoPushMfaBox.Text = "Trigger FortiToken push automatically";
        _autoPushMfaBox.AutoSize = true;
        AlignInputControl(_autoPushMfaBox);
        var mfaLabel = LabelFor("MFA push");
        root.Controls.Add(mfaLabel, 0, 0);
        root.Controls.Add(_autoPushMfaBox, 1, 0);
        SetTip(mfaLabel, "When enabled, MyVpnClient sends an empty MFA code response when Fortinet asks for tokeninfo, which triggers the FortiToken Mobile push.");
        SetTip(_autoPushMfaBox, "Keep enabled for phone approval. Disable only for non-push setups where you want to provide a manual token code below.");

        _mfaBlankResponsesBox.Minimum = 1;
        _mfaBlankResponsesBox.Maximum = 8;
        AddRow(root, 1, "Push trigger tries", _mfaBlankResponsesBox, "How many empty MFA prompts MyVpnClient may answer to trigger FortiToken Mobile push. Useful when FortiGate asks more than once.");
        AddRow(root, 2, "Manual MFA code", _mfaResponseBox, "Optional fixed token code for non-push setups. Leave empty for FortiToken Mobile push.");
        page.Controls.Add(root);
        return page;
    }

    private TabPage MakeNetworkPage()
    {
        var page = new TabPage("Network");
        var root = MakeSettingsGrid(5);

        _networkFixBox.Text = "Set VPN adapter DNS/metric after connect";
        _networkFixBox.AutoSize = true;
        AlignInputControl(_networkFixBox);
        var networkFixLabel = LabelFor("Adapter setup");
        root.Controls.Add(networkFixLabel, 0, 0);
        root.Controls.Add(_networkFixBox, 1, 0);
        SetTip(networkFixLabel, "Applies VPN adapter DNS servers, adapter metric, and DNS flush after the tunnel connects.");
        SetTip(_networkFixBox, "Keep enabled if Windows needs the VPN adapter DNS/metric updated after connect. This does not test named hosts.");

        AddRow(root, 1, "Adapter", _tapAliasBox, "Windows VPN adapter alias to configure. For the current TAP setup this is usually Local Area Connection.");
        AddRow(root, 2, "VPN DNS", _vpnDnsBox, "Comma-separated VPN DNS servers written to the VPN adapter. Leave empty to keep current DNS servers.");
        _tapMetricBox.Minimum = 1;
        _tapMetricBox.Maximum = 999;
        AddRow(root, 3, "Adapter metric", _tapMetricBox, "Lower value makes Windows prefer the VPN adapter for matching VPN routes. Current recommended value is 1.");
        _networkFixWaitBox.Minimum = 5;
        _networkFixWaitBox.Maximum = 300;
        AddRow(root, 4, "Adapter wait sec", _networkFixWaitBox, "How long the helper waits for the VPN adapter IPv4 address before applying DNS/metric setup.");
        page.Controls.Add(root);
        return page;
    }

    private TabPage MakeTunnelPage()
    {
        var page = new TabPage("Tunnel");
        var root = MakeSettingsGrid(11);
        root.RowStyles[10] = new RowStyle(SizeType.Absolute, 160);

        _useOpenconnectBackendBox.Text = "Use OpenConnect for tunnel transport";
        _useOpenconnectBackendBox.AutoSize = true;
        AlignInputControl(_useOpenconnectBackendBox);
        var tunnelBackendLabel = LabelFor("Engine");
        root.Controls.Add(tunnelBackendLabel, 0, 0);
        root.Controls.Add(_useOpenconnectBackendBox, 1, 0);
        SetTip(tunnelBackendLabel, "Recommended/default: MyVpnClient handles Fortinet login and gives the VPN cookie to openconnect.exe.");
        SetTip(_useOpenconnectBackendBox, "Keep enabled for the faster OpenConnect tunnel. Uncheck only to test the experimental native myvpn_tunnel PPP/TAP path.");

        AddRow(root, 1, "OC adapter", _openconnectAliasBox, "Windows Wintun adapter name used by OpenConnect. Use MyVpnClient unless you intentionally manage a different OpenConnect adapter.");

        _openconnectDpdSecondsBox.Minimum = 0;
        _openconnectDpdSecondsBox.Maximum = 3600;
        AddRow(root, 2, "OC DPD sec", _openconnectDpdSecondsBox, "OpenConnect dead-peer detection interval passed as --force-dpd on the next connection. Default is 0, which omits --force-dpd; OpenConnect/server defaults may still emit PPP DPD echo requests.");

        _openconnectReconnectTimeoutBox.Minimum = 0;
        _openconnectReconnectTimeoutBox.Maximum = 3600;
        AddRow(root, 3, "OC reconnect sec", _openconnectReconnectTimeoutBox, "OpenConnect reconnect timeout passed as --reconnect-timeout. Default is 60 seconds; 600 is allowed but delays dead-tunnel detection.");

        _adapterKindBox.DropDownStyle = ComboBoxStyle.DropDownList;
        _adapterKindBox.Items.AddRange(["auto", "tap", "wintun"]);
        AddRow(root, 4, "Native adapter", _adapterKindBox, "Packet adapter used by the native tunnel. Ignored when OpenConnect tunnel transport is enabled.");

        _preferDtlsBox.Text = "Prefer DTLS when a provider is available";
        _preferDtlsBox.AutoSize = true;
        AlignInputControl(_preferDtlsBox);
        var dtlsLabel = LabelFor("DTLS");
        root.Controls.Add(dtlsLabel, 0, 5);
        root.Controls.Add(_preferDtlsBox, 1, 5);
        SetTip(dtlsLabel, "Native tunnel only. Attempts the experimental DTLS transport, then falls back to TLS if unavailable.");
        SetTip(_preferDtlsBox, "Native tunnel only; MSI no longer packages OpenSSL DLLs for this experimental path.");

        _authRetryCountBox.Minimum = 0;
        _authRetryCountBox.Maximum = 5;
        AddRow(root, 6, "Auth retries", _authRetryCountBox, "Extra MFA login attempts when FortiGate returns a challenge without a VPN cookie. Use 0 for no extra retry.");

        _pppTimeoutBox.Minimum = 15;
        _pppTimeoutBox.Maximum = 300;
        AddRow(root, 7, "PPP timeout sec", _pppTimeoutBox, "Native tunnel only. How long the tunnel waits for LCP/IPCP negotiation before marking negotiation-timeout.");

        _idleTimeoutBox.Minimum = 0;
        _idleTimeoutBox.Maximum = 3600;
        AddRow(root, 8, "Idle watchdog sec", _idleTimeoutBox, "Marks tunnel-stalled when network-ready tunnel has no RX/TX for this many seconds. Use 0 to disable.");

        _terminateGraceBox.Minimum = 1;
        _terminateGraceBox.Maximum = 10;
        AddRow(root, 9, "Terminate grace", _terminateGraceBox, "Native tunnel only. Seconds to wait after sending PPP LCP terminate before closing the tunnel.");

        _keepTunnelAliveBox.Text = "Reconnect if VPN drops";
        _keepTunnelAliveBox.AutoSize = true;
        _keepTunnelAliveDelayBox.Minimum = 1;
        _keepTunnelAliveDelayBox.Maximum = 300;
        _keepTunnelAliveMaxBox.Minimum = 0;
        _keepTunnelAliveMaxBox.Maximum = 999;
        AddReconnectGroup(root, 10);
        page.Controls.Add(root);
        return page;
    }

    private void AddReconnectGroup(TableLayoutPanel root, int row)
    {
        var group = new GroupBox
        {
            Text = "Reconnect when VPN drops",
            Dock = DockStyle.Fill,
            Padding = new Padding(14, 18, 14, 12),
            Margin = new Padding(0, 8, 0, 4)
        };
        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
            Margin = Padding.Empty,
            Padding = Padding.Empty
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 142));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var groupRow = 0; groupRow < 3; groupRow++)
        {
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        }

        AlignInputControl(_keepTunnelAliveBox);
        var reconnectLabel = LabelFor("Persistent tunnel");
        grid.Controls.Add(reconnectLabel, 0, 0);
        grid.Controls.Add(_keepTunnelAliveBox, 1, 0);
        SetTip(reconnectLabel, "Reconnects when the tunnel drops while MyVpnClient is still running. It stops reconnecting after user disconnect or when MyVpnClient exits.");
        SetTip(_keepTunnelAliveBox, "Reconnect after an unexpected VPN drop. Killing MyVpnClient still stops reconnecting.");

        AddRow(grid, 1, "Delay sec", _keepTunnelAliveDelayBox, "Seconds to wait before reconnecting a dropped VPN tunnel.");
        AddRow(grid, 2, "Max reconnects", _keepTunnelAliveMaxBox, "Maximum reconnect attempts while MyVpnClient is running. Use 0 to keep trying.");

        group.Controls.Add(grid);
        root.Controls.Add(group, 0, row);
        root.SetColumnSpan(group, 2);
    }
    private TabPage MakeAdvancedPage()
    {
        var page = new TabPage("Advanced");
        var root = MakeSettingsGrid(5);

        _sessionExpiryWarningMinutesBox.Minimum = 0;
        _sessionExpiryWarningMinutesBox.Maximum = 240;
        AddRow(root, 0, "Expiry warn min", _sessionExpiryWarningMinutesBox, "Minutes before reported VPN authentication expiry to write a log warning. Use 0 for only expired log entries.");

        _logPathBox.PlaceholderText = DefaultLogPath();
        AddRow(root, 1, "Log path", _logPathBox, "Full log file path or folder. The default path is shown here when no custom path is configured.");

        _apiEnabledBox.Text = "Enable control API";
        _apiEnabledBox.AutoSize = true;
        AlignInputControl(_apiEnabledBox);
        var apiEnabledLabel = LabelFor("Local API");
        root.Controls.Add(apiEnabledLabel, 0, 2);
        root.Controls.Add(_apiEnabledBox, 1, 2);
        SetTip(apiEnabledLabel, "Disabled by default. Bind to 127.0.0.1 for local-only access or 0.0.0.0 to allow trusted network access.");
        SetTip(_apiEnabledBox, "Allows tools to read status/profiles and request connect/disconnect through HTTP.");

        _apiAllowExternalConnectionsBox.Text = "Allow external connections";
        _apiAllowExternalConnectionsBox.AutoSize = true;
        AlignInputControl(_apiAllowExternalConnectionsBox);
        var apiExternalLabel = LabelFor("External API");
        root.Controls.Add(apiExternalLabel, 0, 3);
        root.Controls.Add(_apiAllowExternalConnectionsBox, 1, 3);
        SetTip(apiExternalLabel, "Unchecked means localhost-only. Checked listens on all interfaces, for external access. Only enable this on trusted networks.");
        SetTip(_apiAllowExternalConnectionsBox, "Allows other trusted machines to call the MyVpnClient API through a trusted network.");

        _apiPortBox.Minimum = 1024;
        _apiPortBox.Maximum = 65535;
        AddRow(root, 4, "API port", _apiPortBox, "Port for the API. Endpoints: GET /status, GET /profiles, GET /health, GET /trace, POST /connect?profile=name, POST /disconnect.");
        page.Controls.Add(root);
        return page;
    }
    private static TableLayoutPanel MakeSettingsGrid(int rows)
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = rows + 1,
            Padding = new Padding(18, 16, 24, 16),
            AutoScroll = true
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var row = 0; row < rows; row++)
        {
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 39));
        }

        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
        var spacer = new Panel
        {
            Dock = DockStyle.Fill,
            Margin = Padding.Empty
        };
        root.Controls.Add(spacer, 0, rows);
        root.SetColumnSpan(spacer, 2);
        return root;
    }

    private void AddRow(TableLayoutPanel root, int row, string label, Control control, string tip)
    {
        AlignInputControl(control);
        var labelControl = LabelFor(label);
        root.Controls.Add(labelControl, 0, row);
        root.Controls.Add(control, 1, row);
        SetTip(labelControl, tip);
        SetTip(control, tip);
    }

    private static void AlignInputControl(Control control)
    {
        control.Dock = DockStyle.None;
        control.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        control.Margin = new Padding(0);
        control.Width = 490;
    }

    private static Label LabelFor(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        Margin = new Padding(6, 0, 10, 0),
        TextAlign = ContentAlignment.MiddleLeft
    };

    private void LoadProfile()
    {
        _profiles = _profileStore.Load();
        if (_profiles.Count == 0)
        {
            _profiles.Add(CreateNewProfile(UniqueProfileName("New VPN")));
        }

        var active = VpnProfile.Load(_configPath);
        var selectedIndex = FindProfileIndex(active);
        if (selectedIndex < 0)
        {
            selectedIndex = 0;
        }

        PopulateProfileSelector(selectedIndex);
        PopulateProfileFields(_profiles[_selectedProfileIndex]);
        _apiEnabledBox.Checked = _appSettings.ApiEnabled;
        _apiAllowExternalConnectionsBox.Checked = _appSettings.ApiAllowExternalConnections
            || string.Equals(_appSettings.ApiBindAddress?.Trim(), "0.0.0.0", StringComparison.OrdinalIgnoreCase)
            || string.Equals(_appSettings.ApiBindAddress?.Trim(), "*", StringComparison.OrdinalIgnoreCase);
        _apiPortBox.Value = Math.Clamp(_appSettings.ApiPort <= 0 ? 17873 : _appSettings.ApiPort, 1024, 65535);
    }

    private int FindProfileIndex(VpnProfile active)
    {
        if (!string.IsNullOrWhiteSpace(active.Name))
        {
            var byName = _profiles.FindIndex(profile => profile.Name.Equals(active.Name, StringComparison.OrdinalIgnoreCase));
            if (byName >= 0)
            {
                return byName;
            }
        }

        if (!string.IsNullOrWhiteSpace(active.Server))
        {
            return _profiles.FindIndex(profile =>
                profile.Server.Equals(active.Server, StringComparison.OrdinalIgnoreCase)
                && profile.Username.Equals(active.Username, StringComparison.OrdinalIgnoreCase));
        }

        return -1;
    }

    private void PopulateProfileSelector(int selectedIndex)
    {
        _loadingProfileSelection = true;
        try
        {
            _profileSelector.Items.Clear();
            foreach (var profile in _profiles)
            {
                _profileSelector.Items.Add(ProfileDisplayName(profile));
            }

            _selectedProfileIndex = _profiles.Count == 0 ? -1 : Math.Clamp(selectedIndex, 0, _profiles.Count - 1);
            if (_selectedProfileIndex >= 0)
            {
                _profileSelector.SelectedIndex = _selectedProfileIndex;
            }
        }
        finally
        {
            _loadingProfileSelection = false;
        }

        UpdateProfileButtons();
    }

    private void SelectProfileFromSelector()
    {
        if (_loadingProfileSelection)
        {
            return;
        }

        var nextIndex = _profileSelector.SelectedIndex;
        if (nextIndex < 0 || nextIndex >= _profiles.Count || nextIndex == _selectedProfileIndex)
        {
            return;
        }

        StoreCurrentProfileFields();
        _selectedProfileIndex = nextIndex;
        PopulateProfileFields(_profiles[_selectedProfileIndex]);
        UpdateProfileButtons();
    }

    private void AddProfile()
    {
        StoreCurrentProfileFields();
        var profile = CreateNewProfile(UniqueProfileName("New VPN"));
        _profiles.Add(profile);
        PopulateProfileSelector(_profiles.Count - 1);
        PopulateProfileFields(profile);
    }

    private void DuplicateProfile()
    {
        if (_selectedProfileIndex < 0 || _selectedProfileIndex >= _profiles.Count)
        {
            return;
        }

        StoreCurrentProfileFields();
        var clone = CloneProfile(_profiles[_selectedProfileIndex]);
        clone.Name = UniqueProfileName($"{ProfileDisplayName(_profiles[_selectedProfileIndex])} copy");
        clone.Password = "";
        _profiles.Add(clone);
        PopulateProfileSelector(_profiles.Count - 1);
        PopulateProfileFields(clone);
    }

    private void DeleteProfile()
    {
        if (_profiles.Count <= 1)
        {
            MessageBox.Show(this, "At least one VPN profile is required. You can overwrite this profile's fields instead.", "Profile required", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (_selectedProfileIndex < 0 || _selectedProfileIndex >= _profiles.Count)
        {
            return;
        }

        var name = ProfileDisplayName(_profiles[_selectedProfileIndex]);
        var result = MessageBox.Show(this, $"Delete VPN profile '{name}'?", "Delete profile", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (result != DialogResult.Yes)
        {
            return;
        }

        _profiles.RemoveAt(_selectedProfileIndex);
        PopulateProfileSelector(Math.Min(_selectedProfileIndex, _profiles.Count - 1));
        PopulateProfileFields(_profiles[_selectedProfileIndex]);
    }

    private void UpdateProfileButtons()
    {
        _duplicateProfileButton.Enabled = _profiles.Count > 0;
        _deleteProfileButton.Enabled = _profiles.Count > 1;
    }

    private void PopulateProfileFields(VpnProfile profile)
    {
        _nameBox.Text = profile.Name;
        _serverBox.Text = profile.Server;
        _usernameBox.Text = profile.Username;
        _passwordBox.Text = "";
        _passwordBox.PlaceholderText = _secretStore.HasSavedPassword ? "Saved password available" : "Leave empty to keep unset";
        _adapterKindBox.SelectedItem = string.IsNullOrWhiteSpace(profile.AdapterKind) ? "auto" : profile.AdapterKind;
        _preferDtlsBox.Checked = profile.PreferDtls;
        _useOpenconnectBackendBox.Checked = profile.UseOpenconnectBackend;
        _authRetryCountBox.Value = Math.Clamp(profile.AuthRetryCount, 0, 5);
        _pppTimeoutBox.Value = Math.Clamp(profile.PppNegotiationTimeoutSeconds <= 0 ? 90 : profile.PppNegotiationTimeoutSeconds, 15, 300);
        _idleTimeoutBox.Value = Math.Clamp(profile.TunnelIdleTimeoutSeconds, 0, 3600);
        _terminateGraceBox.Value = Math.Clamp(profile.TerminateGraceSeconds <= 0 ? 2 : profile.TerminateGraceSeconds, 1, 10);
        _keepTunnelAliveBox.Checked = profile.KeepTunnelAliveWhileAppRunning;
        _keepTunnelAliveDelayBox.Value = Math.Clamp(profile.KeepTunnelAliveReconnectDelaySeconds <= 0 ? 10 : profile.KeepTunnelAliveReconnectDelaySeconds, 1, 300);
        _keepTunnelAliveMaxBox.Value = Math.Clamp(profile.KeepTunnelAliveMaxReconnects, 0, 999);
        _protocolBox.SelectedItem = string.IsNullOrWhiteSpace(profile.Protocol) ? "fortinet" : profile.Protocol;
        _authGroupBox.Text = profile.AuthGroup;
        _serverCertBox.Text = profile.ServerCert;
        _autoPushMfaBox.Checked = profile.AutoPushMfa;
        _mfaBlankResponsesBox.Value = Math.Clamp(profile.MfaBlankResponses <= 0 ? 3 : profile.MfaBlankResponses, 1, 8);
        _mfaResponseBox.Text = profile.MfaResponse;
        _networkFixBox.Checked = profile.PostConnectNetworkFix;
        _tapAliasBox.Text = string.IsNullOrWhiteSpace(profile.TapInterfaceAlias) ? "Local Area Connection" : profile.TapInterfaceAlias;
        _openconnectAliasBox.Text = string.IsNullOrWhiteSpace(profile.OpenconnectInterfaceAlias) ? "MyVpnClient" : profile.OpenconnectInterfaceAlias;
        _openconnectDpdSecondsBox.Value = Math.Clamp(profile.OpenconnectDpdSeconds, 0, 3600);
        _openconnectReconnectTimeoutBox.Value = Math.Clamp(profile.OpenconnectReconnectTimeoutSeconds, 0, 3600);
        _vpnDnsBox.Text = string.Join(", ", profile.VpnDnsServers);
        _tapMetricBox.Value = Math.Clamp(profile.TapInterfaceMetric <= 0 ? 1 : profile.TapInterfaceMetric, 1, 999);
        _networkFixWaitBox.Value = Math.Clamp(profile.NetworkFixWaitSeconds <= 0 ? 90 : profile.NetworkFixWaitSeconds, 5, 300);
        _sessionExpiryWarningMinutesBox.Value = Math.Clamp(profile.NotifySessionExpiryWarningMinutes < 0 ? 10 : profile.NotifySessionExpiryWarningMinutes, 0, 240);
        _logPathBox.Text = DisplayLogPath(profile.LogPath);
    }

    private string DisplayLogPath(string configuredLogPath)
    {
        var resolved = ResolveLogPath(configuredLogPath);
        return string.IsNullOrWhiteSpace(resolved) ? DefaultLogPath() : resolved;
    }

    private string DefaultLogPath() => Path.Combine(_appDirectory, "state", "myvpn.log");

    private string ResolveLogPath(string? configuredLogPath)
    {
        var configured = configuredLogPath?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(configured))
        {
            return "";
        }

        var path = Environment.ExpandEnvironmentVariables(configured);
        if (!Path.IsPathRooted(path))
        {
            path = Path.Combine(_appDirectory, path);
        }
        if (Directory.Exists(path) || string.IsNullOrWhiteSpace(Path.GetExtension(path)))
        {
            path = Path.Combine(path, "myvpn.log");
        }
        return path;
    }

    private string CustomLogPathFromField()
    {
        var text = _logPathBox.Text.Trim();
        return string.Equals(text, DefaultLogPath(), StringComparison.OrdinalIgnoreCase) ? "" : text;
    }

    private void StoreCurrentProfileFields()
    {
        if (_selectedProfileIndex < 0 || _selectedProfileIndex >= _profiles.Count)
        {
            return;
        }

        _profiles[_selectedProfileIndex] = ReadProfileFromFields(_profiles[_selectedProfileIndex]);
        if (_selectedProfileIndex < _profileSelector.Items.Count)
        {
            _profileSelector.Items[_selectedProfileIndex] = ProfileDisplayName(_profiles[_selectedProfileIndex]);
        }
    }

    private VpnProfile ReadProfileFromFields(VpnProfile profile)
    {
        profile.Name = string.IsNullOrWhiteSpace(_nameBox.Text) ? _serverBox.Text.Trim() : _nameBox.Text.Trim();
        profile.Server = _serverBox.Text.Trim();
        profile.Username = _usernameBox.Text.Trim();
        profile.Backend = "myvpn_tunnel";
        profile.AdapterKind = _adapterKindBox.SelectedItem?.ToString() ?? "auto";
        profile.PreferDtls = _preferDtlsBox.Checked;
        profile.UseOpenconnectBackend = _useOpenconnectBackendBox.Checked;
        profile.AuthRetryCount = (int)_authRetryCountBox.Value;
        profile.PppNegotiationTimeoutSeconds = (int)_pppTimeoutBox.Value;
        profile.TunnelIdleTimeoutSeconds = (int)_idleTimeoutBox.Value;
        profile.TerminateGraceSeconds = (int)_terminateGraceBox.Value;
        profile.KeepTunnelAliveWhileAppRunning = _keepTunnelAliveBox.Checked;
        profile.KeepTunnelAliveReconnectDelaySeconds = (int)_keepTunnelAliveDelayBox.Value;
        profile.KeepTunnelAliveMaxReconnects = (int)_keepTunnelAliveMaxBox.Value;
        profile.OpenconnectDpdSeconds = (int)_openconnectDpdSecondsBox.Value;
        profile.OpenconnectReconnectTimeoutSeconds = (int)_openconnectReconnectTimeoutBox.Value;
        profile.Protocol = _protocolBox.SelectedItem?.ToString() ?? "fortinet";
        profile.AuthGroup = _authGroupBox.Text.Trim();
        profile.ServerCert = _serverCertBox.Text.Trim();
        profile.AutoPushMfa = _autoPushMfaBox.Checked;
        profile.MfaBlankResponses = (int)_mfaBlankResponsesBox.Value;
        profile.MfaResponse = _mfaResponseBox.Text;
        profile.PostConnectNetworkFix = _networkFixBox.Checked;
        profile.TapInterfaceAlias = string.IsNullOrWhiteSpace(_tapAliasBox.Text) ? "Local Area Connection" : _tapAliasBox.Text.Trim();
        profile.OpenconnectInterfaceAlias = string.IsNullOrWhiteSpace(_openconnectAliasBox.Text) ? "MyVpnClient" : _openconnectAliasBox.Text.Trim();
        profile.VpnDnsServers = _vpnDnsBox.Text
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .ToList();
        profile.ConnectivityCheckHosts = [];
        profile.TapInterfaceMetric = (int)_tapMetricBox.Value;
        profile.NetworkFixWaitSeconds = (int)_networkFixWaitBox.Value;
        profile.NotifySessionExpiryWarningMinutes = (int)_sessionExpiryWarningMinutesBox.Value;
        profile.LogPath = CustomLogPathFromField();
        profile.Password = "";
        return profile;
    }

    private void SaveAndClose()
    {
        StoreCurrentProfileFields();
        if (_profiles.Count == 0)
        {
            _profiles.Add(CreateNewProfile(UniqueProfileName("New VPN")));
            _selectedProfileIndex = 0;
        }

        if (!string.IsNullOrEmpty(_passwordBox.Text))
        {
            _secretStore.SavePassword(_passwordBox.Text);
        }

        _profileStore.Save(_profiles);
        var selected = _profiles[Math.Clamp(_selectedProfileIndex, 0, _profiles.Count - 1)];
        selected.Save(_configPath);
        SelectedProfileName = selected.Name;

        _appSettings.ApiEnabled = _apiEnabledBox.Checked;
        _appSettings.ApiAllowExternalConnections = _apiAllowExternalConnectionsBox.Checked;
        _appSettings.ApiBindAddress = _appSettings.ApiAllowExternalConnections ? "0.0.0.0" : "127.0.0.1";
        _appSettings.ApiPort = (int)_apiPortBox.Value;
        _appSettings.Save(_settingsPath);
        DialogResult = DialogResult.OK;
    }

    private VpnProfile CreateNewProfile(string name) => new()
    {
        Name = name,
        Backend = "myvpn_tunnel",
        Protocol = "fortinet",
        AutoPushMfa = true,
        MfaBlankResponses = 3,
        PostConnectNetworkFix = true,
        TapInterfaceAlias = "Local Area Connection",
        TapInterfaceMetric = 1,
        NetworkFixWaitSeconds = 90,
        ConnectivityCheckHosts = [],
        AdapterKind = "auto",
        UseOpenconnectBackend = true,
        OpenconnectDpdSeconds = 0,
        OpenconnectReconnectTimeoutSeconds = 60,
        NotifySessionExpiryWarningMinutes = 10,
        PppNegotiationTimeoutSeconds = 90,
        TerminateGraceSeconds = 2,
        KeepTunnelAliveReconnectDelaySeconds = 10,
    };

    private string UniqueProfileName(string preferred)
    {
        var baseName = string.IsNullOrWhiteSpace(preferred) ? "VPN profile" : preferred.Trim();
        var name = baseName;
        var suffix = 2;
        while (_profiles.Any(profile => profile.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
        {
            name = $"{baseName} {suffix}";
            suffix++;
        }

        return name;
    }

    private static VpnProfile CloneProfile(VpnProfile profile)
    {
        return JsonSerializer.Deserialize<VpnProfile>(JsonSerializer.Serialize(profile)) ?? new VpnProfile();
    }

    private static string ProfileDisplayName(VpnProfile profile)
    {
        return !string.IsNullOrWhiteSpace(profile.Name)
            ? profile.Name
            : string.IsNullOrWhiteSpace(profile.Server) ? "VPN profile" : profile.Server;
    }

    private static string BackendLabel(string backend)
    {
        return "myvpn_tunnel";
    }

    private void SetTip(Control control, string text)
    {
        _toolTip.SetToolTip(control, text);
    }

    private static void ForwardWheelToScrollableParent(Control source, int delta)
    {
        for (var parent = source.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent is not ScrollableControl { AutoScroll: true } scrollable)
            {
                continue;
            }

            var lines = SystemInformation.MouseWheelScrollLines;
            var lineCount = lines < 0 ? 6 : Math.Max(1, lines);
            var notchCount = delta == 0 ? 0.0 : delta / 120.0;
            var lineHeight = Math.Max(16, source.Font.Height);
            var pixelDelta = (int)Math.Round(-notchCount * lineCount * lineHeight);
            if (pixelDelta == 0 && delta != 0)
            {
                pixelDelta = delta > 0 ? -lineHeight : lineHeight;
            }

            var currentX = -scrollable.AutoScrollPosition.X;
            var currentY = -scrollable.AutoScrollPosition.Y;
            scrollable.AutoScrollPosition = new Point(currentX, Math.Max(0, currentY + pixelDelta));
            return;
        }
    }

    private sealed class FocusWheelNumericUpDown : NumericUpDown
    {
        protected override void OnMouseWheel(MouseEventArgs e)
        {
            if (!ContainsFocus)
            {
                ForwardWheelToScrollableParent(this, e.Delta);
                return;
            }

            base.OnMouseWheel(e);
        }
    }

    private sealed class FocusWheelComboBox : ComboBox
    {
        protected override void OnMouseWheel(MouseEventArgs e)
        {
            if (!DroppedDown)
            {
                ForwardWheelToScrollableParent(this, e.Delta);
                return;
            }

            base.OnMouseWheel(e);
        }
    }
}
