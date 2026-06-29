using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace MyVpnClient;

internal sealed class VpnProfile
{
    private const int CurrentSchemaVersion = 9;

    private static readonly (string LegacyName, string CurrentName)[] LegacyPropertyNames = [];

    [JsonPropertyName("configSchemaVersion")]
    public int ConfigSchemaVersion { get; set; } = CurrentSchemaVersion;

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("backend")]
    public string Backend { get; set; } = "myvpn_tunnel";

    [JsonPropertyName("adapterKind")]
    public string AdapterKind { get; set; } = "auto";

    [JsonPropertyName("preferDtls")]
    public bool PreferDtls { get; set; }

    [JsonPropertyName("useOpenconnectBackend")]
    public bool UseOpenconnectBackend { get; set; } = true;

    [JsonPropertyName("authRetryCount")]
    public int AuthRetryCount { get; set; }

    [JsonPropertyName("pppNegotiationTimeoutSeconds")]
    public int PppNegotiationTimeoutSeconds { get; set; } = 90;

    [JsonPropertyName("tunnelIdleTimeoutSeconds")]
    public int TunnelIdleTimeoutSeconds { get; set; }

    [JsonPropertyName("terminateGraceSeconds")]
    public int TerminateGraceSeconds { get; set; } = 2;

    [JsonPropertyName("keepTunnelAliveWhileAppRunning")]
    public bool KeepTunnelAliveWhileAppRunning { get; set; }

    [JsonPropertyName("keepTunnelAliveReconnectDelaySeconds")]
    public int KeepTunnelAliveReconnectDelaySeconds { get; set; } = 10;

    [JsonPropertyName("keepTunnelAliveMaxReconnects")]
    public int KeepTunnelAliveMaxReconnects { get; set; }

    [JsonPropertyName("server")]
    public string Server { get; set; } = "";

    [JsonPropertyName("username")]
    public string Username { get; set; } = "";

    [JsonPropertyName("password")]
    public string Password { get; set; } = "";

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "fortinet";

    [JsonPropertyName("servercert")]
    public string ServerCert { get; set; } = "";

    [JsonPropertyName("authgroup")]
    public string AuthGroup { get; set; } = "";

    [JsonPropertyName("autoPushMfa")]
    public bool AutoPushMfa { get; set; } = true;

    [JsonPropertyName("mfaBlankResponses")]
    public int MfaBlankResponses { get; set; } = 3;

    [JsonPropertyName("mfaResponse")]
    public string MfaResponse { get; set; } = "";


    [JsonPropertyName("notifySessionExpiryWarningMinutes")]
    public int NotifySessionExpiryWarningMinutes { get; set; } = 10;

    [JsonPropertyName("logPath")]
    public string LogPath { get; set; } = "";

    [JsonPropertyName("postConnectNetworkFix")]
    public bool PostConnectNetworkFix { get; set; } = true;

    [JsonPropertyName("tapInterfaceAlias")]
    public string TapInterfaceAlias { get; set; } = "Local Area Connection";

    [JsonPropertyName("openconnectInterfaceAlias")]
    public string OpenconnectInterfaceAlias { get; set; } = "MyVpnClient";

    [JsonPropertyName("openconnectForceInterfaceAlias")]
    public bool OpenconnectForceInterfaceAlias { get; set; }

    [JsonPropertyName("openconnectDpdSeconds")]
    public int OpenconnectDpdSeconds { get; set; } = 20;

    [JsonPropertyName("openconnectReconnectTimeoutSeconds")]
    public int OpenconnectReconnectTimeoutSeconds { get; set; } = 60;

    [JsonPropertyName("tapInterfaceMetric")]
    public int TapInterfaceMetric { get; set; } = 1;

    [JsonPropertyName("vpnDnsServers")]
    public List<string> VpnDnsServers { get; set; } = [];

    [JsonPropertyName("networkFixWaitSeconds")]
    public int NetworkFixWaitSeconds { get; set; } = 90;

    [JsonPropertyName("connectivityCheckHosts")]
    public List<string> ConnectivityCheckHosts { get; set; } = [];

    [JsonPropertyName("networkCheckDnsHost")]
    public string NetworkCheckDnsHost { get; set; } = "";

    [JsonPropertyName("networkCheckRouteWaitSeconds")]
    public int NetworkCheckRouteWaitSeconds { get; set; } = 20;

    public static VpnProfile Load(string path)
    {
        if (!File.Exists(path))
        {
            return new VpnProfile();
        }

        return FromJson(File.ReadAllText(path));
    }

    public static VpnProfile FromJson(string json)
    {
        return Normalize(JsonSerializer.Deserialize<VpnProfile>(MigrateLegacyPropertyNames(json), JsonOptions()) ?? new VpnProfile());
    }

    public static List<VpnProfile> LoadList(string json)
    {
        return JsonSerializer.Deserialize<List<VpnProfile>>(MigrateLegacyPropertyNames(json), JsonOptions()) ?? [];
    }

    public void Save(string path)
    {
        Normalize(this);
        var json = JsonSerializer.Serialize(this, JsonOptions());
        File.WriteAllText(path, json);
    }

    public static VpnProfile Normalize(VpnProfile profile)
    {
        if (profile.ConfigSchemaVersion < 5)
        {
            profile.UseOpenconnectBackend = true;
        }

        if (profile.ConfigSchemaVersion < 7 || string.IsNullOrWhiteSpace(profile.OpenconnectInterfaceAlias))
        {
            profile.OpenconnectInterfaceAlias = string.IsNullOrWhiteSpace(profile.TapInterfaceAlias)
                || profile.TapInterfaceAlias.Equals("Local Area Connection", StringComparison.OrdinalIgnoreCase)
                    ? "MyVpnClient"
                    : profile.TapInterfaceAlias;
        }

        if (profile.NotifySessionExpiryWarningMinutes < 0)
        {
            profile.NotifySessionExpiryWarningMinutes = 10;
        }

        profile.ConfigSchemaVersion = CurrentSchemaVersion;
        profile.PreferDtls = false;
        profile.Backend = "myvpn_tunnel";
        profile.Protocol = "fortinet";
        // Host checks were removed from normal MyVpnClient connect flow.
        profile.ConnectivityCheckHosts = [];
        profile.NetworkCheckDnsHost = "";
        if (profile.NetworkCheckRouteWaitSeconds <= 0)
        {
            profile.NetworkCheckRouteWaitSeconds = 20;
        }
        return profile;
    }

    private static string MigrateLegacyPropertyNames(string json)
    {
        var root = JsonNode.Parse(json);
        if (root is null)
        {
            return json;
        }

        var changed = MigrateLegacyPropertyNames(root);
        return changed ? root.ToJsonString(JsonOptions()) : json;
    }

    private static bool MigrateLegacyPropertyNames(JsonNode node)
    {
        var changed = false;
        if (node is JsonObject obj)
        {
            foreach (var (legacyName, currentName) in LegacyPropertyNames)
            {
                if (!obj.TryGetPropertyValue(legacyName, out var legacyValue))
                {
                    continue;
                }

                if (!obj.ContainsKey(currentName))
                {
                    obj[currentName] = legacyValue?.DeepClone();
                }

                changed |= obj.Remove(legacyName);
            }

            foreach (var child in obj.Select(item => item.Value).Where(value => value is not null))
            {
                changed |= MigrateLegacyPropertyNames(child!);
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array.Where(value => value is not null))
            {
                changed |= MigrateLegacyPropertyNames(child!);
            }
        }

        return changed;
    }

    private static JsonSerializerOptions JsonOptions() => new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };
}
