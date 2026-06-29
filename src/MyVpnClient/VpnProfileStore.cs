using System.Text.Json;

namespace MyVpnClient;

internal sealed class VpnProfileStore(string profilesPath, string legacyConfigPath)
{
    private string AppDirectory => Path.GetDirectoryName(profilesPath)!;

    public List<VpnProfile> Load()
    {
        if (File.Exists(profilesPath))
        {
            try
            {
                var json = File.ReadAllText(profilesPath);
                var profiles = VpnProfile.LoadList(json);
                var changed = MigrateMissingBackendFromActiveConfig(profiles, json);
                profiles = EnsureNames(profiles);
                changed = true;
                if (changed)
                {
                    Save(profiles);
                }

                return profiles;
            }
            catch
            {
                return [];
            }
        }

        var legacy = VpnProfile.Load(legacyConfigPath);
        if (string.IsNullOrWhiteSpace(legacy.Server))
        {
            legacy.Name = "New VPN";
        }
        else if (string.IsNullOrWhiteSpace(legacy.Name))
        {
            legacy.Name = legacy.Server;
        }

        var initial = new List<VpnProfile> { legacy };
        Save(initial);
        return initial;
    }

    public void Save(List<VpnProfile> profiles)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(profilesPath)!);
        var json = JsonSerializer.Serialize(EnsureNames(profiles), Options());
        File.WriteAllText(profilesPath, json);
    }

    private List<VpnProfile> EnsureNames(List<VpnProfile> profiles)
    {
        foreach (var profile in profiles)
        {
            VpnProfile.Normalize(profile);

            if (string.IsNullOrWhiteSpace(profile.Name))
            {
                profile.Name = string.IsNullOrWhiteSpace(profile.Server) ? "VPN profile" : profile.Server;
            }

            profile.Password = "";
        }

        return profiles;
    }

    private bool MigrateMissingBackendFromActiveConfig(List<VpnProfile> profiles, string rawJson)
    {
        var active = VpnProfile.Load(legacyConfigPath);
        if (string.IsNullOrWhiteSpace(active.Server) || string.IsNullOrWhiteSpace(active.Backend))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            var changed = false;
            var count = Math.Min(profiles.Count, doc.RootElement.GetArrayLength());
            for (var index = 0; index < count; index++)
            {
                var profile = profiles[index];
                var rawProfile = doc.RootElement[index];
                if (rawProfile.TryGetProperty("backend", out _))
                {
                    continue;
                }

                var sameServer = profile.Server.Equals(active.Server, StringComparison.OrdinalIgnoreCase);
                var sameName = !string.IsNullOrWhiteSpace(active.Name)
                    && profile.Name.Equals(active.Name, StringComparison.OrdinalIgnoreCase);
                if (sameServer || sameName)
                {
                    profile.Backend = active.Backend;
                    profile.AdapterKind = active.AdapterKind;
                    profile.PreferDtls = active.PreferDtls;
                    changed = true;
                }
            }

            return changed;
        }
        catch
        {
            return false;
        }
    }

    private static JsonSerializerOptions Options() => new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };
}

