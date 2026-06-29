using System.Text.Json;

namespace MyVpnClient;

internal sealed class AppSettings
{
    public int X { get; set; }
    public int Y { get; set; }
    public int Width { get; set; } = 960;
    public int Height { get; set; } = 620;
    public bool HasBounds { get; set; }
    public bool Maximized { get; set; }
    public bool ApiEnabled { get; set; } = false;
    public int ApiPort { get; set; } = 17873;
    public string LastRunVersion { get; set; } = "";

    public static AppSettings Load(string path)
    {
        if (!File.Exists(path))
        {
            return new AppSettings();
        }

        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }
}
