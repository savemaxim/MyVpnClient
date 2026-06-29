using System.Diagnostics;

var installDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
var programData = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "MyVpnClient");
var bridgePath = Path.Combine(installDirectory, "myvpnclient_bridge.py");
var stateDirectory = Path.Combine(programData, "state");
Directory.CreateDirectory(stateDirectory);
var logPath = Path.Combine(stateDirectory, "myvpntunnel-launcher.log");
var configPath = Path.Combine(programData, "config.json");

try
{
    if (!File.Exists(bridgePath))
    {
        await AppendLauncherLogAsync(logPath, $"Missing bridge script: {bridgePath}");
        return 2;
    }

    var startInfo = new ProcessStartInfo
    {
        FileName = "py.exe",
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
        WorkingDirectory = programData
    };
    startInfo.Environment["MYVPNCLIENT_DATA_DIR"] = programData;
    startInfo.Environment["PYTHONWARNINGS"] = "ignore::SyntaxWarning";
    startInfo.ArgumentList.Add("-B");
    startInfo.ArgumentList.Add(bridgePath);
    startInfo.ArgumentList.Add("--config");
    startInfo.ArgumentList.Add(configPath);
    startInfo.ArgumentList.Add(args.Length == 0 ? "status" : args[0]);
    foreach (var argument in args.Skip(1))
    {
        startInfo.ArgumentList.Add(argument);
    }

    using var process = Process.Start(startInfo);
    if (process is null)
    {
        await AppendLauncherLogAsync(logPath, "Unable to start py.exe.");
        return 3;
    }

    var outputTask = process.StandardOutput.ReadToEndAsync();
    var errorTask = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();

    var output = await outputTask;
    var error = await errorTask;
    if (!string.IsNullOrEmpty(output))
    {
        Console.Out.Write(output);
    }
    if (!string.IsNullOrEmpty(error))
    {
        Console.Error.Write(error);
    }
    if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error))
    {
        await AppendLauncherLogAsync(logPath, $"Command exited {process.ExitCode}: {string.Join(" ", args)}{Environment.NewLine}{output}{error}");
    }

    return process.ExitCode;
}
catch (Exception ex)
{
    await AppendLauncherLogAsync(logPath, ex.ToString());
    return 1;
}

static async Task AppendLauncherLogAsync(string logPath, string message)
{
    var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message.Trim()}{Environment.NewLine}";
    await File.AppendAllTextAsync(logPath, line);
}
