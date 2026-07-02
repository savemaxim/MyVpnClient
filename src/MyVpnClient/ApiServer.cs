using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MyVpnClient;

internal sealed class ApiServer : IDisposable
{
    private readonly IPAddress _bindAddress;
    private readonly int _port;
    private readonly Func<Task<ApiStatus>> _getStatus;
    private readonly Func<Task<JsonNode>> _getHealth;
    private readonly Func<Task<JsonNode>> _getTrace;
    private readonly Func<Task<JsonNode>> _getPreflight;
    private readonly Func<Task<JsonNode>> _getSandboxCheck;
    private readonly Func<IReadOnlyList<ApiProfile>> _getProfiles;
    private readonly Func<string?, Task<string>> _connect;
    private readonly Func<Task<string>> _disconnect;
    private readonly Func<Task<string>> _resetNetwork;
    private readonly CancellationTokenSource _cts = new();
    private TcpListener? _listener;
    private Task? _loopTask;

    public ApiServer(
        string bindAddress,
        int port,
        Func<Task<ApiStatus>> getStatus,
        Func<Task<JsonNode>> getHealth,
        Func<Task<JsonNode>> getTrace,
        Func<Task<JsonNode>> getPreflight,
        Func<Task<JsonNode>> getSandboxCheck,
        Func<IReadOnlyList<ApiProfile>> getProfiles,
        Func<string?, Task<string>> connect,
        Func<Task<string>> disconnect,
        Func<Task<string>> resetNetwork)
    {
        _bindAddress = ParseBindAddress(bindAddress);
        _port = port;
        _getStatus = getStatus;
        _getHealth = getHealth;
        _getTrace = getTrace;
        _getPreflight = getPreflight;
        _getSandboxCheck = getSandboxCheck;
        _getProfiles = getProfiles;
        _connect = connect;
        _disconnect = disconnect;
        _resetNetwork = resetNetwork;
    }

    public void Start()
    {
        _listener = new TcpListener(_bindAddress, _port);
        _listener.Start();
        _loopTask = Task.Run(AcceptLoopAsync);
    }

    private static IPAddress ParseBindAddress(string? value)
    {
        var text = string.IsNullOrWhiteSpace(value) ? "127.0.0.1" : value.Trim();
        if (text.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Loopback;
        }
        if (text.Equals("*", StringComparison.OrdinalIgnoreCase) ||
            text.Equals("any", StringComparison.OrdinalIgnoreCase) ||
            text.Equals("all", StringComparison.OrdinalIgnoreCase) ||
            text.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Any;
        }
        return IPAddress.TryParse(text, out var parsed) ? parsed : IPAddress.Loopback;
    }

    public void Dispose()
    {
        try
        {
            if (!_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
        }
        catch (ObjectDisposedException)
        {
        }

        try
        {
            _listener?.Stop();
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }

        _cts.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested && _listener is not null)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = Task.Run(() => HandleClientAsync(client), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                await Task.Delay(500, _cts.Token).ContinueWith(_ => { });
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using (client)
        {
            client.ReceiveTimeout = 5000;
            client.SendTimeout = 5000;
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var requestLine = await reader.ReadLineAsync();
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                return;
            }

            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                await WriteJsonAsync(stream, 400, new { error = "Bad request" });
                return;
            }

            var method = parts[0].ToUpperInvariant();
            var pathAndQuery = parts[1];
            var contentLength = 0;
            for (var line = await reader.ReadLineAsync(); !string.IsNullOrEmpty(line); line = await reader.ReadLineAsync())
            {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(line["Content-Length:".Length..].Trim(), out var parsed))
                {
                    contentLength = parsed;
                }
            }

            var body = "";
            if (contentLength > 0)
            {
                var buffer = new char[contentLength];
                var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
                body = new string(buffer, 0, read);
            }

            try
            {
                await RouteAsync(stream, method, pathAndQuery, body);
            }
            catch (Exception ex)
            {
                await WriteJsonAsync(stream, 500, new { error = ex.Message });
            }
        }
    }

    private async Task RouteAsync(Stream stream, string method, string pathAndQuery, string body)
    {
        var uri = new Uri("http://127.0.0.1" + pathAndQuery);
        if (method == "GET" && uri.AbsolutePath.Equals("/status", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, await _getStatus());
            return;
        }

        if (method == "GET" && uri.AbsolutePath.Equals("/profiles", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, new { profiles = _getProfiles() });
            return;
        }

        if (method == "GET" && uri.AbsolutePath.Equals("/health", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, await _getHealth());
            return;
        }

        if (method == "GET" && uri.AbsolutePath.Equals("/trace", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, await _getTrace());
            return;
        }

        if (method == "GET" && uri.AbsolutePath.Equals("/preflight", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, await _getPreflight());
            return;
        }

        if (method == "GET" && uri.AbsolutePath.Equals("/sandbox-check", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 200, await _getSandboxCheck());
            return;
        }

        if (method == "POST" && uri.AbsolutePath.Equals("/connect", StringComparison.OrdinalIgnoreCase))
        {
            var profile = GetQuery(uri, "profile") ?? GetJsonString(body, "profile");
            await WriteJsonAsync(stream, 202, new { message = await _connect(profile) });
            return;
        }

        if (method == "POST" && uri.AbsolutePath.Equals("/disconnect", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 202, new { message = await _disconnect() });
            return;
        }

        if (method == "POST" && uri.AbsolutePath.Equals("/reset-network", StringComparison.OrdinalIgnoreCase))
        {
            await WriteJsonAsync(stream, 202, new { message = await _resetNetwork() });
            return;
        }

        await WriteJsonAsync(stream, 404, new
        {
            error = "Not found",
            endpoints = new[] { "GET /status", "GET /profiles", "GET /health", "GET /trace", "GET /preflight", "GET /sandbox-check", "POST /connect?profile=name", "POST /disconnect", "POST /reset-network" }
        });
    }

    private static string? GetQuery(Uri uri, string name)
    {
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var item in query)
        {
            var pair = item.Split('=', 2);
            if (pair.Length == 2 && WebUtility.UrlDecode(pair[0]).Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return WebUtility.UrlDecode(pair[1]);
            }
        }

        return null;
    }

    private static string? GetJsonString(string body, string name)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task WriteJsonAsync(Stream stream, int statusCode, object payload)
    {
        var body = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        var statusText = statusCode switch
        {
            200 => "OK",
            202 => "Accepted",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Internal Server Error"
        };
        var bytes = Encoding.UTF8.GetBytes(body);
        var header = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {statusCode} {statusText}\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            $"Content-Length: {bytes.Length}\r\n" +
            "Connection: close\r\n" +
            "Access-Control-Allow-Origin: http://127.0.0.1\r\n" +
            "\r\n");
        await stream.WriteAsync(header);
        await stream.WriteAsync(bytes);
    }
}

internal sealed record ApiStatus(
    bool ApiEnabled,
    string State,
    string Detail,
    string? SelectedProfile,
    int Port,
    string BindAddress,
    string Phase,
    string UserMessage,
    string SuggestedAction,
    bool Retryable);

internal sealed record ApiProfile(string Name, string Server, string Protocol, string Backend, bool Selected);

