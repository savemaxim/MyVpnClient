using System.Security.Cryptography;
using System.Text;

namespace MyVpnClient;

internal sealed class SecretStore(string appDirectory)
{
    private readonly string _secretPath = Path.Combine(appDirectory, "state", "password.dpapi");

    public bool HasSavedPassword => File.Exists(_secretPath);

    public string LoadPassword()
    {
        if (!File.Exists(_secretPath))
        {
            return "";
        }

        var protectedBytes = File.ReadAllBytes(_secretPath);
        var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(bytes);
    }

    public void SavePassword(string password)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_secretPath)!);
        var bytes = Encoding.UTF8.GetBytes(password);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_secretPath, protectedBytes);
    }

    public void ClearPassword()
    {
        if (File.Exists(_secretPath))
        {
            File.Delete(_secretPath);
        }
    }
}
