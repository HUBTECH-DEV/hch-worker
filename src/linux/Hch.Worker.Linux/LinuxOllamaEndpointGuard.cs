using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Hch.Worker.Ollama;

namespace Hch.Worker.Linux;

/// <summary>
/// Allows loopback Ollama access only while an allowed, non-writable binary is
/// running as root or as the worker user. Endpoint-to-PID binding is left to a
/// later SO_DIAG/INET_DIAG implementation and therefore this guard must be
/// combined with host firewall isolation.
/// </summary>
public sealed class LinuxOllamaEndpointGuard : IOllamaEndpointGuard
{
    private readonly HashSet<string> allowedExecutables;
    private readonly uint workerUid;

    public LinuxOllamaEndpointGuard(IEnumerable<string>? allowedExecutablePaths = null)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }

        allowedExecutables = (allowedExecutablePaths ??
            ["/usr/bin/ollama", "/usr/local/bin/ollama"])
            .Select(LinuxPathSecurity.RequireAbsoluteCanonicalPath)
            .ToHashSet(StringComparer.Ordinal);
        if (allowedExecutables.Count == 0)
        {
            throw new ArgumentException("ollama-allowed-executables-empty", nameof(allowedExecutablePaths));
        }

        workerUid = GetEffectiveUserId();
    }

    public async ValueTask EnsureTrustedAsync(Uri baseUri, CancellationToken cancellationToken)
    {
        ValidateEndpoint(baseUri);
        if (!FindTrustedOllamaProcess())
        {
            throw Refused("ollama-linux-trusted-process-not-found");
        }

        using var client = new TcpClient(baseUri.Host.Contains(':')
            ? AddressFamily.InterNetworkV6
            : AddressFamily.InterNetwork);
        try
        {
            await client.ConnectAsync(baseUri.Host, baseUri.Port, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (error is SocketException or IOException)
        {
            throw Refused("ollama-linux-endpoint-unreachable", error);
        }
    }

    private static void ValidateEndpoint(Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        bool loopbackHost = IPAddress.TryParse(baseUri.Host, out IPAddress? address)
            && IPAddress.IsLoopback(address)
            || baseUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        if (!baseUri.IsAbsoluteUri || baseUri.Scheme != Uri.UriSchemeHttp
            || !loopbackHost || baseUri.UserInfo.Length != 0
            || baseUri.Query.Length != 0 || baseUri.Fragment.Length != 0
            || baseUri.AbsolutePath != "/" || baseUri.Port is < 1 or > 65535)
        {
            throw Refused("ollama-linux-endpoint-invalid");
        }
    }

    private bool FindTrustedOllamaProcess()
    {
        foreach (string processDirectory in Directory.EnumerateDirectories("/proc").Take(1_000_000))
        {
            if (!int.TryParse(Path.GetFileName(processDirectory), out _))
            {
                continue;
            }

            try
            {
                string executableLink = Path.Combine(processDirectory, "exe");
                string? executable = new FileInfo(executableLink)
                    .ResolveLinkTarget(returnFinalTarget: true)?.FullName;
                if (executable is null || !allowedExecutables.Contains(executable))
                {
                    continue;
                }

                UnixFileMode mode = File.GetUnixFileMode(executable);
                if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                {
                    continue;
                }

                uint uid = ReadRealUid(Path.Combine(processDirectory, "status"));
                if (uid != 0 && uid != workerUid)
                {
                    continue;
                }

                byte[] commandLine = File.ReadAllBytes(Path.Combine(processDirectory, "cmdline"));
                if (commandLine.Length is > 0 and <= 64 * 1024)
                {
                    return true;
                }
            }
            catch (Exception error) when (error is IOException
                or UnauthorizedAccessException
                or InvalidOperationException)
            {
            }
        }

        return false;
    }

    private static uint ReadRealUid(string statusPath)
    {
        string? uidLine = File.ReadLines(statusPath)
            .FirstOrDefault(static line => line.StartsWith("Uid:", StringComparison.Ordinal));
        string? value = uidLine?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Skip(1).FirstOrDefault();
        return uint.TryParse(value, out uint uid)
            ? uid
            : throw new InvalidDataException("linux-process-uid-invalid");
    }

    private static OllamaEndpointTrustException Refused(string code, Exception? inner = null) =>
        new(code, inner);

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}
