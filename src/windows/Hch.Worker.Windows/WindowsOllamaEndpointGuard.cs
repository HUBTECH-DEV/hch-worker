using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Hch.Worker.Ollama;

namespace Hch.Worker.Windows;

/// <summary>
/// Authenticates the Windows process behind a loopback Ollama TCP endpoint.
/// The connection is established without application bytes; its exact server
/// row is bound to a stable listener PID before HTTP is allowed to use it.
/// </summary>
public sealed class WindowsOllamaEndpointGuard : IOllamaEndpointGuard, IAuxiliaryProcessCountProvider
{
    private const int AddressFamilyInet = 2;
    private const int AddressFamilyInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;
    private const int TcpTableOwnerPidAll = 5;
    private const uint TcpStateListen = 2;
    private const uint TcpStateEstablished = 5;
    private const string ExpectedImageFileName = "ollama.exe";

    private readonly Uri baseUri;
    private readonly SecurityIdentifier[] permittedUsers;
    private int lastVerifiedProcessId;
    private long lastVerifiedTimestamp;

    public WindowsOllamaEndpointGuard(
        Uri ollamaBaseUri,
        string? ownerSid,
        string workerServiceName = "HchWorker")
    {
        baseUri = ValidateBaseUri(ollamaBaseUri);
        var users = new Dictionary<string, SecurityIdentifier>(StringComparer.Ordinal);
        Add(users, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        Add(users, WindowsServiceIdentity.ResolveServiceSid(workerServiceName));
        if (ownerSid is not null)
        {
            Add(users, new SecurityIdentifier(ownerSid));
        }

        permittedUsers = users.Values.ToArray();
    }

    public async ValueTask EnsureTrustedAsync(
        Uri requestedBaseUri,
        CancellationToken cancellationToken)
    {
        if (!SameEndpoint(baseUri, ValidateBaseUri(requestedBaseUri)))
        {
            throw Refused("ollama-endpoint-origin-mismatch");
        }

        using Socket socket = await ConnectTrustedSocketAsync(
            new DnsEndPoint(baseUri.Host, baseUri.Port),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Counts only the recently authenticated Ollama process. A process found
    /// by name alone is never treated as an auxiliary Worker process.
    /// </summary>
    public int Collect()
    {
        int processId = Volatile.Read(ref lastVerifiedProcessId);
        long verifiedAt = Interlocked.Read(ref lastVerifiedTimestamp);
        if (processId < 1 || verifiedAt < 1
            || Stopwatch.GetElapsedTime(verifiedAt) > TimeSpan.FromMinutes(2))
        {
            return 0;
        }

        try
        {
            using Process process = Process.GetProcessById(processId);
            return process.HasExited ? 0 : 1;
        }
        catch (Exception error) when (error is ArgumentException
            or InvalidOperationException
            or NotSupportedException
            or Win32Exception)
        {
            return 0;
        }
    }

    /// <summary>
    /// SocketsHttpHandler callback. No HTTP byte is written until this method
    /// returns a stream whose peer has passed the complete process attestation.
    /// </summary>
    public async ValueTask<Stream> ConnectAuthenticatedAsync(
        DnsEndPoint endpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (endpoint.Port != baseUri.Port
            || !endpoint.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase))
        {
            throw Refused("ollama-endpoint-origin-mismatch");
        }

        Socket socket = await ConnectTrustedSocketAsync(endpoint, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private async Task<Socket> ConnectTrustedSocketAsync(
        DnsEndPoint endpoint,
        CancellationToken cancellationToken)
    {
        try
        {
            IPAddress[] addresses = await ResolveLoopbackAsync(endpoint.Host, cancellationToken)
                .ConfigureAwait(false);
            Exception? lastFailure = null;
            foreach (IPAddress address in addresses)
            {
                cancellationToken.ThrowIfCancellationRequested();
                uint? listenerBefore = FindUniqueListenerPid(address, endpoint.Port);
                if (listenerBefore is null)
                {
                    continue;
                }

                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                try
                {
                    await socket.ConnectAsync(
                        new IPEndPoint(address, endpoint.Port),
                        cancellationToken).ConfigureAwait(false);
                    IPEndPoint local = socket.LocalEndPoint as IPEndPoint
                        ?? throw Refused("ollama-endpoint-local-socket-invalid");
                    IPEndPoint remote = socket.RemoteEndPoint as IPEndPoint
                        ?? throw Refused("ollama-endpoint-remote-socket-invalid");

                    uint connectionBefore = await FindEstablishedServerPidAsync(
                        remote,
                        local,
                        cancellationToken).ConfigureAwait(false);
                    if (connectionBefore != listenerBefore.Value)
                    {
                        throw Refused("ollama-endpoint-owner-race");
                    }

                    using WindowsTrustedProcessLease process = WindowsTrustedProcessVerifier.Verify(
                        connectionBefore,
                        ExpectedImageFileName,
                        permittedUsers,
                        permittedUsers);
                    uint? listenerAfter = FindUniqueListenerPid(remote.Address, remote.Port);
                    uint connectionAfter = await FindEstablishedServerPidAsync(
                        remote,
                        local,
                        cancellationToken).ConfigureAwait(false);
                    process.EnsureAlive();
                    if (listenerAfter != listenerBefore
                        || connectionAfter != connectionBefore
                        || process.ProcessId != connectionAfter)
                    {
                        throw Refused("ollama-endpoint-owner-race");
                    }

                    Volatile.Write(ref lastVerifiedProcessId, checked((int)connectionAfter));
                    Interlocked.Exchange(ref lastVerifiedTimestamp, Stopwatch.GetTimestamp());

                    return socket;
                }
                catch (Exception error) when (error is SocketException
                    or Win32Exception or UnauthorizedAccessException
                    or IOException or InvalidOperationException
                    or System.Security.Cryptography.CryptographicException
                    or OllamaEndpointTrustException)
                {
                    socket.Dispose();
                    lastFailure = error;
                    // A process already owns this address/port. Never fall back
                    // to another address after an untrusted listener was found.
                    throw Refused("ollama-endpoint-untrusted", error);
                }
            }

            throw Refused("ollama-endpoint-unavailable", lastFailure);
        }
        catch (OllamaEndpointTrustException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error) when (error is SocketException or Win32Exception
            or UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            throw Refused("ollama-endpoint-untrusted", error);
        }
    }

    private static async Task<IPAddress[]> ResolveLoopbackAsync(
        string host,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }

        if (addresses.Length == 0 || addresses.Any(static address => !IPAddress.IsLoopback(address)))
        {
            throw Refused("ollama-endpoint-resolution-invalid");
        }

        return addresses
            .Where(static address => address.AddressFamily is
                System.Net.Sockets.AddressFamily.InterNetwork or
                System.Net.Sockets.AddressFamily.InterNetworkV6)
            .Distinct()
            .ToArray();
    }

    private static uint? FindUniqueListenerPid(IPAddress address, int port)
    {
        uint[] owners = ReadTcpRows(address.AddressFamily)
            .Where(row => row.State == TcpStateListen
                && row.LocalPort == port
                && SameAddressOrWildcard(row.LocalAddress, address))
            .Select(static row => row.ProcessId)
            .Distinct()
            .ToArray();
        return owners.Length switch
        {
            0 => null,
            1 => owners[0],
            _ => throw Refused("ollama-endpoint-listener-ambiguous"),
        };
    }

    private static async Task<uint> FindEstablishedServerPidAsync(
        IPEndPoint server,
        IPEndPoint client,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            uint[] owners = ReadTcpRows(server.AddressFamily)
                .Where(row => row.State == TcpStateEstablished
                    && row.LocalPort == server.Port
                    && row.RemotePort == client.Port
                    && SameAddress(row.LocalAddress, server.Address)
                    && SameAddress(row.RemoteAddress, client.Address))
                .Select(static row => row.ProcessId)
                .Distinct()
                .ToArray();
            if (owners.Length == 1)
            {
                return owners[0];
            }

            if (owners.Length > 1)
            {
                throw Refused("ollama-endpoint-connection-ambiguous");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
        }

        throw Refused("ollama-endpoint-connection-owner-unavailable");
    }

    private static IReadOnlyList<TcpOwnerRow> ReadTcpRows(
        System.Net.Sockets.AddressFamily family)
    {
        int nativeFamily = family switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork => AddressFamilyInet,
            System.Net.Sockets.AddressFamily.InterNetworkV6 => AddressFamilyInet6,
            _ => throw Refused("ollama-endpoint-address-family-invalid"),
        };
        int size = 0;
        uint result = GetExtendedTcpTable(
            nint.Zero,
            ref size,
            sort: true,
            nativeFamily,
            TcpTableOwnerPidAll,
            0);
        if (result != ErrorInsufficientBuffer || size <= sizeof(uint))
        {
            throw new Win32Exception(checked((int)result));
        }

        nint buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref size,
                sort: true,
                nativeFamily,
                TcpTableOwnerPidAll,
                0);
            if (result != 0)
            {
                throw new Win32Exception(checked((int)result));
            }

            int count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > 1_000_000)
            {
                throw Refused("ollama-endpoint-tcp-table-invalid");
            }

            int rowSize = family == System.Net.Sockets.AddressFamily.InterNetwork
                ? Marshal.SizeOf<Tcp4OwnerPidRow>()
                : Marshal.SizeOf<Tcp6OwnerPidRow>();
            var rows = new List<TcpOwnerRow>(Math.Min(count, 16_384));
            nint rowPointer = buffer + sizeof(uint);
            for (int index = 0; index < count; index++)
            {
                if (family == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Tcp4OwnerPidRow row = Marshal.PtrToStructure<Tcp4OwnerPidRow>(rowPointer);
                    rows.Add(new TcpOwnerRow(
                        new IPAddress(row.LocalAddress),
                        NativePort(row.LocalPort),
                        new IPAddress(row.RemoteAddress),
                        NativePort(row.RemotePort),
                        row.State,
                        row.OwningProcessId));
                }
                else
                {
                    Tcp6OwnerPidRow row = Marshal.PtrToStructure<Tcp6OwnerPidRow>(rowPointer);
                    rows.Add(new TcpOwnerRow(
                        new IPAddress(row.LocalAddress, row.LocalScopeId),
                        NativePort(row.LocalPort),
                        new IPAddress(row.RemoteAddress, row.RemoteScopeId),
                        NativePort(row.RemotePort),
                        row.State,
                        row.OwningProcessId));
                }

                rowPointer += rowSize;
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int NativePort(uint value) =>
        unchecked((ushort)IPAddress.NetworkToHostOrder((short)(value & 0xffff)));

    private static bool SameAddressOrWildcard(IPAddress actual, IPAddress expected) =>
        SameAddress(actual, expected)
        || actual.Equals(expected.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any);

    private static bool SameAddress(IPAddress left, IPAddress right) =>
        left.Equals(right)
        || left.MapToIPv6().Equals(right.MapToIPv6());

    private static Uri ValidateBaseUri(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        bool loopback = value.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || IPAddress.TryParse(value.Host, out IPAddress? address) && IPAddress.IsLoopback(address);
        if (!value.IsAbsoluteUri || value.Scheme != Uri.UriSchemeHttp || !loopback
            || value.UserInfo.Length > 0 || value.AbsolutePath != "/"
            || value.Query.Length > 0 || value.Fragment.Length > 0
            || value.Port is < 1 or > 65_535)
        {
            throw Refused("ollama-endpoint-origin-invalid");
        }

        return value;
    }

    private static bool SameEndpoint(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.Ordinal)
        && left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static void Add(
        IDictionary<string, SecurityIdentifier> values,
        SecurityIdentifier sid) => values[sid.Value] = sid;

    private static OllamaEndpointTrustException Refused(
        string code,
        Exception? cause = null) => new(code, cause);

    private sealed record TcpOwnerRow(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        uint State,
        uint ProcessId);

    [StructLayout(LayoutKind.Sequential)]
    private struct Tcp4OwnerPidRow
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Tcp6OwnerPidRow
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningProcessId;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        nint tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int addressFamily,
        int tableClass,
        uint reserved);
}
