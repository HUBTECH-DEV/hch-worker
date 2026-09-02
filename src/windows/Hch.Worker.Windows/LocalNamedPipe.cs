using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Hch.Worker.Windows;

/// <summary>
/// Creates a local-only named pipe whose native mode rejects remote clients.
/// </summary>
public static partial class LocalNamedPipe
{
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeReadModeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const uint MaximumInstances = 1;
    private const uint BufferSize = 64 * 1024;

    private static readonly Regex PipeNamePattern = PipeNameExpression();

    /// <summary>
    /// Creates the first and only server instance with PIPE_REJECT_REMOTE_CLIENTS.
    /// </summary>
    public static NamedPipeServerStream CreateServer(
        string pipeName,
        SecurityIdentifier ownerSid,
        SecurityIdentifier serviceSid)
    {
        ValidatePipeName(pipeName);
        PipeSecurity security = WindowsAcl.CreateLocalPipeSecurity(ownerSid, serviceSid);
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        nint descriptorPointer = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, descriptorPointer, descriptor.Length);
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptorPointer,
                InheritHandle = 0,
            };

            string path = $"\\\\.\\pipe\\{pipeName}";
            SafePipeHandle handle = CreateNamedPipe(
                path,
                PipeAccessDuplex
                    | FileFlagOverlapped
                    | FileFlagWriteThrough
                    | FileFlagFirstPipeInstance,
                PipeTypeByte | PipeReadModeByte | PipeWait | PipeRejectRemoteClients,
                MaximumInstances,
                BufferSize,
                BufferSize,
                defaultTimeoutMilliseconds: 5000,
                ref attributes);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "windows-local-pipe-create-failed");
            }

            try
            {
                return new NamedPipeServerStream(
                    PipeDirection.InOut,
                    isAsync: true,
                    isConnected: false,
                    handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(descriptorPointer);
        }
    }

    /// <summary>Creates a client constrained to the local machine.</summary>
    public static NamedPipeClientStream CreateClient(string pipeName)
    {
        ValidatePipeName(pipeName);
        return new NamedPipeClientStream(
            serverName: ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            TokenImpersonationLevel.Identification,
            HandleInheritability.None);
    }

    /// <summary>
    /// Returns the process/session identifiers of the server bound to this
    /// already-connected client handle. Callers must authenticate that process
    /// before writing any IPC frame.
    /// </summary>
    public static NamedPipeServerIdentity GetServerIdentity(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!pipe.IsConnected)
        {
            throw new InvalidOperationException("windows-local-pipe-not-connected");
        }

        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint processId)
            || processId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "windows-local-pipe-server-pid-unavailable");
        }

        uint? sessionId = GetNamedPipeServerSessionId(pipe.SafePipeHandle, out uint session)
            ? session
            : null;
        return new NamedPipeServerIdentity(processId, sessionId);
    }

    /// <summary>Returns the authenticated SID and local process/session metadata.</summary>
    public static NamedPipePeerIdentity GetClientIdentity(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!pipe.IsConnected)
        {
            throw new InvalidOperationException("windows-local-pipe-not-connected");
        }

        SecurityIdentifier? sid = null;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            sid = identity.User;
        });
        if (sid is null)
        {
            throw new UnauthorizedAccessException("windows-local-pipe-client-sid-unavailable");
        }

        uint? processId = GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid)
            ? pid
            : null;
        uint? sessionId = GetNamedPipeClientSessionId(pipe.SafePipeHandle, out uint session)
            ? session
            : null;
        return new NamedPipePeerIdentity(sid, processId, sessionId);
    }

    public static void EnsureOwner(
        NamedPipeServerStream pipe,
        SecurityIdentifier expectedOwnerSid)
    {
        ArgumentNullException.ThrowIfNull(expectedOwnerSid);
        NamedPipePeerIdentity identity = GetClientIdentity(pipe);
        if (!identity.Sid.Equals(expectedOwnerSid))
        {
            throw new UnauthorizedAccessException("windows-local-pipe-owner-mismatch");
        }
    }

    /// <summary>
    /// Classifies a connected client without granting it a command. The IPC
    /// dispatcher uses this to allow a local administrator only the dedicated
    /// maintenance preflight; owner commands remain owner-only.
    /// </summary>
    public static NamedPipeClientAuthorization GetClientAuthorization(
        NamedPipeServerStream pipe,
        SecurityIdentifier expectedOwnerSid)
    {
        ArgumentNullException.ThrowIfNull(expectedOwnerSid);
        bool isOwner = false;
        bool isLocalAdministrator = false;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            isOwner = identity.User?.Equals(expectedOwnerSid) == true;
            isLocalAdministrator = identity.User?.Equals(localSystem) == true
                || identity.Groups?.Contains(administrators) == true;
        });
        if (!isOwner && !isLocalAdministrator)
        {
            throw new UnauthorizedAccessException("windows-local-pipe-owner-mismatch");
        }

        return new NamedPipeClientAuthorization(isOwner, isLocalAdministrator);
    }

    private static void ValidatePipeName(string pipeName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        if (!PipeNamePattern.IsMatch(pipeName))
        {
            throw new ArgumentException("windows-local-pipe-name-invalid", nameof(pipeName));
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maximumInstances,
        uint outputBufferSize,
        uint inputBufferSize,
        uint defaultTimeoutMilliseconds,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientSessionId(
        SafePipeHandle pipe,
        out uint clientSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerSessionId(
        SafePipeHandle pipe,
        out uint serverSessionId);

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex PipeNameExpression();

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }
}

/// <summary>Authenticated Windows identity associated with one pipe client.</summary>
public sealed record NamedPipePeerIdentity(
    SecurityIdentifier Sid,
    uint? ProcessId,
    uint? SessionId);

public sealed record NamedPipeClientAuthorization(
    bool IsOwner,
    bool IsLocalAdministrator);

/// <summary>Kernel identity associated with one connected pipe server.</summary>
public sealed record NamedPipeServerIdentity(uint ProcessId, uint? SessionId);
