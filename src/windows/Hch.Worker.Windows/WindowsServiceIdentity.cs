using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Hch.Worker.Windows;

/// <summary>Resolves Windows user and virtual-service identities as SIDs.</summary>
public static partial class WindowsServiceIdentity
{
    private const int ErrorInsufficientBuffer = 122;
    private static readonly Regex ServiceNamePattern = ServiceNameExpression();

    public static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        return identity.User
            ?? throw new InvalidOperationException("windows-current-user-sid-unavailable");
    }

    public static SecurityIdentifier ResolveServiceSid(string serviceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        if (!ServiceNamePattern.IsMatch(serviceName))
        {
            throw new ArgumentException("windows-service-name-invalid", nameof(serviceName));
        }

        return ResolveAccountSid($"NT SERVICE\\{serviceName}");
    }

    public static SecurityIdentifier ResolveAccountSid(string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);

        uint sidLength = 0;
        uint domainLength = 0;
        _ = LookupAccountName(
            null,
            accountName,
            null,
            ref sidLength,
            null,
            ref domainLength,
            out _);
        int firstError = Marshal.GetLastWin32Error();
        if (firstError != ErrorInsufficientBuffer || sidLength == 0)
        {
            throw new Win32Exception(firstError, "windows-account-sid-size-unavailable");
        }

        var sid = new byte[sidLength];
        var domain = new StringBuilder(checked((int)domainLength));
        if (!LookupAccountName(
                null,
                accountName,
                sid,
                ref sidLength,
                domain,
                ref domainLength,
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "windows-account-sid-unavailable");
        }

        return new SecurityIdentifier(sid, 0);
    }

    [DllImport("advapi32.dll", EntryPoint = "LookupAccountNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountName(
        string? systemName,
        string accountName,
        byte[]? sid,
        ref uint sidSize,
        StringBuilder? referencedDomainName,
        ref uint domainNameSize,
        out SidNameUse use);

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceNameExpression();

    private enum SidNameUse
    {
        User = 1,
        Group,
        Domain,
        Alias,
        WellKnownGroup,
        DeletedAccount,
        Invalid,
        Unknown,
        Computer,
        Label,
        LogonSession,
    }
}
