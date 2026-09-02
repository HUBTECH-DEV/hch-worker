using System.Text.Json;

namespace Hch.Worker.Tray;

public static class TrayConfiguration
{
    public static string ResolveNodeId()
    {
        var productRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "HubTech",
            "HCH Worker");
        var path = Path.Combine(productRoot, "config.json");
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            var nodeId = document.RootElement.GetProperty("nodeId").GetString();
            if (!string.IsNullOrWhiteSpace(nodeId))
            {
                return nodeId;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or KeyNotFoundException)
        {
            // The service may not be configured yet. The deterministic pending
            // pipe exposes only diagnostics/onboarding until ownership exists.
        }

        var machine = new string(Environment.MachineName.ToLowerInvariant()
            .Select(static c => char.IsAsciiLetterOrDigit(c) ? c : '-')
            .ToArray()).Trim('-');
        return $"pending-{machine}";
    }
}
