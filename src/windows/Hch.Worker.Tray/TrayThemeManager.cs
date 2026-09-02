using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using MediaColor = System.Windows.Media.Color;
using MediaColorConverter = System.Windows.Media.ColorConverter;
using WpfApplication = System.Windows.Application;
using WpfSystemColors = System.Windows.SystemColors;

namespace Hch.Worker.Tray;

public enum TrayThemePreference
{
    System,
    Light,
    Dark,
}

public static class TrayThemeManager
{
    private const string PreferenceRegistryPath = @"Software\HubTech\HchWorker";
    private const string PreferenceRegistryName = "TrayTheme";
    private const string WindowsThemeRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private static bool initialized;

    public static TrayThemePreference Preference { get; private set; } = TrayThemePreference.System;

    public static bool HighContrastActive => SystemParameters.HighContrast;

    public static string ActiveThemeDescription => HighContrastActive
        ? "Alto contraste do Windows"
        : Preference switch
        {
            TrayThemePreference.Light => "Claro",
            TrayThemePreference.Dark => "Escuro",
            _ => IsWindowsLightTheme() ? "Sistema · claro" : "Sistema · escuro",
        };

    public static event EventHandler? ThemeChanged;

    public static void Initialize()
    {
        if (initialized)
        {
            return;
        }

        initialized = true;
        Preference = ReadPreference();
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
        ApplyTheme();
    }

    public static void Shutdown()
    {
        if (!initialized)
        {
            return;
        }

        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        initialized = false;
    }

    public static void SetPreference(TrayThemePreference preference)
    {
        Preference = preference;
        WritePreference(preference);
        ApplyTheme();
    }

    private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        var application = WpfApplication.Current;
        if (application is null)
        {
            return;
        }

        _ = application.Dispatcher.BeginInvoke(ApplyTheme);
    }

    private static void ApplyTheme()
    {
        var application = WpfApplication.Current;
        if (application is null)
        {
            return;
        }

        if (SystemParameters.HighContrast)
        {
            ApplyHighContrast(application.Resources);
        }
        else
        {
            bool dark = Preference == TrayThemePreference.Dark
                || (Preference == TrayThemePreference.System && !IsWindowsLightTheme());
            ApplyPalette(application.Resources, dark ? DarkPalette : LightPalette);
        }

        ThemeChanged?.Invoke(null, EventArgs.Empty);
    }

    private static void ApplyHighContrast(ResourceDictionary resources)
    {
        resources["BrandBrush"] = WpfSystemColors.HighlightBrush;
        resources["BrandTextBrush"] = WpfSystemColors.HighlightTextBrush;
        resources["CanvasBrush"] = WpfSystemColors.WindowBrush;
        resources["SurfaceBrush"] = WpfSystemColors.WindowBrush;
        resources["SurfaceMutedBrush"] = WpfSystemColors.ControlBrush;
        resources["BorderBrush"] = WpfSystemColors.WindowTextBrush;
        resources["PrimaryTextBrush"] = WpfSystemColors.WindowTextBrush;
        resources["SecondaryTextBrush"] = WpfSystemColors.GrayTextBrush;
        resources["SidebarBrush"] = WpfSystemColors.WindowBrush;
        resources["SidebarTextBrush"] = WpfSystemColors.WindowTextBrush;
        resources["SidebarSelectionBrush"] = WpfSystemColors.HighlightBrush;
        resources["SidebarSelectionTextBrush"] = WpfSystemColors.HighlightTextBrush;
        resources["SuccessBrush"] = WpfSystemColors.WindowTextBrush;
        resources["WarningBrush"] = WpfSystemColors.WindowTextBrush;
        resources["DangerBrush"] = WpfSystemColors.WindowTextBrush;
        resources["FocusBrush"] = WpfSystemColors.HighlightBrush;
    }

    private static void ApplyPalette(ResourceDictionary resources, IReadOnlyDictionary<string, string> palette)
    {
        foreach ((string key, string value) in palette)
        {
            var brush = new SolidColorBrush((MediaColor)MediaColorConverter.ConvertFromString(value));
            brush.Freeze();
            resources[key] = brush;
        }
    }

    private static TrayThemePreference ReadPreference()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(PreferenceRegistryPath, writable: false);
            return Enum.TryParse(key?.GetValue(PreferenceRegistryName) as string, ignoreCase: true, out TrayThemePreference value)
                ? value
                : TrayThemePreference.System;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return TrayThemePreference.System;
        }
    }

    private static void WritePreference(TrayThemePreference preference)
    {
        try
        {
            using RegistryKey key = Registry.CurrentUser.CreateSubKey(PreferenceRegistryPath, writable: true);
            key.SetValue(PreferenceRegistryName, preference.ToString(), RegistryValueKind.String);
        }
        catch (Exception error) when (error is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Theme selection still applies to the current session when HKCU is read-only.
        }
    }

    private static bool IsWindowsLightTheme()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(WindowsThemeRegistryPath, writable: false);
            return key?.GetValue("AppsUseLightTheme") is not int value || value != 0;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return true;
        }
    }

    private static IReadOnlyDictionary<string, string> LightPalette { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["BrandBrush"] = "#155EEF",
            ["BrandTextBrush"] = "#FFFFFF",
            ["CanvasBrush"] = "#F5F7FB",
            ["SurfaceBrush"] = "#FFFFFF",
            ["SurfaceMutedBrush"] = "#EEF2F7",
            ["BorderBrush"] = "#CBD5E1",
            ["PrimaryTextBrush"] = "#172033",
            ["SecondaryTextBrush"] = "#52627A",
            ["SidebarBrush"] = "#0F1B33",
            ["SidebarTextBrush"] = "#F8FAFC",
            ["SidebarSelectionBrush"] = "#234A9E",
            ["SidebarSelectionTextBrush"] = "#FFFFFF",
            ["SuccessBrush"] = "#0F7A47",
            ["WarningBrush"] = "#A85405",
            ["DangerBrush"] = "#B42318",
            ["FocusBrush"] = "#0B6CFB",
        };

    private static IReadOnlyDictionary<string, string> DarkPalette { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["BrandBrush"] = "#78A2FF",
            ["BrandTextBrush"] = "#071021",
            ["CanvasBrush"] = "#0B1220",
            ["SurfaceBrush"] = "#111C2F",
            ["SurfaceMutedBrush"] = "#18243A",
            ["BorderBrush"] = "#40516D",
            ["PrimaryTextBrush"] = "#F4F7FB",
            ["SecondaryTextBrush"] = "#C0CBDB",
            ["SidebarBrush"] = "#070D18",
            ["SidebarTextBrush"] = "#F4F7FB",
            ["SidebarSelectionBrush"] = "#2C57AD",
            ["SidebarSelectionTextBrush"] = "#FFFFFF",
            ["SuccessBrush"] = "#58D698",
            ["WarningBrush"] = "#FFBD70",
            ["DangerBrush"] = "#FF8A80",
            ["FocusBrush"] = "#A9C5FF",
        };
}
