using System.Globalization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

/// <summary>A strict SemVer 2.0 value with precedence comparison.</summary>
public sealed partial record SemanticVersion : IComparable<SemanticVersion>
{
    private const long JavaScriptMaximumSafeInteger = 9_007_199_254_740_991;

    private SemanticVersion(long major, long minor, long patch, string[]? prerelease, string? build, string original)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        Prerelease = prerelease;
        Build = build;
        Original = original;
    }

    public long Major { get; }
    public long Minor { get; }
    public long Patch { get; }
    public IReadOnlyList<string>? Prerelease { get; }
    public string? Build { get; }
    public string Original { get; }

    public static SemanticVersion Parse(string value)
    {
        if (!TryParse(value, out var version))
        {
            throw new ProtocolValidationException("semantic-version-invalid", "The value is not strict SemVer 2.0.");
        }

        return version;
    }

    public static bool TryParse(string? value, out SemanticVersion version)
    {
        version = null!;
        if (value is null || value.Length is 0 or > 64)
        {
            return false;
        }

        var match = SemVerPattern().Match(value);
        if (!match.Success
            || !TryParseCoreNumber(match.Groups[1].Value, out var major)
            || !TryParseCoreNumber(match.Groups[2].Value, out var minor)
            || !TryParseCoreNumber(match.Groups[3].Value, out var patch))
        {
            return false;
        }

        var prerelease = match.Groups[4].Success ? match.Groups[4].Value.Split('.') : null;
        if (prerelease?.Any(part => part.All(char.IsAsciiDigit) && part.Length > 1 && part[0] == '0') == true)
        {
            return false;
        }

        version = new SemanticVersion(
            major,
            minor,
            patch,
            prerelease,
            match.Groups[5].Success ? match.Groups[5].Value : null,
            value);
        return true;
    }

    public int CompareTo(SemanticVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        var comparison = Major.CompareTo(other.Major);
        if (comparison != 0) return comparison;
        comparison = Minor.CompareTo(other.Minor);
        if (comparison != 0) return comparison;
        comparison = Patch.CompareTo(other.Patch);
        if (comparison != 0) return comparison;

        if (Prerelease is null || other.Prerelease is null)
        {
            if (Prerelease is null && other.Prerelease is null) return 0;
            return Prerelease is null ? 1 : -1;
        }

        for (var index = 0; index < Math.Max(Prerelease.Count, other.Prerelease.Count); index++)
        {
            if (index >= Prerelease.Count) return -1;
            if (index >= other.Prerelease.Count) return 1;

            var left = Prerelease[index];
            var right = other.Prerelease[index];
            if (left.Equals(right, StringComparison.Ordinal)) continue;

            var leftNumeric = left.All(char.IsAsciiDigit);
            var rightNumeric = right.All(char.IsAsciiDigit);
            if (leftNumeric && rightNumeric)
            {
                if (left.Length != right.Length) return left.Length.CompareTo(right.Length);
                return string.CompareOrdinal(left, right);
            }

            if (leftNumeric != rightNumeric) return leftNumeric ? -1 : 1;
            return string.CompareOrdinal(left, right);
        }

        return 0;
    }

    public override string ToString() => Original;

    private static bool TryParseCoreNumber(string value, out long result) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result)
        && result <= JavaScriptMaximumSafeInteger;

    [GeneratedRegex(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex SemVerPattern();
}
