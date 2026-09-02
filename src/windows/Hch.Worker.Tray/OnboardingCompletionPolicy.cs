using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Tray;

internal readonly record struct OnboardingCompletionState(
    bool EnrollmentValid,
    bool TrustValid,
    bool ManifestValid,
    bool ReadinessValid,
    bool Paused,
    bool CanComplete);

internal static class OnboardingCompletionPolicy
{
    public static OnboardingCompletionState Evaluate(
        WorkerSnapshotPayload snapshot,
        bool enrollmentCompletedThisSession,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        bool trustValid = IsTrustValid(snapshot.TrustStatus);
        bool manifestValid = IsManifestValid(snapshot.ManifestStatus);
        bool readinessValid = IsReadinessValid(snapshot, now);
        bool paused = !snapshot.AcceptingClaims
            && snapshot.OperationalState.Equals("Paused", StringComparison.OrdinalIgnoreCase);
        bool canComplete = enrollmentCompletedThisSession
            && trustValid
            && manifestValid
            && readinessValid
            && paused;

        return new OnboardingCompletionState(
            enrollmentCompletedThisSession,
            trustValid,
            manifestValid,
            readinessValid,
            paused,
            canComplete);
    }

    public static bool IsTrustValid(string value) =>
        value.Equals("verified", StringComparison.OrdinalIgnoreCase)
        || value.Equals("ready", StringComparison.OrdinalIgnoreCase)
        || value.Equals("trusted", StringComparison.OrdinalIgnoreCase);

    public static bool IsManifestValid(string value) =>
        value.Equals("applied-contract-valid", StringComparison.OrdinalIgnoreCase)
        || value.Equals("valid", StringComparison.OrdinalIgnoreCase);

    public static bool IsReadinessValid(WorkerSnapshotPayload snapshot, DateTimeOffset now) =>
        snapshot.Ready
        && snapshot.ReadyUntil is { } readyUntil
        && readyUntil > now;
}
