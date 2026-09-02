using System.Text.Json;
using System.Text.Json.Serialization;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

public sealed record BootstrapCoordinatorRequest(
    string NodeId,
    string WorkerKeyId,
    string Architecture,
    string Hostname,
    string WorkerRuntimeVersion,
    string BootstrapRequestId,
    string AttestationRequestId,
    int ActiveAssignments = 0);

public sealed record BootstrapCoordinatorResult(
    string NodeId,
    string WorkerKeyId,
    string State,
    long ManifestSequence,
    string ManifestHash,
    string ContentContractHash,
    string ReadyUntil,
    bool WorkStarted,
    bool MetadataOnly);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ManifestTrustStateRecord
{
    [JsonRequired]
    public required string Schema { get; init; }

    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required string RootKeyId { get; init; }

    [JsonRequired]
    public required string RootFingerprint { get; init; }

    [JsonRequired]
    public required string ReleaseKeyId { get; init; }

    [JsonRequired]
    public required long DelegationSequence { get; init; }

    [JsonRequired]
    public required string DelegationHash { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string VerifiedAt { get; init; }

    public DelegationTrustAnchor ToAnchor() => new(
        SchemaVersion,
        RootKeyId,
        RootFingerprint,
        DelegationSequence,
        DelegationHash);

    public AppliedManifestAnchor ToManifestAnchor() => new(
        SchemaVersion,
        ManifestSequence,
        ManifestHash,
        ContentContractHash);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WorkerReadyStateRecord
{
    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required bool Ready { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string KeyId { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string Provider { get; init; }

    [JsonRequired]
    public required string EngineAdapter { get; init; }

    [JsonRequired]
    public required string EngineAdapterVersion { get; init; }

    [JsonRequired]
    public required string WorkerRuntimeVersion { get; init; }

    [JsonRequired]
    public required string RuntimeProfileHash { get; init; }

    [JsonRequired]
    public required string CapacityPolicyHash { get; init; }

    [JsonRequired]
    public required string AdaptiveWorkPolicyHash { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required int GrantedCapacity { get; init; }

    [JsonRequired]
    public required string CapacityClass { get; init; }

    [JsonRequired]
    public required string CapacityReason { get; init; }

    [JsonRequired]
    public required string CapacityGrantedUntil { get; init; }

    [JsonRequired]
    public required string BootstrapSessionId { get; init; }

    [JsonRequired]
    public required string ReadyUntil { get; init; }

    [JsonRequired]
    public required string AttestedAt { get; init; }

    [JsonRequired]
    public required string TrustVerifiedAt { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WorkerCapacityStateRecord
{
    [JsonRequired]
    public required string Schema { get; init; }

    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required string ObservedAt { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string CapacityPolicyHash { get; init; }

    [JsonRequired]
    public required string AlgorithmVersion { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required int GrantedCapacity { get; init; }

    [JsonRequired]
    public required string CapacityClass { get; init; }

    [JsonRequired]
    public required string Reason { get; init; }

    [JsonRequired]
    public required string GrantedUntil { get; init; }

    [JsonRequired]
    public required int ActiveAssignments { get; init; }

    [JsonRequired]
    public required int AvailableSlots { get; init; }

    [JsonRequired]
    public required string Source { get; init; }
}

/// <summary>
/// Orchestrates the fail-closed Windows bootstrap while preserving the
/// operational Paused/Drain state. It never enables claims or starts work.
/// </summary>
public sealed class BootstrapAttestationCoordinator(
    AtomicFileStore files,
    IWorkerBootstrapClient client,
    ManifestArtifactApplier applier,
    ManifestTrustPins pins,
    IEd25519SignatureProvider verifier,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<BootstrapCoordinatorResult> RunPausedAsync(
        BootstrapCoordinatorRequest request,
        CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        var currentApplied = await files.ReadJsonAsync<AppliedManifestState>(
            "applied-manifest.json",
            cancellationToken).ConfigureAwait(false);
        AppliedManifestAnchor? appliedAnchor = null;
        if (currentApplied is not null)
        {
            _ = AppliedRuntimeContract.FromAppliedState(currentApplied);
            appliedAnchor = new AppliedManifestAnchor(
                currentApplied.SchemaVersion,
                currentApplied.ManifestSequence,
                currentApplied.ManifestHash,
                currentApplied.ContentContractHash);
        }

        var persistedTrust = await files.ReadJsonAsync<ManifestTrustStateRecord>(
            "trust-state.json",
            cancellationToken).ConfigureAwait(false);
        appliedAnchor = SelectManifestAnchor(appliedAnchor, persistedTrust?.ToManifestAnchor());
        var priorApplied = await ReadOptionalAppliedStateAsync(
            files,
            ManifestArtifactApplier.PreviousAppliedStatePath,
            cancellationToken).ConfigureAwait(false);
        var durableReady = await ReadOptionalReadyStateAsync(files, cancellationToken).ConfigureAwait(false);
        var previousApplied = WorkerRuntimeFactory.SelectReadyAppliedState(
            currentApplied,
            priorApplied,
            durableReady,
            persistedTrust,
            request,
            pins,
            clock.GetUtcNow());
        var publishedDelivery = await client.FetchManifestAsync(cancellationToken).ConfigureAwait(false);
        var published = await SignedManifestVerifier.VerifyAsync(
            publishedDelivery,
            pins,
            verifier,
            appliedAnchor,
            persistedTrust?.ToAnchor(),
            clock.GetUtcNow(),
            "windows",
            cancellationToken).ConfigureAwait(false);
        var trustVerifiedAt = clock.GetUtcNow().ToString("O");
        var trustState = CreateTrustState(published, trustVerifiedAt);
        await files.WriteJsonAsync("trust-state.json", trustState, cancellationToken).ConfigureAwait(false);
        // This normalized view is informational only. Trust continues to come
        // exclusively from the verified signed delivery and the explicit root pins.
        await files.WriteJsonAsync(
            "available-manifest.json",
            published.Manifest,
            cancellationToken).ConfigureAwait(false);

        var compatibility = ManifestContractValidator.Evaluate(
            published.Manifest,
            request.WorkerRuntimeVersion);
        if (compatibility.Disposition is ManifestRuntimeDisposition.MinimumWorkerVersionNotMet
            or ManifestRuntimeDisposition.WorkerVersionNotAccepted)
        {
            var reason = compatibility.Reason;
            await InvalidateReadyAsync(
                request,
                published,
                reason,
                cancellationToken).ConfigureAwait(false);
            throw Error(
                reason,
                "The installed worker cannot implement the signed content contract.");
        }

        var manifestChanged = previousApplied?.ManifestHash != published.Manifest.Hash;
        var contentChanged = previousApplied is null
            || previousApplied.ContentContractHash != published.ContentContractHash;
        if (!manifestChanged && contentChanged)
        {
            await InvalidateReadyAsync(
                request,
                published,
                "applied-content-contract-mismatch",
                cancellationToken).ConfigureAwait(false);
            throw Error(
                "applied-content-contract-mismatch",
                "The applied content contract does not match its signed manifest hash.");
        }

        if (manifestChanged && contentChanged)
        {
            // A content-changing transition revokes the old readiness before
            // any staging or remote attestation can fail. Compatible metadata
            // refreshes deliberately keep the previous readiness untouched.
            await InvalidateReadyAsync(
                request,
                published,
                "manifest-content-update-required",
                cancellationToken).ConfigureAwait(false);
        }

        if (manifestChanged && contentChanged && request.ActiveAssignments > 0)
        {
            throw Error(
                "manifest-content-update-draining",
                "Active assignments must finish before applying a content-changing manifest.");
        }

        var bootstrap = await client.BootstrapAsync(
            new BootstrapRequestContract
            {
                NodeId = request.NodeId,
                WorkerKeyId = request.WorkerKeyId,
                Platform = "windows",
                Architecture = request.Architecture,
                Hostname = request.Hostname,
                RequestedCapacity = 0,
            },
            request.BootstrapRequestId,
            cancellationToken).ConfigureAwait(false);
        ValidateBootstrapResponse(bootstrap, published, clock.GetUtcNow());

        var sessionManifest = await SignedManifestVerifier.VerifyAsync(
            bootstrap.Manifest,
            pins,
            verifier,
            SelectManifestAnchor(appliedAnchor, trustState.ToManifestAnchor()),
            trustState.ToAnchor(),
            clock.GetUtcNow(),
            "windows",
            cancellationToken).ConfigureAwait(false);
        if (sessionManifest.Manifest.Hash != published.Manifest.Hash
            || sessionManifest.Manifest.Sequence != published.Manifest.Sequence)
        {
            throw Error(
                "bootstrap-manifest-changed",
                "Bootstrap returned a manifest different from the published manifest.");
        }

        if (sessionManifest.ContentContractHash != published.ContentContractHash)
        {
            throw Error(
                "bootstrap-content-contract-changed",
                "Bootstrap returned a different generated-content contract.");
        }

        trustVerifiedAt = clock.GetUtcNow().ToString("O");
        trustState = CreateTrustState(sessionManifest, trustVerifiedAt);
        await files.WriteJsonAsync("trust-state.json", trustState, cancellationToken).ConfigureAwait(false);

        var applied = await applier.ApplyAsync(
            sessionManifest,
            previousApplied,
            new ManifestApplyContext(
                request.NodeId,
                request.WorkerKeyId,
                request.WorkerRuntimeVersion),
            cancellationToken).ConfigureAwait(false);
        var manifest = sessionManifest.Manifest;
        AttestationResponseContract attestation;
        try
        {
            attestation = await client.AttestAsync(
                bootstrap.BootstrapSessionId,
                new AttestationRequestContract
                {
                    NodeId = request.NodeId,
                    WorkerKeyId = request.WorkerKeyId,
                    ManifestSequence = manifest.Sequence,
                    ManifestHash = manifest.Hash,
                    ContentContractHash = sessionManifest.ContentContractHash,
                    Challenge = bootstrap.Challenge,
                    WorkerRuntimeVersion = request.WorkerRuntimeVersion,
                    PolicyHash = manifest.Editorial.PolicyHash,
                    AdaptiveWorkPolicyHash = ManifestPolicyValidator.AdaptiveWorkPolicyHash(
                        manifest.AdaptiveWorkPolicy!.Value),
                    RootKeyId = sessionManifest.RootKeyId,
                    ReleaseKeyId = sessionManifest.ReleaseKeyId,
                    TrustVerifiedAt = trustVerifiedAt,
                    PromptConfigHash = manifest.Editorial.PromptConfigHash,
                    PipelineVersion = manifest.Editorial.PipelineVersion,
                    Provider = manifest.Engine.Provider,
                    EngineAdapter = manifest.Engine.Adapter,
                    EngineAdapterVersion = manifest.Engine.AdapterVersion,
                    Model = manifest.Engine.Model,
                    ModelDigest = NormalizeDigest(manifest.Engine.ModelDigest),
                    Protocol = manifest.Engine.Protocol,
                    Checks = applied.Checks,
                    UpdateReceipt = applied.UpdateReceipt,
                },
                request.AttestationRequestId,
                cancellationToken).ConfigureAwait(false);
            ValidateAttestationResponse(
                attestation,
                request,
                sessionManifest,
                clock.GetUtcNow());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (!WorkerRuntimeFactory.IsTransientBootstrapFailure(error))
        {
            // A permanent rejection must revoke the predecessor before the
            // failure escapes. Otherwise a restart followed by an offline
            // bootstrap could mistake the old ready commit for a transiently
            // deferred compatible refresh.
            await InvalidateReadyAsync(
                request,
                sessionManifest,
                "attestation-permanent-failure",
                CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        var capacityPolicyHash = ManifestPolicyValidator.CapacityPolicyHash(manifest.CapacityPolicy);
        var adaptivePolicyHash = ManifestPolicyValidator.AdaptiveWorkPolicyHash(
            manifest.AdaptiveWorkPolicy.Value);
        var observedAt = clock.GetUtcNow().ToString("O");
        var capacityState = new WorkerCapacityStateRecord
        {
            Schema = "hch.worker-capacity/v1",
            SchemaVersion = 1,
            ObservedAt = observedAt,
            NodeId = request.NodeId,
            WorkerKeyId = request.WorkerKeyId,
            ManifestSequence = manifest.Sequence,
            ManifestHash = manifest.Hash,
            CapacityPolicyHash = capacityPolicyHash,
            AlgorithmVersion = RequiredString(manifest.CapacityPolicy, "algorithmVersion"),
            RequestedCapacity = attestation.Capacity.RequestedCapacity,
            GrantedCapacity = attestation.Capacity.GrantedCapacity,
            CapacityClass = attestation.Capacity.CapacityClass,
            Reason = attestation.Capacity.Reason,
            GrantedUntil = attestation.Capacity.GrantedUntil,
            ActiveAssignments = 0,
            AvailableSlots = 0,
            Source = "attestation",
        };
        await files.WriteJsonAsync("capacity.json", capacityState, cancellationToken).ConfigureAwait(false);

        var readyUntil = attestation.ReadyUntil!;
        var ready = new WorkerReadyStateRecord
        {
            SchemaVersion = 1,
            Ready = true,
            NodeId = request.NodeId,
            KeyId = request.WorkerKeyId,
            ManifestSequence = manifest.Sequence,
            ManifestHash = manifest.Hash,
            ContentContractHash = sessionManifest.ContentContractHash,
            PolicyHash = manifest.Editorial.PolicyHash,
            Provider = manifest.Engine.Provider,
            EngineAdapter = manifest.Engine.Adapter,
            EngineAdapterVersion = manifest.Engine.AdapterVersion,
            WorkerRuntimeVersion = request.WorkerRuntimeVersion,
            RuntimeProfileHash = applied.RuntimeProfile.RuntimeProfileHash,
            CapacityPolicyHash = capacityPolicyHash,
            AdaptiveWorkPolicyHash = adaptivePolicyHash,
            RequestedCapacity = 0,
            GrantedCapacity = 0,
            CapacityClass = attestation.Capacity.CapacityClass,
            CapacityReason = attestation.Capacity.Reason,
            CapacityGrantedUntil = attestation.Capacity.GrantedUntil,
            BootstrapSessionId = bootstrap.BootstrapSessionId,
            ReadyUntil = readyUntil,
            AttestedAt = observedAt,
            TrustVerifiedAt = trustVerifiedAt,
        };
        // Ready is the final commit marker. No claim loop is started here.
        await files.WriteJsonAsync("ready.json", ready, cancellationToken).ConfigureAwait(false);
        return new BootstrapCoordinatorResult(
            request.NodeId,
            request.WorkerKeyId,
            "draining",
            manifest.Sequence,
            manifest.Hash,
            sessionManifest.ContentContractHash,
            readyUntil,
            WorkStarted: false,
            applied.MetadataOnly);
    }

    private static async Task<AppliedManifestState?> ReadOptionalAppliedStateAsync(
        AtomicFileStore files,
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            var state = await files.ReadJsonAsync<AppliedManifestState>(path, cancellationToken)
                .ConfigureAwait(false);
            if (state is not null)
            {
                _ = AppliedRuntimeContract.FromAppliedState(state);
            }

            return state;
        }
        catch (Exception error) when (
            error is JsonException or ProtocolValidationException or WorkerServiceException or IOException)
        {
            return null;
        }
    }

    private static AppliedManifestAnchor? SelectManifestAnchor(
        AppliedManifestAnchor? applied,
        AppliedManifestAnchor? trusted)
    {
        if (applied is null)
        {
            return trusted;
        }

        if (trusted is null)
        {
            return applied;
        }

        if (applied.ManifestSequence == trusted.ManifestSequence)
        {
            if (!string.Equals(applied.ManifestHash, trusted.ManifestHash, StringComparison.Ordinal))
            {
                throw Error(
                    "manifest-equivocation-refused",
                    "The applied and trusted manifest anchors disagree at the same sequence.");
            }

            if (applied.ContentContractHash is not null
                && trusted.ContentContractHash is not null
                && !string.Equals(
                    applied.ContentContractHash,
                    trusted.ContentContractHash,
                    StringComparison.Ordinal))
            {
                throw Error(
                    "manifest-trust-state-invalid",
                    "The applied and trusted manifest anchors disagree on the content contract.");
            }

            return trusted;
        }

        return trusted.ManifestSequence > applied.ManifestSequence ? trusted : applied;
    }

    private static async Task<WorkerReadyStateRecord?> ReadOptionalReadyStateAsync(
        AtomicFileStore files,
        CancellationToken cancellationToken)
    {
        try
        {
            return await files.ReadJsonAsync<WorkerReadyStateRecord>("ready.json", cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException or IOException)
        {
            return null;
        }
    }

    private Task InvalidateReadyAsync(
        BootstrapCoordinatorRequest request,
        VerifiedManifestDelivery published,
        string reason,
        CancellationToken cancellationToken) => files.WriteJsonAsync(
            "ready.json",
            new
            {
                schemaVersion = 1,
                ready = false,
                nodeId = request.NodeId,
                keyId = request.WorkerKeyId,
                targetManifestHash = published.Manifest.Hash,
                targetContentContractHash = published.ContentContractHash,
                invalidatedAt = clock.GetUtcNow().ToString("O"),
                reason,
            },
            cancellationToken);

    private static ManifestTrustStateRecord CreateTrustState(
        VerifiedManifestDelivery verified,
        string verifiedAt) => new()
        {
            Schema = "hch.worker-trust-state/v1",
            SchemaVersion = 1,
            RootKeyId = verified.RootKeyId,
            RootFingerprint = verified.RootFingerprint,
            ReleaseKeyId = verified.ReleaseKeyId,
            DelegationSequence = verified.DelegationSequence,
            DelegationHash = verified.DelegationHash,
            ManifestSequence = verified.Manifest.Sequence,
            ManifestHash = verified.Manifest.Hash,
            ContentContractHash = verified.ContentContractHash,
            PolicyHash = verified.Manifest.Editorial.PolicyHash,
            VerifiedAt = verifiedAt,
        };

    private static void ValidateBootstrapResponse(
        BootstrapResponseContract response,
        VerifiedManifestDelivery manifest,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!Guid.TryParseExact(response.BootstrapSessionId, "D", out var sessionId)
            || sessionId == Guid.Empty
            || response.State is not ("awaiting-attestation" or "attested")
            || response.Challenge.Length is < 16 or > 512
            || response.ManifestHash != manifest.Manifest.Hash
            || response.ManifestSequence != manifest.Manifest.Sequence
            || response.RequestedCapacity != 0
            || response.WorkEnabled
            || response.AttestationUrl
                != $"/api/editorial/orchestrator/bootstrap/{response.BootstrapSessionId}/attest")
        {
            throw Error("bootstrap-response-invalid", "The bootstrap response is incompatible.");
        }

        var expires = ProtocolTime.ParseTimestamp(response.ExpiresAt, "bootstrap.expiresAt");
        if (expires <= now
            || JcsCanonicalizer.Canonicalize(response.CapacityPolicy.GetRawText())
                != JcsCanonicalizer.Canonicalize(manifest.Manifest.CapacityPolicy.GetRawText())
            || manifest.Manifest.AdaptiveWorkPolicy is not { } adaptivePolicy
            || JcsCanonicalizer.Canonicalize(response.AdaptiveWorkPolicy.GetRawText())
                != JcsCanonicalizer.Canonicalize(adaptivePolicy.GetRawText()))
        {
            throw Error("bootstrap-response-invalid", "The bootstrap policies or validity are incompatible.");
        }
    }

    private static void ValidateAttestationResponse(
        AttestationResponseContract response,
        BootstrapCoordinatorRequest request,
        VerifiedManifestDelivery verified,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(response);
        var manifest = verified.Manifest;
        if (response.NodeId != request.NodeId
            || response.WorkerKeyId != request.WorkerKeyId
            || !response.Compatible
            || response.State != "draining"
            || response.ManifestSequence != manifest.Sequence
            || response.ManifestHash != manifest.Hash
            || response.ContentContractHash != verified.ContentContractHash
            || response.ReadyUntil is null)
        {
            throw Error("attestation-response-invalid", "Attestation did not make the paused worker ready.");
        }

        var readyUntil = ProtocolTime.ParseTimestamp(response.ReadyUntil, "attestation.readyUntil");
        var serverTime = ProtocolTime.ParseTimestamp(response.ServerTime, "attestation.serverTime");
        if (readyUntil <= now || serverTime < now.AddMinutes(-5) || serverTime > now.AddMinutes(5))
        {
            throw Error("attestation-response-invalid", "Attestation timestamps are invalid.");
        }

        ValidateDrainingCapacityGrant(
            response.Capacity,
            manifest.CapacityPolicy,
            request.NodeId,
            serverTime,
            now);
    }

    private static void ValidateDrainingCapacityGrant(
        AttestedCapacityGrantContract grant,
        JsonElement policy,
        string nodeId,
        DateTimeOffset serverTime,
        DateTimeOffset now)
    {
        ManifestPolicyValidator.ValidateCapacityPolicy(policy);
        var capacityClass = ResolveCapacityClass(policy, nodeId);
        var grantTtlSeconds = RequiredInt(policy, "grantTtlSeconds");
        var grantedUntil = ProtocolTime.ParseTimestamp(grant.GrantedUntil, "capacity.grantedUntil");
        if (grant.RequestedCapacity != 0 || grant.GrantedCapacity != 0
            || grant.CapacityClass != capacityClass
            || string.IsNullOrWhiteSpace(grant.Reason)
            || !grant.Reason.Contains("drain-requested", StringComparison.Ordinal)
            || grantedUntil <= now
            || grantedUntil <= serverTime
            || grantedUntil > serverTime.AddSeconds(grantTtlSeconds + 5))
        {
            throw Error("capacity-grant-invalid", "The attested drain capacity grant is invalid.");
        }
    }

    private static string ResolveCapacityClass(JsonElement policy, string nodeId)
    {
        var nodeClasses = policy.GetProperty("nodeClasses");
        if (nodeClasses.TryGetProperty(nodeId, out var nodeClass)
            && nodeClass.ValueKind == JsonValueKind.String)
        {
            return nodeClass.GetString()!;
        }

        return policy.GetProperty("platformClasses").GetProperty("windows").GetString()
            ?? throw Error("capacity-policy-invalid", "Windows has no capacity class.");
    }

    private static void ValidateRequest(BootstrapCoordinatorRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.NodeId) || request.NodeId.Length > 128
            || string.IsNullOrWhiteSpace(request.WorkerKeyId) || request.WorkerKeyId.Length > 256
            || string.IsNullOrWhiteSpace(request.Architecture) || request.Architecture.Length > 64
            || string.IsNullOrWhiteSpace(request.Hostname) || request.Hostname.Length > 160
            || request.ActiveAssignments is < 0 or > 64
            || !Guid.TryParseExact(request.BootstrapRequestId, "D", out var bootstrapRequestId)
            || bootstrapRequestId == Guid.Empty
            || !Guid.TryParseExact(request.AttestationRequestId, "D", out var attestationRequestId)
            || attestationRequestId == Guid.Empty)
        {
            throw new ArgumentException("bootstrap-coordinator-request-invalid", nameof(request));
        }

        _ = SemanticVersion.Parse(request.WorkerRuntimeVersion);
    }

    private static string RequiredString(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw Error("capacity-policy-invalid", $"The capacity policy {name} is invalid.");
        }

        return property.GetString()!;
    }

    private static int RequiredInt(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) || !property.TryGetInt32(out var result))
        {
            throw Error("capacity-policy-invalid", $"The capacity policy {name} is invalid.");
        }

        return result;
    }

    private static string NormalizeDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value[7..].ToLowerInvariant()
            : value.ToLowerInvariant();

    private static WorkerServiceException Error(string code, string message) => new(code, message);
}
