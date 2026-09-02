using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hch.Worker.Core;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class OperationalEnrollmentTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 15, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RequestIdAndHashMatchTheNodeHchRfc8785Contract()
    {
        byte[] rawPublicKey = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte[] subjectPublicKeyInfo = Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(rawPublicKey);
        try
        {
            string publicKeyPem = Ed25519KeyEncoding.EncodePublicKeyPem(subjectPublicKeyInfo).Trim();
            var request = OperationalEnrollmentContract.CreateChallengeRequest(
                "windows-test",
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                publicKeyPem);

            Assert.Equal(
                "enroll-v4-5323d570fff1348679b5ebb1e7f6386a8af32787baa169c8364cbf26ed876159",
                request.RequestId);
            Assert.Equal(
                "18ea63a24461f7fdbc6b0f12027f30ac63a47d42e8cf34ff357c1424b4abb955",
                OperationalEnrollmentContract.ComputeRequestHash(request));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawPublicKey);
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }
    }

    [Fact]
    public async Task CoordinatorSignsProofPersistsOnlyPublicReceiptAndReplaysLocally()
    {
        string stateRoot = Path.Combine(Path.GetTempPath(), "hch-enrollment-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        using var identity = Ed25519Identity.Generate();
        string ownerKeyId = "11111111-2222-4333-8444-555555555555";
        string ownerFingerprint = Fingerprint(Enumerable.Repeat((byte)0x5a, 32).ToArray());
        const string token = "hch_enroll_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789_-";
        var handler = new EnrollmentHandler(identity, ownerKeyId, ownerFingerprint, token);
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "windows-test",
            identity.Fingerprint) with
        {
            StateRoot = stateRoot,
        };
        var coordinator = new OperationalEnrollmentCoordinator(
            configuration,
            identity,
            new AtomicFileStore(stateRoot),
            http,
            new FixedTimeProvider(Now));
        byte[] tokenBytes = Encoding.ASCII.GetBytes(token);

        try
        {
            OperationalEnrollmentReceipt first = await coordinator.CompleteAsync(
                tokenBytes,
                ownerKeyId,
                ownerFingerprint);
            OperationalEnrollmentReceipt replay = await coordinator.CompleteAsync(
                tokenBytes,
                ownerKeyId,
                ownerFingerprint);

            Assert.Equal(first, replay);
            Assert.Equal("active", first.Status);
            Assert.Equal(identity.Fingerprint, first.WorkerPublicKeyFingerprint);
            Assert.Equal(2, handler.RequestCount);
            Assert.True(handler.ProofVerified);
            string receipt = await File.ReadAllTextAsync(
                Path.Combine(stateRoot, OperationalEnrollmentCoordinator.ReceiptPath));
            Assert.DoesNotContain("hch_enroll_", receipt, StringComparison.Ordinal);
            Assert.DoesNotContain(token, receipt, StringComparison.Ordinal);
            Assert.DoesNotContain("private", receipt, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(ownerKeyId, receipt, StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
            Directory.Delete(stateRoot, recursive: true);
        }
    }

    [Fact]
    public async Task LostCompletionResponseIsReconciledFromPublicPendingJournalWithoutNewChallenge()
    {
        string stateRoot = Path.Combine(Path.GetTempPath(), "hch-enrollment-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        using var identity = Ed25519Identity.Generate();
        string ownerKeyId = "11111111-2222-4333-8444-555555555555";
        string ownerFingerprint = Fingerprint(Enumerable.Repeat((byte)0x6b, 32).ToArray());
        const string token = "hch_enroll_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789_-";
        var handler = new EnrollmentHandler(identity, ownerKeyId, ownerFingerprint, token)
        {
            LostCompletionResponsesRemaining = 2,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "windows-test",
            identity.Fingerprint) with
        {
            StateRoot = stateRoot,
        };
        var files = new AtomicFileStore(stateRoot);
        byte[] tokenBytes = Encoding.ASCII.GetBytes(token);

        try
        {
            var firstRuntime = new OperationalEnrollmentCoordinator(
                configuration,
                identity,
                files,
                http,
                new FixedTimeProvider(Now));
            OperationalEnrollmentException lost = await Assert.ThrowsAsync<OperationalEnrollmentException>(
                () => firstRuntime.CompleteAsync(tokenBytes, ownerKeyId, ownerFingerprint));
            Assert.Equal("enrollment-network-unavailable", lost.Code);
            Assert.True(File.Exists(files.Resolve(OperationalEnrollmentCoordinator.PendingPath)));
            string pending = await File.ReadAllTextAsync(
                files.Resolve(OperationalEnrollmentCoordinator.PendingPath));
            Assert.DoesNotContain(token, pending, StringComparison.Ordinal);

            var restartedRuntime = new OperationalEnrollmentCoordinator(
                configuration,
                identity,
                files,
                http,
                new FixedTimeProvider(Now));
            OperationalEnrollmentReceipt receipt = await restartedRuntime.CompleteAsync(
                tokenBytes,
                ownerKeyId,
                ownerFingerprint);

            Assert.Equal("active", receipt.Status);
            Assert.Equal(1, handler.ChallengeRequestCount);
            Assert.Equal(3, handler.CompletionRequestCount);
            Assert.False(File.Exists(files.Resolve(OperationalEnrollmentCoordinator.PendingPath)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
            Directory.Delete(stateRoot, recursive: true);
        }
    }

    [Fact]
    public async Task AuthenticatedIpcEnrollmentActivatesRuntimePausedAndRequiresExplicitStart()
    {
        string stateRoot = Path.Combine(Path.GetTempPath(), "hch-enrollment-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        using var identity = Ed25519Identity.Generate();
        string ownerKeyId = "11111111-2222-4333-8444-555555555555";
        string ownerFingerprint = Fingerprint(Enumerable.Repeat((byte)0x7c, 32).ToArray());
        const string token = "hch_enroll_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789_-";
        var handler = new EnrollmentHandler(identity, ownerKeyId, ownerFingerprint, token);
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "windows-test",
            identity.Fingerprint) with
        {
            StateRoot = stateRoot,
        };
        var files = new AtomicFileStore(stateRoot);
        var enrollment = new OperationalEnrollmentCoordinator(
            configuration,
            identity,
            files,
            http,
            new FixedTimeProvider(Now));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 3);
        await using var schedulerHost = new WorkerSchedulerHost();
        var activator = new PostEnrollmentRuntimeActivator(
            control,
            schedulerHost,
            _ => Task.FromResult(new ConcurrentJobScheduler(
                control,
                new EmptyJobSource(),
                new UnusedJobExecutor(),
                new UnusedJobReporter())));
        var controller = new WorkerOperationalController(control, schedulerHost);
        var pipe = new WorkerControlPipeServer(
            configuration,
            controller,
            () => throw new InvalidOperationException("Snapshot is not used by this command."),
            new SanitizedLogStore(stateRoot, new FixedTimeProvider(Now)),
            enrollment,
            activator,
            new FixedTimeProvider(Now));
        byte[] tokenBytes = Encoding.ASCII.GetBytes(token);

        try
        {
            var request = IpcRequest.Create(
                IpcCommand.SubmitEnrollmentToken,
                new EnrollmentTokenPayload(tokenBytes, ownerKeyId, ownerFingerprint),
                Now);

            var response = await pipe.DispatchAsync(request, CancellationToken.None);

            Assert.True(response.Success);
            var completed = response.Payload.Deserialize<OperationalEnrollmentCompletedPayload>(IpcJson.Options);
            Assert.NotNull(completed);
            Assert.Equal("active", completed.Status);
            Assert.NotNull(schedulerHost.Current);
            Assert.True(control.Snapshot.Ready);
            Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);
            Assert.False(control.Snapshot.AcceptingClaims);
            var started = await controller.StartAsync();
            Assert.Equal(WorkerOperationalState.Running, started.State);
            Assert.True(started.AcceptingClaims);
            Assert.Equal(3, started.MaxConcurrentJobs);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
            Directory.Delete(stateRoot, recursive: true);
        }
    }

    [Fact]
    public void EnrollmentTokenPayloadCanBeClearedAfterAuthenticatedIpcUse()
    {
        byte[] secret = Encoding.ASCII.GetBytes(
            "hch_enroll_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789_-");
        var payload = new Hch.Worker.IPC.Contracts.EnrollmentTokenPayload(
            secret,
            "11111111-2222-4333-8444-555555555555",
            Fingerprint(Enumerable.Repeat((byte)0x33, 32).ToArray()));

        payload.Clear();

        Assert.All(secret, static value => Assert.Equal(0, value));
    }

    private static string Fingerprint(byte[] value) =>
        "SHA256:" + Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 0 => string.Empty, 2 => "==", 3 => "=", _ => "!" };
        return Convert.FromBase64String(padded);
    }

    private static HttpResponseMessage Json<T>(T value, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new ByteArrayContent(ProtocolJson.SerializeCanonicalToUtf8(value))
        {
            Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") },
        },
    };

    private sealed class EmptyJobSource : IWorkerJobSource
    {
        public Task<IReadOnlyList<WorkerJob>> ClaimAsync(
            int requestedCount,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<WorkerJob>>([]);
    }

    private sealed class UnusedJobExecutor : IWorkerJobExecutor
    {
        public Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The empty source cannot return a job.");
    }

    private sealed class UnusedJobReporter : IWorkerJobReporter
    {
        public Task CompleteAsync(
            WorkerJob job,
            JobExecutionResult result,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The empty source cannot complete a job.");

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The empty source cannot fail a job.");
    }

    private sealed class EnrollmentHandler(
        Ed25519Identity identity,
        string ownerKeyId,
        string ownerFingerprint,
        string expectedToken) : HttpMessageHandler
    {
        private OperationalEnrollmentChallengeRequest? challengeRequest;
        private OperationalEnrollmentChallengeResponse? challengeResponse;

        public int RequestCount { get; private set; }
        public int ChallengeRequestCount { get; private set; }
        public int CompletionRequestCount { get; private set; }
        public bool ProofVerified { get; private set; }
        public int LostCompletionResponsesRemaining { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal(expectedToken, request.Headers.Authorization?.Parameter);
            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            try
            {
                if (request.RequestUri!.AbsolutePath == OperationalEnrollmentContract.ChallengePath)
                {
                    ChallengeRequestCount++;
                    challengeRequest = ProtocolJson.Deserialize<OperationalEnrollmentChallengeRequest>(body);
                    challengeResponse = CreateChallenge(challengeRequest);
                    return Json(challengeResponse);
                }

                Assert.Equal(OperationalEnrollmentContract.EnrollmentPath, request.RequestUri!.AbsolutePath);
                CompletionRequestCount++;
                Assert.NotNull(challengeRequest);
                Assert.NotNull(challengeResponse);
                var enrollment = ProtocolJson.Deserialize<OperationalEnrollmentRequest>(body);
                Assert.Equal(challengeRequest.RequestId, enrollment.RequestId);
                Assert.Equal(challengeResponse.ChallengeId, enrollment.ChallengeId);
                Assert.Equal(challengeResponse.Challenge, enrollment.Challenge);

                byte[] canonicalProof = ProtocolJson.SerializeCanonicalToUtf8(challengeResponse.Proof);
                byte[] signature = DecodeBase64Url(enrollment.ProofSignature);
                byte[] publicKey = identity.ExportSubjectPublicKeyInfo();
                try
                {
                    ProofVerified = await identity.VerifyAsync(
                        publicKey,
                        canonicalProof,
                        signature,
                        cancellationToken);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(canonicalProof);
                    CryptographicOperations.ZeroMemory(signature);
                    CryptographicOperations.ZeroMemory(publicKey);
                }

                Assert.True(ProofVerified);
                if (LostCompletionResponsesRemaining > 0)
                {
                    LostCompletionResponsesRemaining--;
                    throw new HttpRequestException("simulated-response-loss");
                }

                return Json(new OperationalEnrollmentResponse(
                    challengeRequest.NodeId,
                    challengeRequest.KeyId,
                    identity.Fingerprint,
                    "active",
                    Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
                    OperationalEnrollmentContract.Protocol,
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "owner@hubtech.online",
                    ownerKeyId,
                    ownerFingerprint),
                    HttpStatusCode.Created);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }

        private OperationalEnrollmentChallengeResponse CreateChallenge(
            OperationalEnrollmentChallengeRequest request)
        {
            string challenge = Convert.ToBase64String(Enumerable.Repeat((byte)0x44, 32).ToArray())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            string expiresAt = Now.AddMinutes(5).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
            var proof = new OperationalEnrollmentProof(
                challenge,
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                OperationalEnrollmentContract.ProofDomain,
                expiresAt,
                ownerFingerprint,
                ownerKeyId,
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                OperationalEnrollmentContract.Protocol,
                OperationalEnrollmentContract.ComputeRequestHash(request),
                request.RequestId,
                "ffffffff-1111-4222-8333-444444444444",
                request.KeyId,
                request.NodeId,
                identity.Fingerprint,
                OperationalEnrollmentContract.RuntimeVersion);
            return new OperationalEnrollmentChallengeResponse(
                OperationalEnrollmentContract.Protocol,
                proof.ChallengeId,
                proof.Challenge,
                proof.ExpiresAt,
                proof,
                new OperationalEnrollmentSignatureProfile("Ed25519", "base64url", "RFC8785"));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
