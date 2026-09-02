using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Tray;
using Hch.Worker.Windows;

namespace Hch.Worker.Tests;

public sealed class TraySecurityTests
{
    [Fact]
    public async Task StalledServerAttestationUsesTheOperationDeadlineAndSendsNoFrame()
    {
        string nodeId = $"attestation-stalled-{Guid.NewGuid():N}";
        string pipeName = IpcProtocol.PipeName(nodeId);
        await using var peer = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var releaseAuthentication = new ManualResetEventSlim();
        var authenticator = new BlockingAuthenticator(releaseAuthentication);
        var client = new NamedPipeWorkerClient(
            nodeId,
            authenticator,
            operationTimeout: TimeSpan.FromMilliseconds(250));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[] observed = new byte[1];
        Task server = Task.Run(async () =>
        {
            await peer.WaitForConnectionAsync(globalTimeout.Token);
            connected.SetResult();
            int count = await peer.ReadAsync(observed, globalTimeout.Token);
            Assert.Equal(0, count);
        }, globalTimeout.Token);

        try
        {
            Task<WorkerSnapshotPayload> request = client.GetSnapshotAsync(globalTimeout.Token);
            await connected.Task.WaitAsync(globalTimeout.Token);
            TimeoutException error = await Assert.ThrowsAsync<TimeoutException>(() => request);
            Assert.Equal("ipc-operation-timeout", error.Message);
            Assert.Equal(1, authenticator.Calls);
            await server;
            Assert.Equal(0, observed[0]);
        }
        finally
        {
            releaseAuthentication.Set();
            CryptographicOperations.ZeroMemory(observed);
        }
    }

    [Fact]
    public async Task ConnectedPeerThatNeverRepliesHitsTheFastCommandResponseDeadline()
    {
        string nodeId = $"stalled-{Guid.NewGuid():N}";
        string pipeName = IpcProtocol.PipeName(nodeId);
        await using var stalledPeer = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(
            nodeId,
            new AllowingAuthenticator(),
            operationTimeout: TimeSpan.FromMilliseconds(250));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releasePeer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task server = Task.Run(async () =>
        {
            await stalledPeer.WaitForConnectionAsync(globalTimeout.Token);
            connected.SetResult();
            await releasePeer.Task.WaitAsync(globalTimeout.Token);
        }, globalTimeout.Token);

        try
        {
            Task<WorkerSnapshotPayload> request = client.GetSnapshotAsync(globalTimeout.Token);
            await connected.Task.WaitAsync(globalTimeout.Token);
            TimeoutException error = await Assert.ThrowsAsync<TimeoutException>(() => request);
            Assert.Equal("ipc-operation-timeout", error.Message);
        }
        finally
        {
            releasePeer.TrySetResult();
            await server;
        }
    }

    [Fact]
    public async Task StopCanCompleteAfterTheFailFastDeadlineButBeforeItsCommandDeadline()
    {
        string nodeId = $"stop-long-{Guid.NewGuid():N}";
        await using var peer = new NamedPipeServerStream(
            IpcProtocol.PipeName(nodeId),
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(
            nodeId,
            new AllowingAuthenticator(),
            operationTimeout: TimeSpan.FromMilliseconds(250),
            longRunningOperationTimeout: TimeSpan.FromSeconds(2));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task server = Task.Run(async () =>
        {
            await peer.WaitForConnectionAsync(globalTimeout.Token);
            IpcRequest request = await IpcFraming.ReadAsync<IpcRequest>(peer, globalTimeout.Token);
            Assert.Equal(IpcCommand.Stop, request.Command);
            await Task.Delay(TimeSpan.FromMilliseconds(500), globalTimeout.Token);
            await IpcFraming.WriteAsync(
                peer,
                IpcResponse.Ok(
                    request.RequestId,
                    new CommandAcceptedPayload("Stopped", DateTimeOffset.UtcNow)),
                globalTimeout.Token);
        }, globalTimeout.Token);

        CommandAcceptedPayload response = await client.StopAsync(globalTimeout.Token);

        Assert.Equal("Stopped", response.State);
        await server;
    }

    [Fact]
    public async Task EnrollmentCanCompleteAfterTheFailFastDeadlineButBeforeItsCommandDeadline()
    {
        string nodeId = $"enrollment-long-{Guid.NewGuid():N}";
        await using var peer = new NamedPipeServerStream(
            IpcProtocol.PipeName(nodeId),
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(
            nodeId,
            new AllowingAuthenticator(),
            operationTimeout: TimeSpan.FromMilliseconds(250),
            longRunningOperationTimeout: TimeSpan.FromSeconds(2));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        byte[] token = RandomNumberGenerator.GetBytes(32);
        try
        {
            Task server = Task.Run(async () =>
            {
                await peer.WaitForConnectionAsync(globalTimeout.Token);
                IpcRequest request = await IpcFraming.ReadAsync<IpcRequest>(peer, globalTimeout.Token);
                Assert.Equal(IpcCommand.SubmitEnrollmentToken, request.Command);
                EnrollmentTokenPayload received = IpcValidation.Payload<EnrollmentTokenPayload>(request.Payload);
                try
                {
                    Assert.Equal(token, received.TokenUtf8);
                }
                finally
                {
                    received.Clear();
                }

                await Task.Delay(TimeSpan.FromMilliseconds(500), globalTimeout.Token);
                await IpcFraming.WriteAsync(
                    peer,
                    IpcResponse.Ok(
                        request.RequestId,
                        new OperationalEnrollmentCompletedPayload(
                            OperationalEnrollmentContract.Protocol,
                            nodeId,
                            Guid.NewGuid().ToString("D"),
                            "SHA256:worker",
                            Guid.NewGuid().ToString("D"),
                            "owner@hubtech.online",
                            Guid.NewGuid().ToString("D"),
                            "SHA256:owner",
                            "active",
                            DateTimeOffset.UtcNow)),
                    globalTimeout.Token);
            }, globalTimeout.Token);

            OperationalEnrollmentCompletedPayload response = await client.SubmitEnrollmentTokenAsync(
                token,
                Guid.NewGuid().ToString("D"),
                "SHA256:owner",
                globalTimeout.Token);

            Assert.Equal(nodeId, response.NodeId);
            await server;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
    }

    [Fact]
    public async Task LongRunningCommandStillHasAnEffectiveBoundedDeadline()
    {
        string nodeId = $"stop-deadline-{Guid.NewGuid():N}";
        await using var peer = new NamedPipeServerStream(
            IpcProtocol.PipeName(nodeId),
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(
            nodeId,
            new AllowingAuthenticator(),
            operationTimeout: TimeSpan.FromMilliseconds(100),
            longRunningOperationTimeout: TimeSpan.FromMilliseconds(500));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var requestReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releasePeer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task server = Task.Run(async () =>
        {
            await peer.WaitForConnectionAsync(globalTimeout.Token);
            IpcRequest request = await IpcFraming.ReadAsync<IpcRequest>(peer, globalTimeout.Token);
            Assert.Equal(IpcCommand.Stop, request.Command);
            requestReceived.SetResult();
            await releasePeer.Task.WaitAsync(globalTimeout.Token);
        }, globalTimeout.Token);

        try
        {
            Task<CommandAcceptedPayload> command = client.StopAsync(globalTimeout.Token);
            await requestReceived.Task.WaitAsync(globalTimeout.Token);
            await Task.Delay(TimeSpan.FromMilliseconds(200), globalTimeout.Token);
            Assert.False(command.IsCompleted);
            TimeoutException error = await Assert.ThrowsAsync<TimeoutException>(() => command);
            Assert.Equal("ipc-operation-timeout", error.Message);
        }
        finally
        {
            releasePeer.TrySetResult();
            await server;
        }
    }

    [Fact]
    public async Task PeriodicRefreshSkipsWhileAStalledRefreshOwnsTheSingleFlightGate()
    {
        string nodeId = $"refresh-stalled-{Guid.NewGuid():N}";
        string pipeName = IpcProtocol.PipeName(nodeId);
        await using var stalledPeer = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(
            nodeId,
            new AllowingAuthenticator(),
            operationTimeout: TimeSpan.FromMilliseconds(250));
        var viewModel = new WorkerOptionsViewModel(client);
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releasePeer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task server = Task.Run(async () =>
        {
            await stalledPeer.WaitForConnectionAsync(globalTimeout.Token);
            connected.SetResult();
            await releasePeer.Task.WaitAsync(globalTimeout.Token);
        }, globalTimeout.Token);

        try
        {
            Task<bool> firstRefresh = viewModel.TryRefreshAsync(globalTimeout.Token);
            await connected.Task.WaitAsync(globalTimeout.Token);
            Assert.False(await viewModel.TryRefreshAsync(globalTimeout.Token));
            Assert.True(await firstRefresh.WaitAsync(globalTimeout.Token));
            Assert.Equal("Serviço indisponível. O tray permanece aberto e tentará novamente.", viewModel.StatusMessage);
        }
        finally
        {
            releasePeer.TrySetResult();
            await server;
        }
    }

    [Fact]
    public async Task PipeSquatterReceivesNoFrameWhenServerAttestationFails()
    {
        string nodeId = $"squatter-{Guid.NewGuid():N}";
        string pipeName = IpcProtocol.PipeName(nodeId);
        await using var squatter = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeWorkerClient(nodeId, new RejectingAuthenticator());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        byte[] token = RandomNumberGenerator.GetBytes(32);
        byte[] observed = new byte[1];
        try
        {
            Task server = Task.Run(async () =>
            {
                try
                {
                    await squatter.WaitForConnectionAsync(timeout.Token);
                }
                catch (IOException) when (!squatter.IsConnected)
                {
                    // A rejected peer can close before the server-side connect
                    // completion is delivered. That is an equivalent proof that
                    // no enrollment frame reached the untrusted process.
                    return;
                }

                int count = await squatter.ReadAsync(observed, timeout.Token);
                Assert.Equal(0, count);
            }, timeout.Token);

            UnauthorizedAccessException error = await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                client.SubmitEnrollmentTokenAsync(
                    token,
                    Guid.NewGuid().ToString("D"),
                    "SHA256:test",
                    timeout.Token));
            Assert.Equal("test-pipe-server-untrusted", error.Message);
            await server;
            Assert.Equal(0, observed[0]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
            CryptographicOperations.ZeroMemory(observed);
        }
    }

    [Fact]
    public void ValidatedProofIsReconstructedLocallyAndMatchesTheExpectedDomain()
    {
        using Ed25519Identity identity = Ed25519Identity.Generate();
        ProofFixture fixture = ProofFixture.Create(identity);

        using ValidatedWorkerSshKeyProof validated = WorkerSshKeyProofValidator.Validate(
            fixture.Challenge,
            fixture.Key,
            fixture.Label,
            fixture.Context,
            fixture.Now);

        Assert.Equal(fixture.ExpectedCanonical, validated.CanonicalPayload.ToArray());
        Assert.Equal(identity.Fingerprint, validated.ExpectedFingerprint);
        fixture.Dispose();
    }

    [Fact]
    public void ServerCanonicalPayloadCannotTurnTheUserKeyIntoASigningOracle()
    {
        using Ed25519Identity identity = Ed25519Identity.Generate();
        ProofFixture fixture = ProofFixture.Create(identity);
        try
        {
            string attackerPayload = ProtocolJson.SerializeCanonical(new
            {
                action = "hih.worker-ssh-key.delete",
                keyId = Guid.NewGuid().ToString("D"),
            });
            WorkerSshKeyChallengeEnvelope malicious = fixture.Challenge with
            {
                Proof = fixture.Challenge.Proof with { CanonicalPayload = attackerPayload },
            };

            HihDesktopAuthenticationException error = Assert.Throws<HihDesktopAuthenticationException>(() =>
                WorkerSshKeyProofValidator.Validate(
                    malicious,
                    fixture.Key,
                    fixture.Label,
                    fixture.Context,
                    fixture.Now));
            Assert.Contains("desafio", error.UserMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public void ServerPayloadWithAnotherTenantOrUserIsNeverSigned()
    {
        using Ed25519Identity identity = Ed25519Identity.Generate();
        ProofFixture fixture = ProofFixture.Create(identity);
        try
        {
            WorkerSshKeyRegistrationProof foreign = fixture.Expected with
            {
                TenantId = Guid.NewGuid().ToString("D"),
                UserId = Guid.NewGuid().ToString("D"),
            };
            string canonical = ProtocolJson.SerializeCanonical(foreign);
            WorkerSshKeyChallengeEnvelope malicious = fixture.Challenge with
            {
                Proof = fixture.Challenge.Proof with
                {
                    Payload = JsonSerializer.SerializeToElement(
                        foreign,
                        ProtocolJson.SerializerOptions),
                    CanonicalPayload = canonical,
                },
            };

            Assert.Throws<HihDesktopAuthenticationException>(() =>
                WorkerSshKeyProofValidator.Validate(
                    malicious,
                    fixture.Key,
                    fixture.Label,
                    fixture.Context,
                    fixture.Now));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("algorithm")]
    [InlineData("fingerprint")]
    [InlineData("nonce")]
    public void UncorrelatedChallengeMetadataIsRejected(string mutation)
    {
        using Ed25519Identity identity = Ed25519Identity.Generate();
        ProofFixture fixture = ProofFixture.Create(identity);
        try
        {
            WorkerSshKeyChallengeEnvelope challenge = mutation switch
            {
                "expired" => fixture.Challenge with { ExpiresAt = fixture.Now.AddSeconds(-1) },
                "algorithm" => fixture.Challenge with
                {
                    Proof = fixture.Challenge.Proof with { SignatureAlgorithm = "RSA" },
                },
                "fingerprint" => fixture.Challenge with
                {
                    PublicKey = fixture.Challenge.PublicKey with { Fingerprint = "SHA256:foreign" },
                },
                "nonce" => fixture.Challenge with { Nonce = "not-a-canonical-nonce" },
                _ => throw new InvalidOperationException(),
            };

            Assert.Throws<HihDesktopAuthenticationException>(() =>
                WorkerSshKeyProofValidator.Validate(
                    challenge,
                    fixture.Key,
                    fixture.Label,
                    fixture.Context,
                    fixture.Now));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Fact]
    public async Task GeneratedPrivateKeyHasARestrictedAclAndCanSignOnlyValidatedProof()
    {
        string root = CreatePrivateTestDirectory();
        try
        {
            string privatePath = Path.Combine(root, "keys", "id_ed25519_hch_test");
            UserSshPublicKey key = await UserSshKeyManager.GenerateAsync(privatePath, "test-node");
            var owner = WindowsServiceIdentity.GetCurrentUserSid();
            WindowsAcl.ValidateUserPrivateFile(key.PrivateKeyPath, owner);

            byte[] spki = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(key.PublicKey);
            ProofFixture fixture = ProofFixture.Create(key);
            byte[]? signature = null;
            try
            {
                using ValidatedWorkerSshKeyProof validated = WorkerSshKeyProofValidator.Validate(
                    fixture.Challenge,
                    key,
                    fixture.Label,
                    fixture.Context,
                    fixture.Now);
                signature = await UserSshKeyManager.SignRegistrationProofAsync(
                    key.PrivateKeyPath,
                    validated);
                using Ed25519Identity verifier = Ed25519Identity.Generate();
                Assert.True(await verifier.VerifyAsync(
                    spki,
                    fixture.ExpectedCanonical,
                    signature));
            }
            finally
            {
                fixture.Dispose();
                CryptographicOperations.ZeroMemory(spki);
                if (signature is not null)
                {
                    CryptographicOperations.ZeroMemory(signature);
                }
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GenerationRejectsAWorldWritableCustomParent()
    {
        string root = CreatePrivateTestDirectory();
        string unsafeDirectory = Path.Combine(root, "public-write");
        Directory.CreateDirectory(unsafeDirectory);
        try
        {
            DirectorySecurity security = new DirectoryInfo(unsafeDirectory).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(unsafeDirectory).SetAccessControl(security);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                UserSshKeyManager.GenerateAsync(
                    Path.Combine(unsafeDirectory, "id_ed25519_hch_test"),
                    "test-node"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExistingPrivateKeyWithAnExtraPrincipalIsRejected()
    {
        string root = CreatePrivateTestDirectory();
        try
        {
            string privatePath = Path.Combine(root, "keys", "id_ed25519_hch_test");
            UserSshPublicKey key = await UserSshKeyManager.GenerateAsync(privatePath, "test-node");
            FileSecurity security = new FileInfo(key.PrivateKeyPath).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.ReadData,
                AccessControlType.Allow));
            new FileInfo(key.PrivateKeyPath).SetAccessControl(security);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                UserSshKeyManager.ReadExistingAsync(key.PublicKeyPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreatePrivateTestDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), $"hch-worker-key-tests-{Guid.NewGuid():N}");
        var owner = WindowsServiceIdentity.GetCurrentUserSid();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        foreach (SecurityIdentifier sid in new[] { owner, administrators })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        var directory = new DirectoryInfo(path);
        FileSystemAclExtensions.Create(directory, security);
        return path;
    }

    private sealed class RejectingAuthenticator : ILocalPipeServerAuthenticator
    {
        public void Authenticate(NamedPipeClientStream pipe) =>
            throw new UnauthorizedAccessException("test-pipe-server-untrusted");
    }

    private sealed class AllowingAuthenticator : ILocalPipeServerAuthenticator
    {
        public void Authenticate(NamedPipeClientStream pipe)
        {
        }
    }

    private sealed class BlockingAuthenticator(ManualResetEventSlim release) : ILocalPipeServerAuthenticator
    {
        private int calls;

        public int Calls => Volatile.Read(ref calls);

        public void Authenticate(NamedPipeClientStream pipe)
        {
            Interlocked.Increment(ref calls);
            release.Wait();
        }
    }

    private sealed class ProofFixture : IDisposable
    {
        private ProofFixture(
            DateTimeOffset now,
            string label,
            UserSshPublicKey key,
            WorkerSshKeyProofContext context,
            WorkerSshKeyRegistrationProof expected,
            WorkerSshKeyChallengeEnvelope challenge,
            byte[] expectedCanonical)
        {
            Now = now;
            Label = label;
            Key = key;
            Context = context;
            Expected = expected;
            Challenge = challenge;
            ExpectedCanonical = expectedCanonical;
        }

        public DateTimeOffset Now { get; }
        public string Label { get; }
        public UserSshPublicKey Key { get; }
        public WorkerSshKeyProofContext Context { get; }
        public WorkerSshKeyRegistrationProof Expected { get; }
        public WorkerSshKeyChallengeEnvelope Challenge { get; }
        public byte[] ExpectedCanonical { get; }

        public static ProofFixture Create(Ed25519Identity identity)
        {
            string publicKey = identity.ExportOpenSshPublicKey("hch:test-node");
            return Create(new UserSshPublicKey(
                "ssh-ed25519",
                string.Empty,
                string.Empty,
                identity.Fingerprint,
                publicKey), identity.ExportSubjectPublicKeyInfoPem());
        }

        public static ProofFixture Create(UserSshPublicKey key)
        {
            byte[] spki = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(key.PublicKey);
            try
            {
                return Create(key, Ed25519KeyEncoding.EncodePublicKeyPem(spki));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }

        private static ProofFixture Create(UserSshPublicKey key, string publicKeyPem)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string label = "HCH Worker test-node";
            string userId = Guid.NewGuid().ToString("D");
            string tenantId = Guid.NewGuid().ToString("D");
            string challengeId = Guid.NewGuid().ToString("D");
            byte[] nonceBytes = RandomNumberGenerator.GetBytes(32);
            byte[] spki = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(key.PublicKey);
            try
            {
                string nonce = Base64Url(nonceBytes);
                string normalizedOpenSsh = OpenSshEd25519PublicKey.Encode(spki);
                var context = new WorkerSshKeyProofContext(
                    userId,
                    tenantId,
                    now.AddMinutes(15),
                    120);
                var expected = new WorkerSshKeyRegistrationProof(
                    "hih.worker-ssh-key.register",
                    "Ed25519",
                    challengeId,
                    key.Fingerprint,
                    label,
                    nonce,
                    Base64Url(spki),
                    tenantId,
                    userId);
                byte[] canonical = ProtocolJson.SerializeCanonicalToUtf8(expected);
                var challenge = new WorkerSshKeyChallengeEnvelope(
                    challengeId,
                    nonce,
                    now.AddSeconds(120),
                    new WorkerSshKeyChallengeProof(
                        "RFC8785",
                        "Ed25519",
                        JsonSerializer.SerializeToElement(
                            expected,
                            ProtocolJson.SerializerOptions),
                        Encoding.UTF8.GetString(canonical)),
                    new WorkerSshKeyChallengePublicKey(
                        "Ed25519",
                        key.Fingerprint,
                        publicKeyPem,
                        normalizedOpenSsh));
                return new ProofFixture(now, label, key, context, expected, challenge, canonical);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonceBytes);
                CryptographicOperations.ZeroMemory(spki);
            }
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(ExpectedCanonical);

        private static string Base64Url(ReadOnlySpan<byte> value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
