namespace Hch.Worker.Core;

public enum WorkerOperationalState
{
    NotReady,
    Paused,
    Running,
    Pausing,
    Stopping,
    Stopped,
    Updating,
    Error,
}

public sealed record WorkerControlSnapshot(
    WorkerOperationalState State,
    bool Ready,
    bool AcceptingClaims,
    int MaxConcurrentJobs,
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize,
    int GrantedCapacity,
    bool ClaimAllowed,
    int RecommendedClaimCount,
    DateTimeOffset? ClaimAuthorizationValidUntil,
    string ClaimReason,
    int ReservedJobs,
    int ActiveJobs,
    DateTimeOffset UpdatedAt,
    string UpdatedBy)
{
    public int EffectiveCapacity => AcceptingClaims
        ? Math.Min(MaxConcurrentJobs, GrantedCapacity)
        : 0;

    public int AvailableSlots => Math.Max(0, EffectiveCapacity - ActiveJobs - ReservedJobs);
}

public sealed class WorkerControlState
{
    public const int MinimumParallelism = 0;
    public const int MaximumParallelism = 64;

    private readonly object _sync = new();
    private readonly TimeProvider _timeProvider;
    private WorkerControlSnapshot _snapshot;

    public WorkerControlState(
        int lastNonZeroMaxConcurrentJobs = 1,
        int claimBatchSize = 1,
        TimeProvider? timeProvider = null)
    {
        ValidatePositiveParallelism(lastNonZeroMaxConcurrentJobs, nameof(lastNonZeroMaxConcurrentJobs));
        ValidatePositiveParallelism(claimBatchSize, nameof(claimBatchSize));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _snapshot = new WorkerControlSnapshot(
            WorkerOperationalState.NotReady,
            Ready: false,
            AcceptingClaims: false,
            MaxConcurrentJobs: 0,
            LastNonZeroMaxConcurrentJobs: lastNonZeroMaxConcurrentJobs,
            ClaimBatchSize: claimBatchSize,
            GrantedCapacity: 0,
            ClaimAllowed: false,
            RecommendedClaimCount: 0,
            ClaimAuthorizationValidUntil: null,
            ClaimReason: "heartbeat-unavailable",
            ReservedJobs: 0,
            ActiveJobs: 0,
            UpdatedAt: _timeProvider.GetUtcNow(),
            UpdatedBy: "service-start");
    }

    public event EventHandler<WorkerControlSnapshot>? Changed;

    public WorkerControlSnapshot Snapshot
    {
        get
        {
            lock (_sync)
            {
                return _snapshot;
            }
        }
    }

    public WorkerControlSnapshot MarkReady(string updatedBy = "readiness") =>
        Mutate(current => current with
        {
            State = current.State is WorkerOperationalState.Stopped or WorkerOperationalState.Stopping
                ? current.State
                : WorkerOperationalState.Paused,
            Ready = true,
            AcceptingClaims = false,
            MaxConcurrentJobs = 0,
            GrantedCapacity = 0,
            ClaimAllowed = false,
            RecommendedClaimCount = 0,
            ClaimAuthorizationValidUntil = null,
            ClaimReason = "worker-not-ready",
            UpdatedBy = updatedBy,
        });

    public WorkerControlSnapshot MarkNotReady(string updatedBy = "readiness") =>
        Mutate(current => current with
        {
            State = current.ActiveJobs > 0 ? WorkerOperationalState.Pausing : WorkerOperationalState.NotReady,
            Ready = false,
            AcceptingClaims = false,
            MaxConcurrentJobs = 0,
            GrantedCapacity = 0,
            ClaimAllowed = false,
            RecommendedClaimCount = 0,
            ClaimAuthorizationValidUntil = null,
            ClaimReason = "worker-not-ready",
            UpdatedBy = updatedBy,
        });

    public WorkerControlSnapshot Start(string updatedBy = "operator-start") =>
        Mutate(current =>
        {
            if (!current.Ready)
            {
                throw new WorkerControlException("worker-not-ready", "The Worker is not ready to start.");
            }

            if (current.State is WorkerOperationalState.Stopping or WorkerOperationalState.Updating)
            {
                throw new WorkerControlException("worker-transition-active", "The Worker is changing state.");
            }

            return current with
            {
                State = WorkerOperationalState.Running,
                AcceptingClaims = true,
                MaxConcurrentJobs = current.LastNonZeroMaxConcurrentJobs,
                ClaimAllowed = false,
                RecommendedClaimCount = 0,
                ClaimAuthorizationValidUntil = null,
                ClaimReason = "heartbeat-required-after-start",
                UpdatedBy = updatedBy,
            };
        });

    public WorkerControlSnapshot Pause(string updatedBy = "operator-pause") =>
        Mutate(current => current with
        {
            State = current.ActiveJobs > 0 ? WorkerOperationalState.Pausing : WorkerOperationalState.Paused,
            AcceptingClaims = false,
            MaxConcurrentJobs = 0,
            GrantedCapacity = 0,
            ClaimAllowed = false,
            RecommendedClaimCount = 0,
            ClaimAuthorizationValidUntil = null,
            ClaimReason = "operator-paused",
            UpdatedBy = updatedBy,
        });

    public WorkerControlSnapshot BeginStop(string updatedBy = "operator-stop") =>
        Mutate(current => current with
        {
            State = WorkerOperationalState.Stopping,
            AcceptingClaims = false,
            MaxConcurrentJobs = 0,
            GrantedCapacity = 0,
            ClaimAllowed = false,
            RecommendedClaimCount = 0,
            ClaimAuthorizationValidUntil = null,
            ClaimReason = "operator-stop",
            UpdatedBy = updatedBy,
        });

    public WorkerControlSnapshot CompleteStop(string updatedBy = "operator-stop-reconciled") =>
        Mutate(current =>
        {
            if (current.ActiveJobs != 0 || current.ReservedJobs != 0)
            {
                throw new WorkerControlException(
                    "worker-stop-not-reconciled",
                    "Active or reserved jobs remain while completing Stop.");
            }

            return current with
            {
                State = WorkerOperationalState.Stopped,
                AcceptingClaims = false,
                MaxConcurrentJobs = 0,
                GrantedCapacity = 0,
                ClaimAllowed = false,
                RecommendedClaimCount = 0,
                ClaimAuthorizationValidUntil = null,
                ClaimReason = "operator-stopped",
                UpdatedBy = updatedBy,
            };
        });

    public WorkerControlSnapshot SetMaxConcurrentJobs(int value, string updatedBy = "operator-parallelism")
    {
        ValidateParallelism(value, nameof(value));
        if (value == 0)
        {
            return Pause(updatedBy);
        }

        return Mutate(current =>
        {
            if (!current.Ready)
            {
                throw new WorkerControlException("worker-not-ready", "The Worker is not ready to accept work.");
            }

            if (current.State is WorkerOperationalState.Stopping or WorkerOperationalState.Updating)
            {
                throw new WorkerControlException("worker-transition-active", "The Worker is changing state.");
            }

            return current with
            {
                State = WorkerOperationalState.Running,
                AcceptingClaims = true,
                MaxConcurrentJobs = value,
                LastNonZeroMaxConcurrentJobs = value,
                ClaimAllowed = false,
                RecommendedClaimCount = 0,
                ClaimAuthorizationValidUntil = null,
                ClaimReason = "heartbeat-required-after-capacity-change",
                UpdatedBy = updatedBy,
            };
        });
    }

    public WorkerControlSnapshot SetClaimBatchSize(int value, string updatedBy = "operator-claim-batch")
    {
        ValidatePositiveParallelism(value, nameof(value));
        return Mutate(current => current with { ClaimBatchSize = value, UpdatedBy = updatedBy });
    }

    public WorkerControlSnapshot SetGrantedCapacity(int value, string updatedBy = "orchestrator-capacity")
    {
        ValidateParallelism(value, nameof(value));
        return Mutate(current => current with { GrantedCapacity = value, UpdatedBy = updatedBy });
    }

    public WorkerControlSnapshot ApplyHeartbeatDecision(
        int grantedCapacity,
        bool claimAllowed,
        int recommendedClaimCount,
        DateTimeOffset claimAuthorizationValidUntil,
        string claimReason,
        string updatedBy = "orchestrator-node-heartbeat")
    {
        ValidateParallelism(grantedCapacity, nameof(grantedCapacity));
        ValidateClaimAuthorization(
            grantedCapacity,
            claimAllowed,
            recommendedClaimCount,
            claimAuthorizationValidUntil,
            claimReason);
        return Mutate(current => current with
        {
            GrantedCapacity = grantedCapacity,
            ClaimAllowed = claimAllowed,
            RecommendedClaimCount = recommendedClaimCount,
            ClaimAuthorizationValidUntil = claimAuthorizationValidUntil,
            ClaimReason = claimReason,
            UpdatedBy = updatedBy,
        });
    }

    public WorkerControlSnapshot ClearClaimAuthorization(
        string claimReason = "heartbeat-unavailable",
        string updatedBy = "orchestrator-node-heartbeat-failed")
    {
        ValidateClaimReason(claimReason);
        return Mutate(current => current with
        {
            ClaimAllowed = false,
            RecommendedClaimCount = 0,
            ClaimAuthorizationValidUntil = null,
            ClaimReason = claimReason,
            UpdatedBy = updatedBy,
        });
    }

    public int CurrentRecommendedClaimCount()
    {
        lock (_sync)
        {
            return CurrentRecommendedClaimCount(_snapshot, _timeProvider.GetUtcNow());
        }
    }

    public bool IsClaimRequestAuthorized(int requestedCount)
    {
        if (requestedCount < 1)
        {
            return false;
        }

        lock (_sync)
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            return ClaimAuthorizationIsCurrent(_snapshot, now)
                && requestedCount <= _snapshot.ReservedJobs
                && requestedCount <= _snapshot.RecommendedClaimCount
                && _snapshot.ActiveJobs + _snapshot.ReservedJobs <= _snapshot.EffectiveCapacity;
        }
    }

    public bool TryReserveSlot()
    {
        WorkerControlSnapshot? changed = null;
        lock (_sync)
        {
            if (_snapshot.AvailableSlots < 1)
            {
                return false;
            }

            _snapshot = Stamp(_snapshot with { ReservedJobs = _snapshot.ReservedJobs + 1 }, "scheduler-reserve");
            changed = _snapshot;
        }

        RaiseChanged(changed);
        return true;
    }

    public bool TryReserveClaimSlot()
    {
        WorkerControlSnapshot? changed = null;
        lock (_sync)
        {
            if (_snapshot.AvailableSlots < 1
                || CurrentRecommendedClaimCount(_snapshot, _timeProvider.GetUtcNow()) < 1)
            {
                return false;
            }

            _snapshot = Stamp(_snapshot with { ReservedJobs = _snapshot.ReservedJobs + 1 }, "scheduler-reserve");
            changed = _snapshot;
        }

        RaiseChanged(changed);
        return true;
    }

    public WorkerControlSnapshot ReleaseReservation(string updatedBy = "scheduler-release") =>
        Mutate(current => current.ReservedJobs < 1
            ? throw new WorkerControlException("worker-reservation-underflow", "No reserved slot exists.")
            : current with { ReservedJobs = current.ReservedJobs - 1, UpdatedBy = updatedBy });

    public WorkerControlSnapshot ActivateReservation(string updatedBy = "scheduler-activate") =>
        Mutate(current => current.ReservedJobs < 1
            ? throw new WorkerControlException("worker-reservation-underflow", "No reserved slot exists.")
            : current with
            {
                ReservedJobs = current.ReservedJobs - 1,
                ActiveJobs = current.ActiveJobs + 1,
                UpdatedBy = updatedBy,
            });

    public WorkerControlSnapshot FinishJob(string updatedBy = "scheduler-finish") =>
        Mutate(current =>
        {
            if (current.ActiveJobs < 1)
            {
                throw new WorkerControlException("worker-active-underflow", "No active job exists.");
            }

            var remaining = current.ActiveJobs - 1;
            var nextState = !current.Ready && remaining == 0
                ? WorkerOperationalState.NotReady
                : current.State switch
                {
                    WorkerOperationalState.Pausing when remaining == 0 => WorkerOperationalState.Paused,
                    WorkerOperationalState.NotReady when remaining == 0 => WorkerOperationalState.NotReady,
                    _ => current.State,
                };
            return current with { ActiveJobs = remaining, State = nextState, UpdatedBy = updatedBy };
        });

    private WorkerControlSnapshot Mutate(Func<WorkerControlSnapshot, WorkerControlSnapshot> mutation)
    {
        WorkerControlSnapshot changed;
        lock (_sync)
        {
            changed = mutation(_snapshot);
            ValidateSnapshot(changed);
            _snapshot = Stamp(changed, changed.UpdatedBy);
            changed = _snapshot;
        }

        RaiseChanged(changed);
        return changed;
    }

    private WorkerControlSnapshot Stamp(WorkerControlSnapshot value, string updatedBy) => value with
    {
        UpdatedAt = _timeProvider.GetUtcNow(),
        UpdatedBy = updatedBy,
    };

    private void RaiseChanged(WorkerControlSnapshot snapshot) => Changed?.Invoke(this, snapshot);

    private static void ValidateSnapshot(WorkerControlSnapshot value)
    {
        ValidateParallelism(value.MaxConcurrentJobs, nameof(value.MaxConcurrentJobs));
        ValidatePositiveParallelism(value.LastNonZeroMaxConcurrentJobs, nameof(value.LastNonZeroMaxConcurrentJobs));
        ValidatePositiveParallelism(value.ClaimBatchSize, nameof(value.ClaimBatchSize));
        ValidateParallelism(value.GrantedCapacity, nameof(value.GrantedCapacity));
        if (value.RecommendedClaimCount is < 0 or > 32
            || value.ClaimAllowed != (value.RecommendedClaimCount > 0)
            || (value.ClaimAllowed && value.ClaimAuthorizationValidUntil is null)
            || string.IsNullOrWhiteSpace(value.ClaimReason)
            || value.ClaimReason.Length > 160)
        {
            throw new WorkerControlException("worker-claim-authorization-invalid", "Worker claim authorization is invalid.");
        }

        if (value.ActiveJobs < 0 || value.ReservedJobs < 0 ||
            value.ActiveJobs + value.ReservedJobs > MaximumParallelism)
        {
            throw new WorkerControlException("worker-capacity-invalid", "Worker capacity counters are invalid.");
        }
    }

    private static void ValidateParallelism(int value, string parameterName)
    {
        if (value is < MinimumParallelism or > MaximumParallelism)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Parallelism must be between 0 and 64.");
        }
    }

    private static void ValidatePositiveParallelism(int value, string parameterName)
    {
        if (value is < 1 or > MaximumParallelism)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "The value must be between 1 and 64.");
        }
    }

    private void ValidateClaimAuthorization(
        int grantedCapacity,
        bool allowed,
        int recommendedCount,
        DateTimeOffset validUntil,
        string reason)
    {
        if (recommendedCount is < 0 or > 32
            || recommendedCount > grantedCapacity
            || allowed != (recommendedCount > 0))
        {
            throw new ArgumentOutOfRangeException(nameof(recommendedCount));
        }

        if (validUntil <= _timeProvider.GetUtcNow())
        {
            throw new ArgumentOutOfRangeException(nameof(validUntil));
        }

        ValidateClaimReason(reason);
    }

    private static void ValidateClaimReason(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 160
            || value.Any(static character => character is < ' ' or '\x7f'))
        {
            throw new ArgumentException("worker-claim-reason-invalid", nameof(value));
        }
    }

    private static int CurrentRecommendedClaimCount(
        WorkerControlSnapshot snapshot,
        DateTimeOffset now) => ClaimAuthorizationIsCurrent(snapshot, now)
        ? Math.Min(snapshot.AvailableSlots, snapshot.RecommendedClaimCount)
        : 0;

    private static bool ClaimAuthorizationIsCurrent(
        WorkerControlSnapshot snapshot,
        DateTimeOffset now) => snapshot.AcceptingClaims
            && snapshot.ClaimAllowed
            && snapshot.ClaimAuthorizationValidUntil is { } validUntil
            && now <= validUntil;
}

public sealed class WorkerControlException(string code, string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}
